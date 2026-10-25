package process

import (
	T "github.com/sagernet/sing-box/common/pathfluxtree"
	W "github.com/sagernet/sing/common/winiphlpapi"
	"net/netip"
)

// TUN may rewrite the remote TCP endpoint in the Windows table. Require a unique
// owner across all rows for the original local endpoint instead of picking one.
// UDP likewise refuses ambiguous wildcard/shared binds.
// Never use the upstream first-local-port match for exact instance routing.
func pathFluxFindOwner(network string, source, destination netip.AddrPort) (uint32, error) {
	var pid uint32
	ambiguous := false
	add := func(value uint32) {
		if pid != 0 && pid != value {
			ambiguous = true
		}
		pid = value
	}
	if network == "tcp" {
		if !destination.IsValid() {
			return 0, T.ErrUnavailable
		}
		if source.Addr().Is4() {
			rows, err := W.GetExtendedTcpTable()
			if err != nil {
				return 0, err
			}
			for _, r := range rows {
				if source == netip.AddrPortFrom(W.DwordToAddr(r.DwLocalAddr), W.DwordToPort(r.DwLocalPort)) {
					add(r.DwOwningPid)
				}
			}
		} else {
			rows, err := W.GetExtendedTcp6Table()
			if err != nil {
				return 0, err
			}
			for _, r := range rows {
				if source == netip.AddrPortFrom(netip.AddrFrom16(r.UcLocalAddr), W.DwordToPort(r.DwLocalPort)) {
					add(r.DwOwningPid)
				}
			}
		}
	} else if network == "udp" {
		if source.Addr().Is4() {
			rows, err := W.GetExtendedUdpTable()
			if err != nil {
				return 0, err
			}
			for _, r := range rows {
				a := W.DwordToAddr(r.DwLocalAddr)
				if source.Port() == W.DwordToPort(r.DwLocalPort) && (a == source.Addr() || a.IsUnspecified()) {
					add(r.DwOwningPid)
				}
			}
		} else {
			rows, err := W.GetExtendedUdp6Table()
			if err != nil {
				return 0, err
			}
			for _, r := range rows {
				a := netip.AddrFrom16(r.UcLocalAddr)
				if source.Port() == W.DwordToPort(r.DwLocalPort) && (a == source.Addr() || a.IsUnspecified()) {
					add(r.DwOwningPid)
				}
			}
		}
	}
	if pid <= 4 || ambiguous {
		return 0, T.ErrUnavailable
	}
	return pid, nil
}
