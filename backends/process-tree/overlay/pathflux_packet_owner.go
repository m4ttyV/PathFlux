package route

import (
	"context"
	T "github.com/sagernet/sing-box/common/pathfluxtree"
	"github.com/sagernet/sing-box/common/process"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"net/netip"
)

// Guard every datagram in both directions, including Direct associations. A tuple reused
// by another process must close the old association before any bytes can cross it.
type pathFluxPacketOwner struct {
	N.PacketConn
	router              *Router
	ctx                 context.Context
	source, destination netip.AddrPort
	owner               T.Identity
}

func (p *pathFluxPacketOwner) valid() bool {
	o, err := process.FindProcessInfo(p.router.processSearcher, p.ctx, N.NetworkUDP, p.source, p.destination)
	return err == nil && o != nil && o.ProcessID == p.owner.PID && o.PathFluxStarted == p.owner.Started && o.PathFluxSequence == p.owner.Sequence && o.PathFluxStarted != 0 && o.PathFluxSequence != 0
}
func (p *pathFluxPacketOwner) ReadPacket(b *buf.Buffer) (M.Socksaddr, error) {
	d, err := p.PacketConn.ReadPacket(b)
	if err != nil {
		return d, err
	}
	if !p.valid() {
		b.Reset()
		return M.Socksaddr{}, T.ErrUnavailable
	}
	return d, nil
}
func (p *pathFluxPacketOwner) WritePacket(b *buf.Buffer, d M.Socksaddr) error {
	if !p.valid() {
		b.Release()
		return T.ErrUnavailable
	}
	return p.PacketConn.WritePacket(b, d)
}
