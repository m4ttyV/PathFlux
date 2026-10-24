"""A bounded UDP echo endpoint for a controlled PathFlux diagnostic lab.

Only run on a host you control. Defaults to loopback; no firewall rules are changed.
"""

import argparse
import ipaddress
import socket


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1", help="Literal bind IP, default 127.0.0.1")
    parser.add_argument("--port", type=int, default=4444, help="UDP port, default 4444")
    parser.add_argument("--count", type=int, default=0, help="Exit after this many echoes; 0 means until Ctrl+C")
    args = parser.parse_args()
    try:
        address = ipaddress.ip_address(args.bind)
    except ValueError:
        parser.error("--bind must be an IP address")
    if not 1 <= args.port <= 65535 or args.count < 0:
        parser.error("--port must be 1..65535 and --count must be nonnegative")
    family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as server:
        if family == socket.AF_INET6:
            server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        server.bind((str(address), args.port))
        server.settimeout(0.5)
        print(f"UDP echo listening on {address}:{args.port}; maximum payload 1024 bytes. Ctrl+C to stop.", flush=True)
        echoed = 0
        try:
            while not args.count or echoed < args.count:
                try:
                    payload, peer = server.recvfrom(1025)
                except socket.timeout:
                    continue
                if not payload or len(payload) > 1024:
                    continue
                server.sendto(payload, peer)
                echoed += 1
        except KeyboardInterrupt:
            pass
        print(f"Echoed {echoed} datagrams. No payloads were logged.", flush=True)


if __name__ == "__main__":
    main()
