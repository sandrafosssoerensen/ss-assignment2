import argparse
import socket
import sys
from datetime import datetime, timezone

from covert_common import decrypt_payload

ICMP_TYPE_RESERVED = 47

def parse_args():
    parser = argparse.ArgumentParser(
        description="Listen for encrypted ICMP type 47 packets"
    )
    parser.add_argument("--bind", default="0.0.0.0", help="Local IP to bind (default: 0.0.0.0)")
    parser.add_argument("--key", required=True, help="Pre-shared secret")
    return parser.parse_args()

def main():
    args = parse_args()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.bind((args.bind, 0))
    except OSError as exc:
        print(f"Socket error: {exc}", file=sys.stderr)
        return 1

    print(f"Listening on {args.bind} for ICMP type {ICMP_TYPE_RESERVED}. Press Ctrl+C to exit.")

    try:
        while True:
            packet, addr = sock.recvfrom(65535)

            if len(packet) < 8:
                continue

            # Include the IPv4 header before ICMP
            if (packet[0] >> 4) == 4 and len(packet) >= 20:
                ip_header_len = (packet[0] & 0x0F) * 4
                if len(packet) < ip_header_len + 8:
                    continue
                icmp_offset = ip_header_len
            else:
                icmp_offset = 0

            payload = packet[icmp_offset + 8 :]
            plaintext = decrypt_payload(args.key, payload)
    
            timestamp = datetime.now(timezone.utc).isoformat()
            text = plaintext.decode("utf-8", errors="replace")
            print(f"[{timestamp}] from {addr[0]}: {text}")

    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        sock.close()

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
