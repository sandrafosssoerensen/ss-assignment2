import argparse
import os
import socket
import struct

from covert_common import encrypt_payload, icmp_checksum

ICMP_TYPE_RESERVED = 47

def parse_args():
    parser = argparse.ArgumentParser(
        description="Send encrypted ICMP type 47 packets"
    )
    parser.add_argument("dest_ip", help="Destination IPv4 address")
    parser.add_argument("--key", required=True, help="Pre-shared secret")
    parser.add_argument("--max-bytes", type=int, default=1024, help="Max plaintext bytes (default: 1024)")
    return parser.parse_args()

def main():
    args = parse_args()

    identifier = os.getpid() & 0xFFFF
    sequence = 0

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    print(f"Sending encrypted ICMP type {ICMP_TYPE_RESERVED} to {args.dest_ip}. Press Ctrl+C to exit.")

    try:
        while True:
            try:
                line = input("> ")
            except EOFError:
                break

            if not line:
                continue

            plaintext = line.encode("utf-8")

            encrypted = encrypt_payload(args.key, plaintext)
            
            # Build ICMP header with checksum field set to 0
            header = struct.pack("!BBHHH", ICMP_TYPE_RESERVED, 0, 0, identifier, sequence)
            
            # Calculate correct checksum
            checksum = icmp_checksum(header + encrypted)
            
            # Rebuild header with correct checksum
            header = struct.pack("!BBHHH", ICMP_TYPE_RESERVED, 0, checksum, identifier, sequence)
            packet = header + encrypted
            
            sock.sendto(packet, (args.dest_ip, 0))
            print(f"Sent seq={sequence}, {len(plaintext)} bytes")
            sequence = (sequence + 1) & 0xFFFF

    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        sock.close()

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
