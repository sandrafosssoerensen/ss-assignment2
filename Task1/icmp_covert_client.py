import argparse
import os
import socket
import struct

from covert_common import encrypt_payload, icmp_checksum

# https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol 
# From above source ICMP type 47 falls in the 44-252 unassigned/reserved range, which is the type that 
# the task specifies to use as the reserved number to use for the covert channel
# in this task this is used to create covert channels, known as ICMP tunnels
ICMP_TYPE_RESERVED = 47

def parse_args():
    parser = argparse.ArgumentParser(
        description="Send encrypted ICMP type 47 packets"
    )
    parser.add_argument("dest_ip", help="Destination IPv4 address")
    parser.add_argument("--key", required=True, help="Pre-shared secret")
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
            
            # https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
            # ICMP header layout:
            #   Byte 0      - Type  (8 bits)
            #   Byte 1      - Code  (8 bits, 0 for unassigned types)
            #   Bytes 2-3   - Checksum (16 bits, 0 while computing)
            #   Bytes 4-5   - Identifier (16 bits, used to match replies)
            #   Bytes 6-7   - Sequence number (16 bits)
            # Checksum covers the entire ICMP message (header + data), with checksum field set to 0.
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
