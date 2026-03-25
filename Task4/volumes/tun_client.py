#!/usr/bin/env python3

from scapy.all import IP
import fcntl
import struct
import os
import socket
import select

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

# Create TUN interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Client TUN interface:", ifname)

# Configure interface
os.system(f"ip addr add 192.168.53.99/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")

# Create UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

SERVER_IP = "10.9.0.11"
SERVER_PORT = 9090

while True:
    ready, _, _ = select.select([sock, tun], [], [])

    for fd in ready:

        # SERVER → CLIENT
        if fd is sock:
            data, _ = sock.recvfrom(2048)

            try:
                pkt = IP(data)
            except:
                continue

            # Only accept VPN traffic
            if not pkt.src.startswith("192.168."):
                continue

            print("From socket <==:", pkt.src, "-->", pkt.dst)

            os.write(tun, data)

        # CLIENT → SERVER
        if fd is tun:
            packet = os.read(tun, 2048)

            try:
                pkt = IP(packet)
            except:
                continue

            # Only send VPN traffic
            if not pkt.dst.startswith("192.168."):
                continue

            print("From tun ==>: ", pkt.src, "-->", pkt.dst)

            sock.sendto(packet, (SERVER_IP, SERVER_PORT))