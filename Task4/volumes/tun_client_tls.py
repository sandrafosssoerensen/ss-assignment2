#!/usr/bin/env python3

from scapy.all import IP
import socket, ssl, os, fcntl, struct, select

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

# TUN SETUP
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname = fcntl.ioctl(tun, TUNSETIFF, ifr).decode()[:16].strip("\x00")

print("Client TUN:", ifname)

os.system(f"ip addr add 192.168.53.99/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")

# TLS SETUP
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tls_sock = context.wrap_socket(sock)

tls_sock.connect(("10.9.0.11", 9090))

print("Connected to TLS server")

while True:

    r, _, _ = select.select([tun], [], [], 0.1)

    if tun in r:
        packet = os.read(tun, 2048)

        try:
            pkt = IP(packet)
        except:
            pkt = None

        if pkt and (pkt.src.startswith("192.168.") or pkt.dst.startswith("192.168.")):
            print("TLS ==>:", pkt.src, "-->", pkt.dst)
            tls_sock.send(packet)

    try:
        tls_sock.settimeout(0.1)
        data = tls_sock.recv(2048)

        if data:
            try:
                pkt = IP(data)
            except:
                pkt = None

            if pkt and (pkt.src.startswith("192.168.") or pkt.dst.startswith("192.168.")):
                print("TLS <==:", pkt.src, "-->", pkt.dst)
                os.write(tun, data)

    except:
        pass