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

print("Server TUN:", ifname)

os.system(f"ip addr add 192.168.53.1/24 dev {ifname}")
os.system(f"ip link set dev {ifname} up")

# TLS SETUP
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(("0.0.0.0", 9090))
sock.listen(1)

print("Waiting for TLS client...")
conn, addr = sock.accept()
tls_conn = context.wrap_socket(conn, server_side=True)

print("TLS connection established with", addr)

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
            tls_conn.send(packet)

    try:
        tls_conn.settimeout(0.1)
        data = tls_conn.recv(2048)

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