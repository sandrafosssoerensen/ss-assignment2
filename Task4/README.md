# Mini TLS-based VPN Tunnel – README

## Overview

This project implements a simple VPN tunnel using TUN interfaces and a TLS-encrypted connection.
A client and server communicate securely by forwarding IP packets through a TLS socket.

---

## Requirements

* Docker & Docker Compose
* Python 3
* Root privileges (required for TUN interface)

---

## Setup

### 1. Start the environment

From the project directory:

```bash
docker-compose up
```

---

### 2. Start the VPN Server

Open a terminal:

```bash
docker exec -it server-router bash
cd /volumes
python3 tun_server_tls.py
```

Expected output:

```
Server TUN: tun0
Waiting for TLS client...
```

---

### 3. Start the VPN Client

Open another terminal:

```bash
docker exec -it client-10.9.0.5 bash
cd /volumes
python3 tun_client_tls.py
```

Expected output:

```
Client TUN: tun0
Connected to TLS server
```

---

### 4. Configure Routing (Client)

Inside the client container:

```bash
ip route add 192.168.60.0/24 dev tun0
```

---

## Testing the VPN

From the client container:

```bash
ping 192.168.60.5
```

Expected result:

```
64 bytes from 192.168.60.5
```

---

## Observing Encrypted Traffic

Run inside client container:

```bash
tcpdump -i eth0 -n port 9090
```

Expected output:

```
10.9.0.5 > 10.9.0.11: length 106
```

This shows encrypted TLS traffic between VPN endpoints.

---