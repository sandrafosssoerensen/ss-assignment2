# Task 1 - Encrypted ICMP Covert Channel

This folder contains a one-way encrypted covert channel over ICMP type `47`.

- Sender: `icmp_covert_client.py`
- Receiver: `icmp_covert_server.py`
- Shared helpers: `covert_common.py`

## 1) Setup

Create and activate a virtual environment, then install dependencies.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## 2) Run server

Raw ICMP sockets require root/admin privileges.

```bash
sudo .venv/bin/python icmp_covert_server.py --bind 0.0.0.0 --key "<shared-key>"
```

## 3) Run client

In another terminal, send messages to the server IP.

```bash
sudo .venv/bin/python icmp_covert_client.py <SERVER_IP> --key "<shared-key>"
```

Type messages in the client terminal and press Enter. The server prints decrypted messages.

## Notes
Use the same `--key` value on both client and server. <br>
Testing was done in Oracle VM.
