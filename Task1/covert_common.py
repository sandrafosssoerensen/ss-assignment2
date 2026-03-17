
# Reference:
# https://cryptography.io/en/latest/hazmat/primitives/aead/

# This documentation was used to understand how AES-GCM authenticated
# encryption works and how to correctly use the AESGCM class for encryption
# and decryption in Python.

import hashlib
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(psk):
    # Derives a 32-byte AES key from a pre-shared secret using SHA-256.
    return hashlib.sha256(psk.encode("utf-8")).digest()

def encrypt_payload(psk, plaintext):
    # Encrypts plaintext using AES-GCM and returns ciphertext with nonce.
    nonce = os.urandom(12)
    key = derive_key(psk)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    # Send nonce together with ciphertext so receiver can decrypt
    return ciphertext + nonce

def decrypt_payload(psk, encrypted):
    # Decrypts AES-GCM encrypted payload and returns plaintext or None if invalid. 
    nonce = encrypted[-12:]
    ciphertext = encrypted[:-12]
    key = derive_key(psk)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except:
        return None

def icmp_checksum(data):
    # Computes the ICMP checksum over 16-bit words.
    if len(data) % 2 != 0:
        data += b"\x00"
    total = 0
    
    for i in range(0, len(data), 2):
        # Merge two bytes into one 16-bit number
        word = (data[i] << 8) + data[i + 1]
        total += word
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF