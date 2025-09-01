# -*- coding: utf-8 -*-
"""
Created on Mon Sep  1 05:46:22 2025

@author: preth
"""

# ================================================================
# AES Client - All Modes (aes_client_all_modes.py)
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import base64

def aes_encrypt_ecb(plaintext, key):
    """ECB Mode - Electronic Codebook (No IV needed)"""
    key_bytes = key.encode()[:32].ljust(32, b'\0')
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    padded = pad(plaintext.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(encrypted).decode()

def aes_encrypt_cbc(plaintext, key):
    """CBC Mode - Cipher Block Chaining"""
    key_bytes = key.encode()[:32].ljust(32, b'\0')
    iv = get_random_bytes(16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(iv + encrypted).decode()

def aes_encrypt_cfb(plaintext, key):
    """CFB Mode - Cipher Feedback (No padding needed)"""
    key_bytes = key.encode()[:32].ljust(32, b'\0')
    iv = get_random_bytes(16)
    cipher = AES.new(key_bytes, AES.MODE_CFB, iv)
    encrypted = cipher.encrypt(plaintext.encode())
    return base64.b64encode(iv + encrypted).decode()

def aes_encrypt_ofb(plaintext, key):
    """OFB Mode - Output Feedback (No padding needed)"""
    key_bytes = key.encode()[:32].ljust(32, b'\0')
    iv = get_random_bytes(16)
    cipher = AES.new(key_bytes, AES.MODE_OFB, iv)
    encrypted = cipher.encrypt(plaintext.encode())
    return base64.b64encode(iv + encrypted).decode()

def aes_encrypt_ctr(plaintext, key):
    """CTR Mode - Counter (No padding needed)"""
    key_bytes = key.encode()[:32].ljust(32, b'\0')
    nonce = get_random_bytes(8)  # CTR uses 8-byte nonce
    cipher = AES.new(key_bytes, AES.MODE_CTR, nonce=nonce)
    encrypted = cipher.encrypt(plaintext.encode())
    return base64.b64encode(nonce + encrypted).decode()

def start_client(host="127.0.0.1", port=65432):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    
    # Get key and mode from user
    key = input("Enter encryption key (string): ")
    print("\nAvailable AES modes:")
    print("1. ECB - Electronic Codebook")
    print("2. CBC - Cipher Block Chaining")
    print("3. CFB - Cipher Feedback")
    print("4. OFB - Output Feedback")
    print("5. CTR - Counter")
    
    mode_choice = input("Choose mode (1-5): ")
    modes = {'1': 'ECB', '2': 'CBC', '3': 'CFB', '4': 'OFB', '5': 'CTR'}
    mode = modes.get(mode_choice, 'CBC')
    
    print(f"Selected mode: {mode}")
    
    # Send key and mode to server
    client_socket.sendall(f"{key}|{mode}".encode())
    
    # Select encryption function based on mode
    encrypt_functions = {
        'ECB': aes_encrypt_ecb,
        'CBC': aes_encrypt_cbc,
        'CFB': aes_encrypt_cfb,
        'OFB': aes_encrypt_ofb,
        'CTR': aes_encrypt_ctr
    }
    
    encrypt_func = encrypt_functions[mode]
    
    # Send encrypted messages
    while True:
        msg = input("Enter message (or 'exit' to quit): ")
        if msg.lower() == "exit":
            break
        
        encrypted = encrypt_func(msg, key)
        print(f"Sending encrypted ({mode}): {encrypted[:50]}...")
        client_socket.sendall(encrypted.encode())
    
    client_socket.close()

if __name__ == "__main__":
    start_client()

# ================================================================
# COMPARISON DEMO - Shows differences between modes
def demo_all_modes():
    """Demo showing how same plaintext encrypts differently in each mode"""
    key = "mySecretKey123"
    plaintext = "Hello World! This is a test message."
    
    print("AES MODE COMPARISON")
    print("=" * 50)
    print(f"Plaintext: {plaintext}")
    print(f"Key: {key}")
    print()
    
    # Test each mode
    modes = [
        ("ECB", aes_encrypt_ecb),
        ("CBC", aes_encrypt_cbc),
        ("CFB", aes_encrypt_cfb),
        ("OFB", aes_encrypt_ofb),
        ("CTR", aes_encrypt_ctr)
    ]
    
    for mode_name, encrypt_func in modes:
        encrypted = encrypt_func(plaintext, key)
        print(f"{mode_name}: {encrypted[:60]}...")
    
    print("\nKey characteristics:")
    print("ECB: Same plaintext blocks = same ciphertext blocks")
    print("CBC: Uses IV, chains blocks together")
    print("CFB: Stream cipher mode, no padding needed")
    print("OFB: Stream cipher mode, no padding needed")
    print("CTR: Stream cipher mode, uses counter")

if __name__ == "__main__":
    # Uncomment to run demo
    # demo_all_modes()
    pass