# -*- coding: utf-8 -*-
"""
Created on Sun Aug 31 09:59:06 2025

@author: preth
"""

# AES Client (aes_client.py)
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import base64

def aes_encrypt(plaintext, key):
    key_bytes = key.encode()[:32].ljust(32, b'\0')  # Ensure 32 bytes
    iv = get_random_bytes(16)
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    padded = pad(plaintext.encode(), AES.block_size)
    encrypted = cipher.encrypt(padded)
    return base64.b64encode(iv + encrypted).decode()

def start_client(host="127.0.0.1", port=65432):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    
    # Send the key to server
    key = input("Enter encryption key (string): ")
    client_socket.sendall(key.encode())
    
    # Send encrypted messages
    while True:
        msg = input("Enter message (or 'exit' to quit): ")
        if msg.lower() == "exit":
            break
        
        encrypted = aes_encrypt(msg, key)
        print(f"Sending encrypted: {encrypted}")
        client_socket.sendall(encrypted.encode())
    
    client_socket.close()

if __name__ == "__main__":
    start_client()