# -*- coding: utf-8 -*-
"""
Created on Mon Sep  1 05:45:10 2025

@author: preth
"""

# AES Server - All Modes (aes_server_all_modes.py)
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def aes_decrypt_ecb(ciphertext, key):
    """ECB Mode - Electronic Codebook"""
    data = base64.b64decode(ciphertext)
    cipher = AES.new(key.encode()[:32].ljust(32, b'\0'), AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(data), AES.block_size)
    return decrypted.decode()

def aes_decrypt_cbc(ciphertext, key):
    """CBC Mode - Cipher Block Chaining"""
    data = base64.b64decode(ciphertext)
    iv = data[:16]
    encrypted = data[16:]
    cipher = AES.new(key.encode()[:32].ljust(32, b'\0'), AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
    return decrypted.decode()

def aes_decrypt_cfb(ciphertext, key):
    """CFB Mode - Cipher Feedback"""
    data = base64.b64decode(ciphertext)
    iv = data[:16]
    encrypted = data[16:]
    cipher = AES.new(key.encode()[:32].ljust(32, b'\0'), AES.MODE_CFB, iv)
    decrypted = cipher.decrypt(encrypted)
    return decrypted.decode()

def aes_decrypt_ofb(ciphertext, key):
    """OFB Mode - Output Feedback"""
    data = base64.b64decode(ciphertext)
    iv = data[:16]
    encrypted = data[16:]
    cipher = AES.new(key.encode()[:32].ljust(32, b'\0'), AES.MODE_OFB, iv)
    decrypted = cipher.decrypt(encrypted)
    return decrypted.decode()

def aes_decrypt_ctr(ciphertext, key):
    """CTR Mode - Counter"""
    data = base64.b64decode(ciphertext)
    nonce = data[:8]  # CTR uses 8-byte nonce
    encrypted = data[8:]
    cipher = AES.new(key.encode()[:32].ljust(32, b'\0'), AES.MODE_CTR, nonce=nonce)
    decrypted = cipher.decrypt(encrypted)
    return decrypted.decode()

def start_server(host="127.0.0.1", port=65432):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    
    print(f"AES Server (All Modes) running on {host}:{port}... Waiting for client.")
    
    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")
    
    # Receive the key and mode from client
    key_data = conn.recv(1024).decode()
    key, mode = key_data.split('|')
    print(f"Key received: {key}")
    print(f"Mode received: {mode}")
    
    # Select decryption function based on mode
    decrypt_functions = {
        'ECB': aes_decrypt_ecb,
        'CBC': aes_decrypt_cbc,
        'CFB': aes_decrypt_cfb,
        'OFB': aes_decrypt_ofb,
        'CTR': aes_decrypt_ctr
    }
    
    decrypt_func = decrypt_functions.get(mode.upper())
    if not decrypt_func:
        print(f"Unknown mode: {mode}")
        conn.close()
        server_socket.close()
        return
    
    while True:
        data = conn.recv(2048).decode()
        if not data:
            break
        print(f"Ciphertext received ({mode}): {data[:50]}...")
        try:
            decrypted = decrypt_func(data, key)
            print(f"Decrypted plaintext: {decrypted}")
        except Exception as e:
            print(f"Decryption error: {e}")
    
    conn.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()

