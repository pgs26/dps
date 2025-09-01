# -*- coding: utf-8 -*-
"""
Created on Sun Aug 31 09:58:16 2025

@author: preth
"""

# AES Server (aes_server.py)
import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

def aes_decrypt(ciphertext, key):
    data = base64.b64decode(ciphertext)
    iv = data[:16]
    encrypted = data[16:]
    cipher = AES.new(key.encode()[:32].ljust(32, b'\0'), AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
    return decrypted.decode()

def start_server(host="127.0.0.1", port=65432):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    
    print(f"AES Server running on {host}:{port}... Waiting for client.")
    
    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")
    
    # Receive the key from client
    key_data = conn.recv(1024).decode()
    print(f"Key received from client: {key_data}")
    
    while True:
        data = conn.recv(1024).decode()
        if not data:
            break
        print(f"Ciphertext received: {data}")
        decrypted = aes_decrypt(data, key_data)
        print(f"Decrypted plaintext: {decrypted}")
    
    conn.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()