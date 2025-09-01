# -*- coding: utf-8 -*-
"""
Created on Sun Aug 31 09:59:27 2025

@author: preth
"""

# RSA Client (rsa_client.py)
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

def rsa_encrypt(plaintext, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted = cipher.encrypt(plaintext.encode())
    return base64.b64encode(encrypted).decode()

def start_client(host="127.0.0.1", port=65433):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    
    # Receive public key from server
    public_key_data = client_socket.recv(2048).decode()
    public_key = RSA.import_key(public_key_data)
    print("Public key received from server")
    
    # Send encrypted messages
    while True:
        msg = input("Enter message (or 'exit' to quit): ")
        if msg.lower() == "exit":
            break
        
        encrypted = rsa_encrypt(msg, public_key)
        print(f"Sending encrypted: {encrypted[:50]}...")
        client_socket.sendall(encrypted.encode())
    
    client_socket.close()

if __name__ == "__main__":
    start_client()