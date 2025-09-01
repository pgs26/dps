# -*- coding: utf-8 -*-
"""
Created on Sun Aug 31 09:59:57 2025

@author: preth
"""

# RSA Server (rsa_server.py)
import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
def rsa_decrypt(ciphertext, private_key):
    encrypted_data = base64.b64decode(ciphertext)
    cipher = PKCS1_OAEP.new(private_key)
    decrypted = cipher.decrypt(encrypted_data)
    return decrypted.decode()

def start_server(host="127.0.0.1", port=65433):
    # Generate RSA key pair
    key = RSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    
    print(f"RSA Server running on {host}:{port}... Waiting for client.")
    
    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")
    
    # Send public key to client
    public_key_pem = public_key.export_key().decode()
    conn.sendall(public_key_pem.encode())
    print("Public key sent to client")
    
    while True:
        data = conn.recv(2048).decode()
        if not data:
            break
        print(f"Ciphertext received: {data[:50]}...")
        decrypted = rsa_decrypt(data, private_key)
        print(f"Decrypted plaintext: {decrypted}")
    
    conn.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()