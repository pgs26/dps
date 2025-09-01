# -*- coding: utf-8 -*-
"""
Created on Sun Aug 31 22:07:57 2025

@author: preth
"""

HOST = "127.0.0.1"
PORT = 50007
A_KEY = 5
B_KEY = 8

def start_server(host=HOST, port=PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)
        print(f"Server listening on {host}:{port}")
        conn, addr = s.accept()
        with conn:
            print("Connected by", addr)
            while True:
                data = conn.recv(4096)
                if not data:
                    print("Connection closed by client")
                    break
                ciphertext = data.decode('utf-8')
                print("Received ciphertext:", ciphertext)
                try:
                    plaintext = decrypt(ciphertext, A_KEY, B_KEY)
                except Exception as e:
                    plaintext = f"[decryption error: {e}]"
                print("Decrypted plaintext:", plaintext)
                # send ack
                ack = f"Server received and decrypted message: {plaintext}"
                conn.sendall(ack.encode('utf-8'))


start_server()

HOST = "127.0.0.1"
PORT = 50007
A_KEY = 5
B_KEY = 8

def send_message(msg, host=HOST, port=PORT):
    ct = encrypt(msg, A_KEY, B_KEY)
    print("Sending ciphertext:", ct)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(ct.encode('utf-8'))
        data = s.recv(4096)
    print("Received ack:", data.decode('utf-8'))


message = "Hello server, this is a test!"
send_message(message)


ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
M = len(ALPHABET)

def modinv(a, m):
    a = a % m
    if gcd(a, m) != 1:
        raise ValueError(f"{a} has no modular inverse mod {m}")
    t0, t1 = 0, 1
    r0, r1 = m, a
    while r1 != 0:
        q = r0 // r1
        r0, r1, t0, t1 = r1, r0 - q * r1, t1, t0 - q * t1
    inv = t0 % m
    return inv

def encrypt(plaintext, a, b):
    if gcd(a, M) != 1:
        raise ValueError(f"a={a} is invalid since gcd({a},{M}) != 1")
    plaintext = plaintext.upper()
    out = []
    for ch in plaintext:
        if 'A' <= ch <= 'Z':
            x = ord(ch) - ord('A')
            y = (a * x + b) % M
            out.append(chr(y + ord('A')))
        else:
            out.append(ch)
    return ''.join(out)

def decrypt(ciphertext, a, b):
    if gcd(a, M) != 1:
        raise ValueError(f"a={a} is invalid since gcd({a},{M}) != 1")
    a_inv = modinv(a, M)
    ciphertext = ciphertext.upper()
    out = []
    for ch in ciphertext:
        if 'A' <= ch <= 'Z':
            y = ord(ch) - ord('A')
            x = (a_inv * (y - b)) % M
            out.append(chr(x + ord('A')))
        else:
            out.append(ch)
    return ''.join(out)