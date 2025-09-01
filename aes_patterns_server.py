# -*- coding: utf-8 -*-
"""
Created on Mon Sep  1 05:55:23 2025

@author: preth
"""


# AES Server - Pattern Preservation and Error Propagation Analysis
import socket
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class AESServer:
    def __init__(self):
        self.key = get_random_bytes(32)  # 256-bit key
        
    def bytes_to_hex_string(self, data):
        """Convert bytes to hex string format like '00 01 02 03'"""
        return ' '.join([f'{b:02x}' for b in data])
    
    def hex_string_to_bytes(self, hex_str):
        """Convert hex string back to bytes"""
        return bytes.fromhex(hex_str.replace(' ', ''))
    
    def encrypt_ecb(self, plaintext_bytes):
        """ECB Mode Encryption"""
        cipher = AES.new(self.key, AES.MODE_ECB)
        padded = pad(plaintext_bytes, AES.block_size)
        ciphertext = cipher.encrypt(padded)
        return ciphertext, None  # No IV for ECB
    
    def decrypt_ecb(self, ciphertext_bytes):
        """ECB Mode Decryption"""
        cipher = AES.new(self.key, AES.MODE_ECB)
        try:
            decrypted = cipher.decrypt(ciphertext_bytes)
            unpadded = unpad(decrypted, AES.block_size)
            return unpadded
        except:
            return decrypted  # Return even if padding fails
    
    def encrypt_cbc(self, plaintext_bytes):
        """CBC Mode Encryption"""
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        padded = pad(plaintext_bytes, AES.block_size)
        ciphertext = cipher.encrypt(padded)
        return ciphertext, iv
    
    def decrypt_cbc(self, ciphertext_bytes, iv):
        """CBC Mode Decryption"""
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        try:
            decrypted = cipher.decrypt(ciphertext_bytes)
            unpadded = unpad(decrypted, AES.block_size)
            return unpadded
        except:
            return decrypted  # Return even if padding fails
    
    def encrypt_cfb(self, plaintext_bytes):
        """CFB Mode Encryption"""
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        ciphertext = cipher.encrypt(plaintext_bytes)
        return ciphertext, iv
    
    def decrypt_cfb(self, ciphertext_bytes, iv):
        """CFB Mode Decryption"""
        cipher = AES.new(self.key, AES.MODE_CFB, iv)
        decrypted = cipher.decrypt(ciphertext_bytes)
        return decrypted
    
    def analyze_mode(self, mode, plaintext_bytes):
        """Analyze a specific mode for pattern preservation and error propagation"""
        print(f"\n{'='*60}")
        print(f"ANALYZING MODE: {mode}")
        print(f"{'='*60}")
        
        # Original encryption
        if mode == "ECB":
            ciphertext, iv = self.encrypt_ecb(plaintext_bytes)
        elif mode == "CBC":
            ciphertext, iv = self.encrypt_cbc(plaintext_bytes)
        elif mode == "CFB":
            ciphertext, iv = self.encrypt_cfb(plaintext_bytes)
        
        print(f"opmode: {mode}")
        print(f"input : {self.bytes_to_hex_string(plaintext_bytes)}")
        print(f"cipher: {self.bytes_to_hex_string(ciphertext)}")
        
        # Test error propagation - modify random byte
        modified_ciphertext = bytearray(ciphertext)
        random_pos = random.randint(0, len(ciphertext) - 1)
        original_byte = modified_ciphertext[random_pos]
        
        # Change byte to a different random value
        new_byte = original_byte
        while new_byte == original_byte:
            new_byte = random.randint(0, 255)
        
        modified_ciphertext[random_pos] = new_byte
        
        print(f"Modifying random byte: {original_byte:02x}->{new_byte:02x}")
        
        # Decrypt modified ciphertext
        if mode == "ECB":
            decrypted = self.decrypt_ecb(bytes(modified_ciphertext))
        elif mode == "CBC":
            decrypted = self.decrypt_cbc(bytes(modified_ciphertext), iv)
        elif mode == "CFB":
            decrypted = self.decrypt_cfb(bytes(modified_ciphertext), iv)
        
        print(f"plain : {self.bytes_to_hex_string(decrypted)}")
        
        # Analyze error propagation
        self.analyze_error_propagation(plaintext_bytes, decrypted, mode)
        
        return ciphertext, iv, decrypted
    
    def analyze_error_propagation(self, original, decrypted, mode):
        """Analyze how error propagated through decryption"""
        min_len = min(len(original), len(decrypted))
        errors = sum(1 for i in range(min_len) if original[i] != decrypted[i])
        
        print(f"\nError Propagation Analysis for {mode}:")
        print(f"Original length: {len(original)} bytes")
        print(f"Decrypted length: {len(decrypted)} bytes")
        print(f"Bytes affected: {errors}/{min_len}")
        print(f"Error propagation: {(errors/min_len)*100:.1f}%")
        
        if mode == "ECB":
            print("ECB: Error affects only one block (16 bytes)")
        elif mode == "CBC":
            print("CBC: Error affects current block and next block")
        elif mode == "CFB":
            print("CFB: Error affects one byte, then propagates")

def start_server(host="127.0.0.1", port=65432):
    server = AESServer()
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    
    print(f"AES Analysis Server running on {host}:{port}...")
    print("Ready to analyze AES modes: ECB, CBC, CFB")
    
    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")
    
    while True:
        try:
            # Receive mode and data from client
            data = conn.recv(4096).decode()
            if not data:
                break
            
            parts = data.split('|')
            if len(parts) < 2:
                continue
                
            mode = parts[0]
            hex_data = parts[1]
            
            # Convert hex string to bytes
            plaintext_bytes = server.hex_string_to_bytes(hex_data)
            
            # Analyze the mode
            ciphertext, iv, decrypted = server.analyze_mode(mode, plaintext_bytes)
            
            # Send results back to client
            result = f"{mode}|{server.bytes_to_hex_string(ciphertext)}|{server.bytes_to_hex_string(decrypted)}"
            conn.send(result.encode())
            
        except Exception as e:
            print(f"Error: {e}")
            break
    
    conn.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()