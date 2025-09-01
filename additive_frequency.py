# -*- coding: utf-8 -*-
"""
Created on Mon Sep  1 05:42:25 2025

@author: preth
"""

import socket
from collections import Counter

# Additive cipher decryption
def additive_decrypt(ciphertext, key):
    result = ""
    for char in ciphertext:
        if char.isalpha():
            shift = 65 if char.isupper() else 97
            result += chr((ord(char) - shift - key) % 26 + shift)
        else:
            result += char
    return result

def character_frequency_analysis(ciphertext):
    """Analyze frequency of individual characters"""
    print(f"\n=== CHARACTER FREQUENCY ANALYSIS ===")
    print(f"Ciphertext: {ciphertext}")
    
    # Extract only alphabetic characters and convert to uppercase
    cipher_letters = ''.join([c.upper() for c in ciphertext if c.isalpha()])
    
    if not cipher_letters:
        print("No letters found in ciphertext")
        return None, None
    
    # Count frequency of each character
    char_freq = Counter(cipher_letters)
    total_letters = len(cipher_letters)
    
    print(f"\nCharacter frequencies in ciphertext ({total_letters} total letters):")
    print("Char | Count | Percentage")
    print("-" * 25)
    
    # Sort by frequency (most common first)
    for char, count in char_freq.most_common():
        percentage = (count / total_letters) * 100
        print(f"  {char}  |  {count:2d}   |   {percentage:5.1f}%")
    
    # Most frequent character in ciphertext
    most_frequent_cipher = char_freq.most_common(1)[0][0]
    print(f"\nMost frequent cipher character: '{most_frequent_cipher}'")
    
    # Assume most frequent cipher character maps to 'E' (most common in English)
    # Calculate key: key = (cipher_char - 'E') % 26
    potential_key = (ord(most_frequent_cipher) - ord('E')) % 26
    
    print(f"Assuming '{most_frequent_cipher}' maps to 'E'")
    print(f"Calculated key: ({ord(most_frequent_cipher)} - {ord('E')}) % 26 = {potential_key}")
    
    # Test decryption with this key
    decrypted = additive_decrypt(ciphertext, potential_key)
    print(f"Decrypted message: {decrypted}")
    
    return potential_key, decrypted

def analyze_combined_frequency(all_ciphertext):
    """Analyze frequency across all collected messages"""
    if not all_ciphertext:
        return
    
    print(f"\n=== COMBINED FREQUENCY ANALYSIS ({len(all_ciphertext)} messages) ===")
    
    # Combine all ciphertext
    combined = " ".join(all_ciphertext)
    cipher_letters = ''.join([c.upper() for c in combined if c.isalpha()])
    
    if not cipher_letters:
        print("No letters found in combined ciphertext")
        return None, None
    
    # Count frequency of each character
    char_freq = Counter(cipher_letters)
    total_letters = len(cipher_letters)
    
    print(f"\nCombined character frequencies ({total_letters} total letters):")
    print("Char | Count | Percentage | Expected E%")
    print("-" * 40)
    
    # English letter frequency (E is most common at ~12.7%)
    english_freq = {'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7}
    
    for char, count in char_freq.most_common():
        percentage = (count / total_letters) * 100
        expected = english_freq.get(chr((ord(char) - potential_key) % 26 + ord('A')), 0)
        print(f"  {char}  |  {count:2d}   |   {percentage:5.1f}%   |   {expected:4.1f}%")
    
    # Calculate key assuming most frequent = 'E'
    most_frequent = char_freq.most_common(1)[0][0]
    potential_key = (ord(most_frequent) - ord('E')) % 26
    
    print(f"\nMost frequent: '{most_frequent}' -> Assuming it's 'E'")
    print(f"Calculated key: {potential_key}")
    
    # Test decryption
    decrypted = additive_decrypt(combined, potential_key)
    print(f"Combined decryption: {decrypted[:100]}...")
    
    return potential_key, decrypted

def start_server(host="127.0.0.1", port=65432):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    
    print(f"Server running on {host}:{port}... Waiting for client.")
    
    conn, addr = server_socket.accept()
    print(f"Connected by {addr}")
    
    # First, receive the key from the client
    key_data = conn.recv(1024).decode()
    actual_key = int(key_data)
    print(f"Actual key received from client: {actual_key}")
    
    collected_ciphertext = []
    
    while True:
        data = conn.recv(1024).decode()
        if not data:
            break
        
        print(f"\nCiphertext received: {data}")
        collected_ciphertext.append(data)
        
        # Normal decryption with known key
        decrypted = additive_decrypt(data, actual_key)
        print(f"Correct decryption: {decrypted}")
        
        # Perform character frequency analysis attack
        cracked_key, cracked_message = character_frequency_analysis(data)
        
        if cracked_key is not None:
            if cracked_key == actual_key:
                print("✓ SINGLE MESSAGE ATTACK SUCCESSFUL!")
            else:
                print(f"✗ Single message attack failed. Guessed {cracked_key}, actual {actual_key}")
        
        # Combined analysis (more accurate with more data)
        if len(collected_ciphertext) >= 2:
            print(f"\n{'='*50}")
            combined_key, combined_message = analyze_combined_frequency(collected_ciphertext)
            
            if combined_key is not None:
                if combined_key == actual_key:
                    print("✓ COMBINED FREQUENCY ATTACK SUCCESSFUL!")
                else:
                    print(f"✗ Combined attack failed. Guessed {combined_key}, actual {actual_key}")

    conn.close()
    server_socket.close()

if __name__ == "__main__":
    start_server()