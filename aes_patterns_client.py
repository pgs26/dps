# -*- coding: utf-8 -*-
"""
Created on Mon Sep  1 05:55:43 2025

@author: preth
"""

import socket

class AESClient:
    def __init__(self):
        pass
    
    def bytes_to_hex_string(self, data):
        """Convert bytes to hex string format"""
        return ' '.join([f'{b:02x}' for b in data])
    
    def create_pattern_data(self):
        """Create test patterns to check pattern preservation"""
        patterns = {
            "Sequential": bytes(range(24)),  # 00 01 02 03... (shows ECB weakness)
            "Repeated": bytes([0x00, 0x01, 0x02, 0x03] * 6),  # Repeated pattern
            "All Zeros": bytes([0x00] * 24),  # All same byte
            "Custom": bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                           0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])  # Task example
        }
        return patterns

def start_client(host="127.0.0.1", port=65432):
    client = AESClient()
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    
    print("AES Modes Analysis Client")
    print("Testing Pattern Preservation and Error Propagation")
    
    patterns = client.create_pattern_data()
    modes = ["ECB", "CBC", "CFB"]
    
    while True:
        print(f"\n{'='*60}")
        print("Available test patterns:")
        for i, (name, data) in enumerate(patterns.items(), 1):
            print(f"{i}. {name}: {client.bytes_to_hex_string(data)}")
        
        print(f"{len(patterns)+1}. Custom pattern")
        print(f"{len(patterns)+2}. Exit")
        
        choice = input("\nSelect pattern (1-6): ")
        
        if choice == str(len(patterns)+2):  # Exit
            break
        elif choice == str(len(patterns)+1):  # Custom
            hex_input = input("Enter hex bytes (e.g., '00 01 02 03'): ")
            try:
                pattern_data = bytes.fromhex(hex_input.replace(' ', ''))
                pattern_name = "Custom"
            except:
                print("Invalid hex format")
                continue
        else:
            try:
                idx = int(choice) - 1
                pattern_name, pattern_data = list(patterns.items())[idx]
            except:
                print("Invalid choice")
                continue
        
        print(f"\nTesting pattern: {pattern_name}")
        print(f"Data: {client.bytes_to_hex_string(pattern_data)}")
        
        # Test each mode
        for mode in modes:
            try:
                # Send mode and data to server
                hex_data = client.bytes_to_hex_string(pattern_data)
                message = f"{mode}|{hex_data}"
                client_socket.send(message.encode())
                
                # Receive results
                response = client_socket.recv(4096).decode()
                print(f"\nReceived results for {mode} mode")
                
            except Exception as e:
                print(f"Error with {mode}: {e}")
        
        input("\nPress Enter to continue...")
    
    client_socket.close()

# ================================================================
# Demo Mode - Run analysis without client-server
def demo_mode():
    """Standalone demo showing all modes"""
    server = AESServer()
    
    # Test pattern from task description
    test_pattern = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
                         0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07])
    
    print("AES MODES ANALYSIS DEMO")
    print("Testing Pattern Preservation and Error Propagation")
    
    modes = ["ECB", "CBC", "CFB"]
    
    for mode in modes:
        server.analyze_mode(mode, test_pattern)
        input(f"\nPress Enter to continue to next mode...")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        demo_mode()
    elif len(sys.argv) > 1 and sys.argv[1] == "client":
        start_client()
    else:
        start_server()