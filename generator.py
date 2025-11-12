#!/usr/bin/env python3

"""
This script generates various types of network anomaly traffic for 10-minute intervals.
It uses a menu system for user selection.

REQUIREMENTS:
  pip install requests dnspython
"""

import sys
import os
import time
import socket
import threading
import http.server
import socketserver
import shutil
import secrets
import random
from concurrent.futures import ThreadPoolExecutor, TimeoutError

# --- External Library Dependencies ---
try:
    import requests
except ImportError:
    print("Error: 'requests' library not found. Please run: pip install requests", file=sys.stderr)
    sys.exit(1)

try:
    import dns.resolver
except ImportError:
    print("Error: 'dnspython' library not found. Please run: pip install dnspython", file=sys.stderr)
    sys.exit(1)
# --- End Dependencies ---


# --- Utility Functions ---

def start_http_server(port, directory="."):
    """Starts an HTTP server in a background daemon thread."""
    original_cwd = os.getcwd()
    
    # Handle changing directory safely
    try:
        os.chdir(directory)
    except FileNotFoundError:
        print(f"Warning: Directory {directory} not found. Serving from current directory.")
        directory = "."
        os.chdir(directory)

    
    handler = http.server.SimpleHTTPRequestHandler
    
    # Allow address reuse
    socketserver.TCPServer.allow_reuse_address = True
    try:
        httpd = socketserver.TCPServer(("", port), handler)
    except OSError as e:
        print(f"FATAL: Could not bind to port {port}. Is it already in use? Error: {e}")
        os.chdir(original_cwd) # Change back before exiting
        return None, None

    print(f"Starting HTTP server on port {port} in directory {os.path.abspath(directory)}...")
    
    def serve_forever(server, start_dir):
        try:
            server.serve_forever()
        except Exception as e:
            print(f"HTTP server on port {port} stopped: {e}")
        finally:
            os.chdir(start_dir) # Always change back
            
    thread = threading.Thread(target=serve_forever, args=(httpd, original_cwd))
    thread.daemon = True  # So it exits when the main script exits
    thread.start()
    
    return httpd, thread

# --- Anomaly Function Definitions (Unchanged) ---

def port_scan_anomaly(duration=600):
    """
    Script 1: High-volume port scan (creates many connections to different ports)
    """
    print(f"Starting port scan anomaly generation for {duration} seconds...")
    target_ip = "127.0.0.1"
    ports_to_scan = range(20, 1001)
    end_time = time.time() + duration
    
    while time.time() < end_time:
        for port in ports_to_scan:
            if time.time() >= end_time:
                break
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.01)  # Very fast timeout
                    s.connect_ex((target_ip, port))
            except socket.error:
                pass  # Ignore socket errors
        
        print(f"Port scan loop completed. Pausing... (Remaining: {int(end_time - time.time())}s)")
        time.sleep(1)

    print("Port scan anomaly generation completed")

def connection_flood(duration=600):
    """
    Script 2: Connection flood (rapid connections to a specific service)
    """
    print(f"Starting connection flood anomaly for {duration} seconds...")
    target_url = "http://localhost:80"
    end_time = time.time() + duration

    with requests.Session() as session:
        while time.time() < end_time:
            try:
                session.get(target_url, timeout=0.5)
            except requests.exceptions.RequestException:
                pass
            time.sleep(0.5)

    print("Connection flood anomaly completed")

def unusual_data_transfer(duration=600):
    """
    Script 3: Unusual data transfer patterns (large file transfers)
    """
    print(f"Starting unusual data transfer patterns for {duration} seconds...")
    temp_dir = "temp_anomaly"
    server_port = 8000
    file_size_mb = 100
    num_files = 3

    shutil.rmtree(temp_dir, ignore_errors=True)
    os.makedirs(temp_dir, exist_ok=True)

    print(f"Generating {num_files} large files ({file_size_mb}MB each)...")
    for i in range(1, num_files + 1):
        file_path = os.path.join(temp_dir, f"large_file_{i}")
        try:
            with open(file_path, "wb") as f:
                f.write(os.urandom(file_size_mb * 1024 * 1024))
        except MemoryError:
            print(f"ERROR: Not enough memory to create {file_size_mb}MB file. Aborting transfer anomaly.")
            return

    httpd, _ = start_http_server(server_port, temp_dir)
    if httpd is None:
        print("Failed to start HTTP server for data transfer. Aborting.")
        return
    
    end_time = time.time() + duration
    print(f"Starting {duration} seconds of file transfers...")
    
    try:
        with requests.Session() as session:
            while time.time() < end_time:
                for i in range(1, num_files + 1):
                    if time.time() >= end_time:
                        break
                    url = f"http://localhost:{server_port}/large_file_{i}"
                    try:
                        session.get(url, timeout=10) 
                    except requests.exceptions.RequestException as e:
                        print(f"Warning: File transfer failed (this is ok): {e}")
                    time.sleep(1)
    finally:
        print("Stopping file server...")
        httpd.shutdown()
        print("Cleaning up temporary files...")
        shutil.rmtree(temp_dir, ignore_errors=True)

    print("Unusual data transfer anomaly completed")

def dns_query_anomalies(duration=600):
    """
    Script 4: DNS query anomalies
    """
    print(f"Starting DNS query anomalies for {duration} seconds...")
    
    domains = [
        "very-long-subdomain-that-probably-doesnt-exist-anywhere.example.com",
        "random-subdomain-123456789.example.org",
        "this-is-an-unusually-long-domain-name-for-testing-purposes-only.com",
        f"completely-random-subdomain-for-testing-{int(time.time())}.example.net",
        f"another-unusual-domain-name-with-random-characters-{secrets.token_hex(8)}.com"
    ]
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1.0
    resolver.lifetime = 1.0
    
    end_time = time.time() + duration
    loop_count = 0
    
    def perform_query(domain):
        try:
            resolver.resolve(domain, 'A')
        except Exception:
            pass # We expect most of these to fail

    while time.time() < end_time:
        domain = random.choice(domains)
        print(f"Querying: {domain}")
        perform_query(domain)
        
        if loop_count % 20 == 0:
            print("--- Performing query burst ---")
            with ThreadPoolExecutor(max_workers=20) as executor:
                for _ in range(20):
                    executor.submit(perform_query, random.choice(domains))
        
        time.sleep(2)
        loop_count += 1
        
    print("DNS query anomalies completed")

def packet_size_anomalies(duration=600):
    """
    Script 5: Packet size anomalies
    """
    print(f"Starting packet size anomalies for {duration} seconds...")
    server_port = 8899
    
    httpd, _ = start_http_server(server_port, ".")
    if httpd is None:
        print("Failed to start HTTP server for packet size. Aborting.")
        return
        
    url = f"http://localhost:{server_port}"
    end_time = time.time() + duration

    def post_data(data, timeout):
        try:
            requests.post(url, data=data, timeout=timeout)
        except requests.exceptions.RequestException:
            pass
            
    try:
        while time.time() < end_time:
            print("Sending very large payload...")
            try:
                large_data = os.urandom(16 * 1024 * 100) # 1.6MB
            except MemoryError:
                print("ERROR: Not enough memory to create 1.6MB payload. Sending smaller payload.")
                large_data = os.urandom(1 * 1024 * 1024) # 1MB

            post_data(large_data, timeout=10)
            
            print("Sending many tiny payloads...")
            tiny_data = b'a'
            with ThreadPoolExecutor(max_workers=50) as executor:
                for _ in range(100):
                    executor.submit(post_data, tiny_data, 0.5)
            
            time.sleep(5)
    finally:
        print("Stopping receiver server...")
        httpd.shutdown()
        
    print("Packet size anomalies completed")

def abnormal_protocol_behavior(duration=600):
    """
    Script 6: Abnormal protocol behavior
    """
    print(f"Starting abnormal protocol behavior for {duration} seconds...")
    url = "http://localhost:80" 
    end_time = time.time() + duration
    loop_count = 0
    
    with requests.Session() as session:
        while time.time() < end_time:
            try:
                session.get(url, timeout=0.1)
            except requests.exceptions.RequestException:
                pass
            
            headers = {
                "X-Unusual-Header": secrets.token_hex(32),
                "Content-Type": "application/octet-stream"
            }
            try:
                session.get(url, headers=headers, timeout=1)
            except requests.exceptions.RequestException:
                pass
                
            if loop_count % 60 == 0:
                print("--- Performing OPTIONS flood ---")
                def send_options():
                    try:
                        session.options(url, timeout=1)
                    except requests.exceptions.RequestException:
                        pass
                
                with ThreadPoolExecutor(max_workers=30) as executor:
                    for _ in range(30):
                        executor.submit(send_options)
                        time.sleep(0.05)
            
            time.sleep(1)
            loop_count += 1
            
    print("Abnormal protocol behavior completed")

# --- NEW: Main Execution with Menu ---

def print_menu():
    """Prints the main menu to the console."""
    print("\n" + "="*40)
    print("  Network Anomaly Generator")
    print("="*40)
    print(" 1.  Port Scan")
    print(" 2.  Connection Flood")
    print(" 3.  Unusual Data Transfer")
    print(" 4.  DNS Query Anomalies")
    print(" 5.  Packet Size Anomalies")
    print(" 6.  Abnormal Protocol Behavior")
    print(" ---")
    print(" 0.  Run ALL anomalies (MIXED/CONCURRENTLY)")
    print(" 9.  Quit")
    print("="*40)
    return input("Enter your choice (0-6 or 9): ")

if __name__ == "__main__":
    
    while True:
        choice = print_menu()
        
        try:
            if choice == '1':
                port_scan_anomaly()
            elif choice == '2':
                connection_flood()
            elif choice == '3':
                unusual_data_transfer()
            elif choice == '4':
                dns_query_anomalies()
            elif choice == '5':
                packet_size_anomalies()
            elif choice == '6':
                abnormal_protocol_behavior()
            
            elif choice == '0':
                # Run all anomalies "mixed" (concurrently)
                print("--- STARTING ALL 6 ANOMALIES (MIXED/CONCURRENTLY) ---")
                print("All anomalies will run at the same time for 10 minutes.")
                
                functions = [
                    port_scan_anomaly,
                    connection_flood,
                    unusual_data_transfer,
                    dns_query_anomalies,
                    packet_size_anomalies,
                    abnormal_protocol_behavior
                ]
                
                with ThreadPoolExecutor(max_workers=len(functions)) as executor:
                    # Submit all functions to run for 600s
                    futures = [executor.submit(func, 600) for func in functions]
                    
                    print("All 6 anomalies are running. This will take 10 minutes.")
                    print("Pressing Ctrl+C will return you to the menu (anomaly threads will stop).")
                    
                    # Wait for all functions to complete, but handle Ctrl+C
                    for future in futures:
                        future.result() # Wait for each one to finish
                
                print("--- ALL 6 MIXED ANOMALIES COMPLETED ---")
                
            elif choice == '9':
                print("Exiting.")
                break
            else:
                print("Invalid choice. Please try again.")

        except KeyboardInterrupt:
            print("\nOperation cancelled by user. Returning to menu.")
        except Exception as e:
            print(f"\nAn error occurred: {e}", file=sys.stderr)
            print("Returning to menu.")