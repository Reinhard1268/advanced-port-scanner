#!/usr/bin/env python3
import socket
import sys
import select
import threading
import queue
from concurrent.futures import ThreadPoolExecutor, as_completed
import errno
import time
import json
import csv
import re
import argparse
from functools import partial

# Protocol-specific payloads for UDP scanning
UDP_PROBES = {
    53: b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",  # DNS
    67: b"\x01\x01\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # DHCP
    161: b"\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x71\xb4\xb5\x68\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",  # SNMP
    123: b'\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # NTP
}

# Version detection probes
VERSION_PROBES = {
    'http': b"GET / HTTP/1.0\r\n\r\n",
    'ftp': b"USER anonymous\r\n",
    'smtp': b"HELO example.com\r\n",
    'ssh': b"SSH-2.0-Client\r\n",
    'pop3': b"USER test\r\n",
    'imap': b"A001 CAPABILITY\r\n"
}

def get_service_name(port, protocol):
    """Map common ports to their service names."""
    service_map = {
        (53, 'tcp'): 'DNS',
        (53, 'udp'): 'DNS',
        (80, 'tcp'): 'HTTP',
        (443, 'tcp'): 'HTTPS',
        (22, 'tcp'): 'SSH',
        (21, 'tcp'): 'FTP',
        (25, 'tcp'): 'SMTP',
        (110, 'tcp'): 'POP3',
        (143, 'tcp'): 'IMAP',
        (161, 'udp'): 'SNMP',
        (123, 'udp'): 'NTP',
        (67, 'udp'): 'DHCP',
        (68, 'udp'): 'DHCP',
        (853, 'tcp'): 'DNS-over-TLS',
        (3306, 'tcp'): 'MySQL',
        (5432, 'tcp'): 'PostgreSQL',
        (3389, 'tcp'): 'RDP'
    }
    return service_map.get((port, protocol.lower()), 'Unknown')

def detect_version(host, port, banner, protocol, timeout=2):
    """Perform version detection for open ports."""
    if not banner:
        return "Unknown"
    
    # Try to extract version from banner
    version_patterns = {
        'SSH': r'SSH-(\d+\.\d+-[^\s]+)',
        'HTTP': r'Server:\s*([^\r\n]+)',
        'FTP': r'\(([^\)]+)\)',
        'SMTP': r'(\d+ [^\s]+)'
    }
    
    for service, pattern in version_patterns.items():
        if service in banner:
            match = re.search(pattern, banner)
            if match:
                return match.group(1)
    
    # Send protocol-specific probes
    service_name = get_service_name(port, protocol).lower()
    probe = None
    
    if service_name in VERSION_PROBES:
        probe = VERSION_PROBES[service_name]
    elif 'http' in service_name:
        probe = VERSION_PROBES['http']
    
    if probe:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((host, port))
                s.sendall(probe)
                response = s.recv(1024).decode(errors='ignore')
                
                # HTTP specific parsing
                if service_name == 'http' and 'Server:' in response:
                    match = re.search(r'Server:\s*([^\r\n]+)', response, re.IGNORECASE)
                    if match:
                        return match.group(1).strip()
                
                return response.split('\n')[0].strip() if response else "No response"
        except:
            return "Probe failed"
    
    return banner.split('\n')[0].strip() if banner else "Unknown"

def scan_port(host, port, protocol="tcp", timeout=1, version_detect=False):
    """Scan a single port and return its status and banner if available."""
    result = {
        "port": port,
        "protocol": protocol,
        "status": "UNKNOWN",
        "service": get_service_name(port, protocol),
        "banner": None,
        "version": None
    }
    
    if protocol == "tcp":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            try:
                sock.connect((host, port))
                try:
                    # Attempt banner grab
                    banner = sock.recv(1024).decode(errors='ignore').strip()
                    result["status"] = "OPEN"
                    result["banner"] = banner
                    
                    # Version detection
                    if version_detect and banner:
                        result["version"] = detect_version(host, port, banner, protocol, timeout)
                        
                except (socket.error, UnicodeDecodeError):
                    result["status"] = "OPEN"
            except socket.timeout:
                result["status"] = "FILTERED"
            except ConnectionRefusedError:
                result["status"] = "CLOSED"
            except socket.error as e:
                if e.errno == errno.EHOSTUNREACH:
                    result["status"] = "FILTERED"
                else:
                    result["status"] = "ERROR"
                    result["banner"] = str(e)
    
    elif protocol == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            try:
                # Send protocol-specific payload if available
                payload = UDP_PROBES.get(port, b"SCAN_PROBE")
                sock.sendto(payload, (host, port))
                
                try:
                    data, _ = sock.recvfrom(1024)
                    result["status"] = "OPEN"
                    result["banner"] = data.hex()[:50] + "..." if data else None
                except socket.timeout:
                    # No response could mean open|filtered
                    result["status"] = "FILTERED"
                    
            except socket.error as e:
                if e.errno in (errno.ECONNREFUSED, errno.EHOSTUNREACH):
                    result["status"] = "CLOSED"
                else:
                    result["status"] = "ERROR"
                    result["banner"] = str(e)
    
    else:
        raise ValueError("Invalid protocol. Use 'tcp' or 'udp'")
    
    return result

def output_manager(output_queue, output_file=None, format='text'):
    """Dedicated thread to manage all output printing."""
    if output_file and format == 'csv':
        writer = csv.writer(output_file)
        writer.writerow(['Port', 'Protocol', 'Status', 'Service', 'Version', 'Banner'])
    elif output_file and format == 'json':
        results = []
    
    while True:
        message = output_queue.get()
        if message == "EXIT":
            break
            
        if isinstance(message, dict):
            # Result dictionary
            if format == 'text' and message['status'] == 'OPEN':
                banner_info = f" | Banner: {message['banner']}" if message['banner'] else ""
                version_info = f" | Version: {message['version']}" if message['version'] else ""
                output = f"Port {message['port']}/{(message['protocol']+' ').upper():<5} OPEN ({message['service']}){version_info}{banner_info}"
                print(output, flush=True)
                if output_file and format == 'text':
                    output_file.write(output + '\n')
            
            if format == 'csv' and output_file:
                writer.writerow([
                    message['port'],
                    message['protocol'].upper(),
                    message['status'],
                    message['service'],
                    message.get('version', ''),
                    message.get('banner', '')[:200]  # Limit banner length
                ])
                
            if format == 'json' and output_file:
                results.append(message)
        else:
            # Regular message
            print(message, flush=True)
            if output_file and format == 'text':
                output_file.write(message + '\n')
    
    if format == 'json' and output_file:
        json.dump(results, output_file, indent=2)

def scan_host(host, ports, protocol="tcp", timeout=1, max_threads=100, 
              version_detect=False, output_queue=None, exclude_ports=None):
    """Scan multiple ports on a host with progress monitoring."""
    if exclude_ports:
        ports = [p for p in ports if p not in exclude_ports]
    
    if not ports:
        output_queue.put("No ports to scan after exclusions")
        return []
    
    output_queue.put(f"\nStarting {protocol.upper()} scan on {host}...")
    results = []
    scanned_count = 0
    total_ports = len(ports)
    lock = threading.Lock()
    progress_queue = queue.Queue()
    last_progress = 0
    
    # Adjust timeout for large scans
    if len(ports) > 500:
        output_queue.put("Large port range detected, increasing timeout...")
        timeout = max(timeout * 2, 2.0)  # Cap at minimum 2s
    
    def worker(port):
        nonlocal scanned_count
        result = scan_port(host, port, protocol, timeout, version_detect)
        with lock:
            results.append(result)
            scanned_count += 1
            progress_queue.put(scanned_count)
            output_queue.put(result)  # Send result to output manager
        return result

    # Start scanning
    start_time = time.time()
    try:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(worker, port): port for port in ports}
            
            # Progress monitoring in main thread
            while scanned_count < total_ports:
                try:
                    current = progress_queue.get(timeout=0.5)
                    # Update progress only when it changes significantly
                    if current != last_progress and (current % 10 == 0 or current == total_ports):
                        progress_msg = f"Progress: {current}/{total_ports} ports scanned"
                        output_queue.put(progress_msg)
                        last_progress = current
                except queue.Empty:
                    pass
                
            # Wait for completion
            for future in as_completed(futures):
                pass  # Results handled in worker
        
        output_queue.put(f"Progress: {total_ports}/{total_ports} ports scanned")
        duration = time.time() - start_time
        output_queue.put(f"{protocol.upper()} scan completed in {duration:.2f} seconds")
        return results
    
    except KeyboardInterrupt:
        output_queue.put("\nScan interrupted by user!")
        sys.exit(1)
    except Exception as e:
        output_queue.put(f"Scan error: {str(e)}")
        return results

def parse_ports(port_str):
    """Parse port ranges and comma-separated lists."""
    ports = set()
    parts = port_str.split(',')
    
    for part in parts:
        if '-' in part:
            start, end = part.split('-')
            try:
                start_port = int(start.strip())
                end_port = int(end.strip())
                validate_ports(start_port, end_port)
                ports.update(range(start_port, end_port + 1))
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid port range: {part}")
        else:
            try:
                port = int(part.strip())
                if not 1 <= port <= 65535:
                    raise ValueError
                ports.add(port)
            except ValueError:
                raise argparse.ArgumentTypeError(f"Invalid port: {part}")
    
    return sorted(ports)

def validate_ports(start, end):
    """Validate port range inputs."""
    if not (1 <= start <= 65535 and 1 <= end <= 65535):
        raise ValueError("Ports must be between 1-65535")
    if start > end:
        raise ValueError("Start port cannot be greater than end port")

def main():
    parser = argparse.ArgumentParser(description='Advanced Port Scanner', 
                                     epilog='Example: ./scanner.py 192.168.1.1 -p 1-1000 --protocol all')
    parser.add_argument('host', help='Target host to scan')
    parser.add_argument('-p', '--ports', required=True, 
                        help='Ports to scan (e.g., 80,443 or 1-1000)')
    parser.add_argument('--protocol', choices=['tcp', 'udp', 'all'], default='all',
                        help='Protocol to scan (default: all)')
    parser.add_argument('-t', '--timeout', type=float, default=0.5,
                        help='Base timeout per port in seconds (default: 0.5)')
    parser.add_argument('--threads', type=int, default=100,
                        help='Maximum threads (default: 100)')
    parser.add_argument('--exclude-ports', 
                        help='Comma-separated ports to exclude (e.g., 22,80)')
    parser.add_argument('-o', '--output', 
                        help='Output file for scan results')
    parser.add_argument('--format', choices=['text', 'csv', 'json'], default='text',
                        help='Output format (default: text)')
    parser.add_argument('--version-detect', action='store_true',
                        help='Enable version detection (like Nmap -sV)')
    parser.add_argument('-y', '--yes', action='store_true',
                        help='Skip permission confirmation')
    
    args = parser.parse_args()
    
    # Permission confirmation
    if not args.yes:
        confirm = input("Confirm you have permission to scan (y/n): ").lower()
        if not confirm.startswith('y'):
            print("Scan aborted")
            sys.exit(0)
    
    try:
        # Parse ports
        ports = parse_ports(args.ports)
        exclude_ports = parse_ports(args.exclude_ports) if args.exclude_ports else []
        
        # Setup output
        output_file = open(args.output, 'w') if args.output else None
        output_queue = queue.Queue()
        output_thread = threading.Thread(
            target=output_manager, 
            args=(output_queue, output_file, args.format),
            daemon=True
        )
        output_thread.start()
        
        # Host reachability check
        try:
            socket.gethostbyname(args.host)
        except socket.error:
            output_queue.put(f"Host {args.host} unreachable")
            sys.exit(1)
        
        start_time = time.time()
        tcp_results = []
        udp_results = []
        
        if args.protocol in ("tcp", "all"):
            tcp_results = scan_host(
                args.host, ports, "tcp", 
                timeout=args.timeout,
                max_threads=args.threads,
                version_detect=args.version_detect,
                output_queue=output_queue,
                exclude_ports=exclude_ports
            )
        
        if args.protocol in ("udp", "all"):
            udp_results = scan_host(
                args.host, ports, "udp", 
                timeout=max(args.timeout * 3, 1.5),  # Longer UDP timeout
                max_threads=args.threads,
                version_detect=args.version_detect,
                output_queue=output_queue,
                exclude_ports=exclude_ports
            )
        
        duration = time.time() - start_time
        output_queue.put(f"\nTotal scan completed in {duration:.2f} seconds")
        
        # Summary report
        if args.format == 'text':
            if args.protocol in ("tcp", "all") and tcp_results:
                output_queue.put("\nTCP Summary:")
                for res in sorted(tcp_results, key=lambda x: x['port']):
                    if res['status'] == 'OPEN':
                        version_info = f" | Version: {res['version']}" if res['version'] else ""
                        banner_info = f" | Banner: {res['banner']}" if res['banner'] else ""
                        output_queue.put(f"  {res['port']}/TCP: {res['service']}{version_info}{banner_info}")
            
            if args.protocol in ("udp", "all") and udp_results:
                output_queue.put("\nUDP Summary:")
                for res in sorted(udp_results, key=lambda x: x['port']):
                    if res['status'] == 'OPEN':
                        version_info = f" | Version: {res['version']}" if res['version'] else ""
                        banner_info = f" | Banner: {res['banner']}" if res['banner'] else ""
                        output_queue.put(f"  {res['port']}/UDP: {res['service']}{version_info}{banner_info}")
            
            # Show counts for filtered ports
            total_ports = len(ports) - len(exclude_ports)
            if args.protocol in ("tcp", "all"):
                open_tcp = sum(1 for r in tcp_results if r['status'] == 'OPEN')
                output_queue.put(f"\nTCP ports: {open_tcp} open, {total_ports - open_tcp} filtered/closed")
            
            if args.protocol in ("udp", "all"):
                open_udp = sum(1 for r in udp_results if r['status'] == 'OPEN')
                output_queue.put(f"UDP ports: {open_udp} open, {total_ports - open_udp} filtered/closed")
    
    except Exception as e:
        output_queue.put(f"Critical error: {str(e)}")
    finally:
        output_queue.put("EXIT")
        output_thread.join()
        if output_file:
            output_file.close()

if __name__ == "__main__":
    main()