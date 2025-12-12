#!/usr/bin/env python3
import socket
import struct
import re
import sys
import os
from datetime import datetime

def create_raw_socket():
    """Create a raw socket to capture packets"""
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        return s
    except socket.error as e:
        print(f"Socket creation error: {e}")
        print("Try running with sudo!")
        sys.exit(1)

def parse_ip_header(data):
    """Parse IP header and return source/destination IPs and protocol"""
    iph = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version_ihl = iph[0]
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    protocol = iph[6]
    src_ip = socket.inet_ntoa(iph[8])
    dst_ip = socket.inet_ntoa(iph[9])
    return src_ip, dst_ip, protocol, iph_length

def parse_tcp_header(data):
    """Parse TCP header and return source/destination ports"""
    tcph = struct.unpack('!HHLLBBHHH', data[:20])
    src_port = tcph[0]
    dst_port = tcph[1]
    data_offset = (tcph[4] >> 4) * 4
    return src_port, dst_port, data_offset

def extract_host(line):
    """Extract host value from Host: header line"""
    if ':' in line:
        # Get everything after the first colon
        value = line.split(':', 1)[1].strip()
        return value
    return None

def load_existing_hosts(filename):
    """Load existing hosts from file"""
    hosts = set()
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                for line in f:
                    host = line.strip()
                    if host:
                        hosts.add(host)
        except:
            pass
    return hosts

def save_host(filename, host):
    """Save a host to file"""
    try:
        with open(filename, 'a') as f:
            f.write(f"{host}\n")
    except:
        pass

def main():
    output_file = "captured_hosts.txt"
    # Only look for Host: header (case-insensitive)
    patterns = [
        re.compile(r"Host:", re.IGNORECASE)
    ]
    target_ports = {80, 700}
    
    # Check for root
    if os.geteuid() != 0:
        print("Error: This script requires root privileges.")
        print("Please run with: sudo python3 script_name.py")
        sys.exit(1)
    
    # Load existing hosts
    existing_hosts = load_existing_hosts(output_file)
    unique_count = len(existing_hosts)
    
    print(f"Starting packet capture for ports {target_ports}...")
    print(f"Only capturing 'Host:' headers")
    print(f"Unique hosts will be saved to: {output_file}")
    print(f"Already have {unique_count} existing hosts")
    print("Press Ctrl+C to stop")
    print("-" * 80)
    
    sock = create_raw_socket()
    
    try:
        while True:
            packet = sock.recvfrom(65565)
            packet_data = packet[0]
            
            # Parse Ethernet header
            eth_length = 14
            eth_header = packet_data[:eth_length]
            eth = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth[2])
            
            # Only process IP packets
            if eth_protocol == 8:  # IPv4
                # Parse IP header
                src_ip, dst_ip, protocol, iph_length = parse_ip_header(packet_data[eth_length:])
                
                # Check for TCP protocol
                if protocol == 6:  # TCP
                    tcp_header_start = eth_length + iph_length
                    tcp_header = packet_data[tcp_header_start:tcp_header_start+20]
                    src_port, dst_port, data_offset = parse_tcp_header(tcp_header)
                    
                    # Check if packet is on target port
                    if src_port in target_ports or dst_port in target_ports:
                        tcp_header_size = tcp_header_start + data_offset
                        payload = packet_data[tcp_header_size:]
                        
                        try:
                            payload_text = payload.decode('utf-8', errors='ignore')
                            
                            for pattern in patterns:
                                if pattern.search(payload_text):
                                    lines = payload_text.split('\n')
                                    for line in lines:
                                        if pattern.search(line):
                                            host = extract_host(line)
                                            if host and host not in existing_hosts:
                                                timestamp = datetime.now().strftime("%H:%M:%S")
                                                print(f"[{timestamp}] NEW HOST: {host}")
                                                print(f"    Source: {src_ip}:{src_port}")
                                                print(f"    Destination: {dst_ip}:{dst_port}")
                                                save_host(output_file, host)
                                                existing_hosts.add(host)
                                                unique_count += 1
                        except:
                            continue
                            
    except KeyboardInterrupt:
        print(f"\n\nCapture stopped.")
        print(f"Total unique hosts captured: {unique_count}")
        print(f"Hosts saved to: {output_file}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
