"""
Simple Log Parser Test - No Unicode
Tests Web Server Log Parser directly
"""

import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

print("=" * 80)
print("CyberGuard AI - Log Parser Test")
print("=" * 80)
print()

from log_ingestors.web_server_logs import WebServerLogParser

threats_found = []

def threat_callback(log_data):
    threats_found.append(log_data)
    severity = log_data.get('severity', 'UNKNOWN')
    source_ip = log_data.get('source_ip', 'unknown')
    threats = log_data.get('threats', [])
    message = log_data.get('message', '')
    
    print(f"[{severity}] {source_ip}: {', '.join(threats)}")
    print(f"    {message}")
    print()

# Create parser
parser = WebServerLogParser(callback=threat_callback)

# Check log file
log_file = r"C:\logs\access.log"

if os.path.exists(log_file):
    print(f"Reading: {log_file}")
    print()
    
    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
    
    print(f"Processing {len(lines)} log entries...\n")
    
    for line in lines:
        if line.strip():
            parser.process_log_line(line.strip())
    
    print("=" * 80)
    print(f"RESULT: Found {len(threats_found)} threats in {len(lines)} log entries")
    print("=" * 80)
    print()
    
    if threats_found:
        print("Threat Summary:")
        threat_types = {}
        for t in threats_found:
            for threat in t.get('threats', []):
                threat_types[threat] = threat_types.get(threat, 0) + 1
        
        for threat_type, count in sorted(threat_types.items()):
            print(f"  {threat_type}: {count}")
        
        print()
        print("SUCCESS: Web Server Log Parser is WORKING!")
    else:
        print("No threats detected (all logs were clean)")
else:
    print(f"ERROR: Log file not found: {log_file}")
    print("Run these commands to create it:")
    print()
    print('mkdir C:\\logs')
    print('echo 192.168.1.100 - - [15/Jan/2026:13:00:00 +0530] "GET /login.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 200 890 > C:\\logs\\access.log')

print()
