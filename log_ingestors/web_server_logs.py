"""
Web Server Log Parser

Parses Apache and Nginx logs for security threats.
Detects SQL injection, XSS, path traversal, and scanner activity.
"""

import re
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path
import threading
import time


class WebServerLogParser:
    """Parse Apache/Nginx logs for security threats"""
    
    # Apache Common Log Format: IP - - [timestamp] "METHOD /path HTTP/1.1" status size
    COMMON_LOG_PATTERN = r'(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+) \S+" (\d{3}) (\S+)'
    
    # Apache Combined Log Format (includes user agent and referer)
    COMBINED_LOG_PATTERN = r'(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] "(\S+) (\S+) \S+" (\d{3}) (\S+) "([^"]*)" "([^"]*)"'
    
    # Threat patterns
    SQL_INJECTION_PATTERNS = [
        r"union\s+select",
        r"or\s+1\s*=\s*1",
        r"'\s*or\s*'",
        r"--\s*$",
        r";.*drop\s+table",
        r"exec\s*\(",
        r"insert\s+into",
        r"select.*from.*where"
    ]
    
    XSS_PATTERNS = [
        r"<script",
        r"javascript:",
        r"onerror\s*=",
        r"onload\s*=",
        r"<iframe",
        r"alert\s*\("
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r"\.\./",
        r"\.\.\\",
        r"/etc/passwd",
        r"/etc/shadow",
        r"c:\\windows",
        r"\.\.%2f"
    ]
    
    SCANNER_USER_AGENTS = [
        "nikto",
        "sqlmap",
        "nmap",
        "masscan",
        "metasploit",
        "burp",
        "acunetix",
        "nessus",
        "openvas"
    ]
    
    def __init__(self, callback=None):
        """
        Initialize Web Server Log Parser
        
        Args:
            callback: Function to call with detected threats
        """
        self.callback = callback
        self.running = False
        self.thread = None
        self.watched_files = []
        
    def parse_line(self, line: str) -> Optional[Dict]:
        """
        Parse a single log line
        
        Args:
            line: Log line string
            
        Returns:
            Parsed log dict or None
        """
        # Try combined format first (more info)
        match = re.match(self.COMBINED_LOG_PATTERN, line)
        if match:
            ip, timestamp, method, path, status, size, referer, user_agent = match.groups()
        else:
            # Try common format
            match = re.match(self.COMMON_LOG_PATTERN, line)
            if match:
                ip, timestamp, method, path, status, size = match.groups()
                referer = ""
                user_agent = ""
            else:
                return None
        
        return {
            "ip": ip,
            "timestamp": timestamp,
            "method": method,
            "path": path,
            "status": int(status),
            "size": size,
            "referer": referer,
            "user_agent": user_agent,
            "raw": line
        }
    
    def detect_threats(self, parsed_log: Dict) -> List[Dict]:
        """
        Detect security threats in parsed log
        
        Args:
            parsed_log: Parsed log dictionary
            
        Returns:
            List of detected threats
        """
        threats = []
        path = parsed_log["path"].lower()
        user_agent = parsed_log["user_agent"].lower()
        
        # SQL Injection Detection
        for pattern in self.SQL_INJECTION_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                threats.append({
                    "type": "SQL_INJECTION",
                    "severity": "CRITICAL",
                    "pattern": pattern,
                    "location": "path"
                })
                break
        
        # XSS Detection
        for pattern in self.XSS_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                threats.append({
                    "type": "XSS",
                    "severity": "HIGH",
                    "pattern": pattern,
                    "location": "path"
                })
                break
        
        # Path Traversal Detection
        for pattern in self.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                threats.append({
                    "type": "PATH_TRAVERSAL",
                    "severity": "HIGH",
                    "pattern": pattern,
                    "location": "path"
                })
                break
        
        # Scanner Detection
        for scanner in self.SCANNER_USER_AGENTS:
            if scanner in user_agent:
                threats.append({
                    "type": "SCANNER_DETECTED",
                    "severity": "MEDIUM",
                    "scanner": scanner,
                    "location": "user_agent"
                })
                break
        
        # Suspicious Status Codes
        if parsed_log["status"] == 403:
            threats.append({
                "type": "FORBIDDEN_ACCESS",
                "severity": "MEDIUM",
                "status": 403,
                "location": "status"
            })
        elif parsed_log["status"] == 401:
            threats.append({
                "type": "UNAUTHORIZED_ACCESS",
                "severity": "MEDIUM",
                "status": 401,
                "location": "status"
            })
        
        return threats
    
    def normalize_log(self, parsed_log: Dict, threats: List[Dict]) -> Dict:
        """
        Normalize log to standard format
        
        Args:
            parsed_log: Parsed log dict
            threats: List of detected threats
            
        Returns:
            Normalized log dict
        """
        severity = "INFO"
        if threats:
            # Use highest severity
            severities = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            max_severity = max(threats, key=lambda t: severities.get(t["severity"], 0))
            severity = max_severity["severity"]
        
        threat_types = [t["type"] for t in threats]
        
        return {
            "timestamp": datetime.now().isoformat(),
            "source": "web_server_log",
            "severity": severity,
            "source_ip": parsed_log["ip"],
            "method": parsed_log["method"],
            "path": parsed_log["path"],
            "status": parsed_log["status"],
            "user_agent": parsed_log["user_agent"],
            "threats": threat_types,
            "message": f"Web request from {parsed_log['ip']}: {parsed_log['method']} {parsed_log['path']} - Threats: {', '.join(threat_types) if threat_types else 'None'}",
            "raw_data": {
                "referer": parsed_log["referer"],
                "size": parsed_log["size"],
                "threat_details": threats
            }
        }
    
    def process_log_line(self, line: str):
        """
        Process a single log line
        
        Args:
            line: Log line string
        """
        parsed = self.parse_line(line)
        if not parsed:
            return
        
        threats = self.detect_threats(parsed)
        
        # Only report if threats detected or callback wants all logs
        if threats or self.callback:
            normalized = self.normalize_log(parsed, threats)
            if self.callback:
                self.callback(normalized)
    
    def watch_file(self, filepath: str):
        """
        Watch a log file for new entries
        
        Args:
            filepath: Path to log file
        """
        path = Path(filepath)
        if not path.exists():
            print(f"[WebServerLogParser] File not found: {filepath}")
            return
        
        self.watched_files.append(filepath)
        print(f"[WebServerLogParser] Watching {filepath}")
        
        # Read existing content first
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            # Skip to end
            f.seek(0, 2)
            
            while self.running:
                line = f.readline()
                if line:
                    self.process_log_line(line.strip())
                else:
                    time.sleep(0.5)
    
    def start(self, log_files: List[str]):
        """
        Start watching log files
        
        Args:
            log_files: List of log file paths to watch
        """
        if self.running:
            print("[WebServerLogParser] Already running")
            return
        
        self.running = True
        
        # Start a thread for each log file
        for log_file in log_files:
            thread = threading.Thread(target=self.watch_file, args=(log_file,), daemon=True)
            thread.start()
        
        print(f"[WebServerLogParser] Started watching {len(log_files)} log files")
    
    def stop(self):
        """Stop watching log files"""
        self.running = False
        print("[WebServerLogParser] Stopped")


# Test function
if __name__ == "__main__":
    def print_threat(log):
        if log["threats"]:
            print(f"\n[THREAT DETECTED]")
            print(f"  IP: {log['source_ip']}")
            print(f"  Severity: {log['severity']}")
            print(f"  Threats: {', '.join(log['threats'])}")
            print(f"  Path: {log['path']}")
            print(f"  Message: {log['message']}")
    
    print("Testing Web Server Log Parser...")
    
    # Test with sample log lines
    parser = WebServerLogParser(callback=print_threat)
    
    sample_logs = [
        '192.168.1.100 - - [14/Jan/2026:22:00:00 +0530] "GET /index.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 200 1234',
        '10.0.0.5 - - [14/Jan/2026:22:00:01 +0530] "GET /admin.php HTTP/1.1" 403 567',
        '172.16.0.8 - - [14/Jan/2026:22:00:02 +0530] "GET /test.php?file=../../etc/passwd HTTP/1.1" 200 890 "-" "Nikto/2.1.6"',
        '192.168.1.50 - - [14/Jan/2026:22:00:03 +0530] "GET /search.php?q=<script>alert(1)</script> HTTP/1.1" 200 456'
    ]
    
    print("\nProcessing sample logs:\n")
    for log in sample_logs:
        parser.process_log_line(log)
