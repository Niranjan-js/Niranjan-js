import re
from typing import List
from agents.base_agent import BaseAgent
from agents.types import ThreatFinding

class LogAnalysisAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="LogAnalysisAgent")
        self.ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')

    async def analyze(self, logs: str) -> List[ThreatFinding]:
        findings = []
        lines = logs.split('\n')
        
        for line in lines:
            if not line.strip(): continue
            
            ip_match = self.ip_pattern.search(line)
            ip = ip_match.group(1) if ip_match else "Unknown"

            # Check for authentication failures
            if any(p in line.lower() for p in ["authentication failure", "failed password", "unauthorized access", "access denied"]):
                findings.append(ThreatFinding(
                    agent_name=self.name,
                    threat_type="BRUTE_FORCE",
                    description="Repeated authentication failures detected",
                    severity="HIGH",
                    source_ip=ip
                ))
            
            # Check for SQL injection
            if any(p in line.upper() for p in ["SQL INJECTION", "SELECT", "UNION SELECT", "INSERT INTO", "DROP TABLE", "OR 1=1"]):
                findings.append(ThreatFinding(
                    agent_name=self.name,
                    threat_type="SQL_INJECTION",
                    description="SQL injection pattern in WAF/Application logs",
                    severity="CRITICAL",
                    source_ip=ip
                ))

            # Check for XSS
            if any(p in line.lower() for p in ["xss attempt", "<script>", "javascript:", "onerror="]):
                findings.append(ThreatFinding(
                    agent_name=self.name,
                    threat_type="XSS_ATTACK",
                    description="Cross-site scripting attempt blocked",
                    severity="HIGH",
                    source_ip=ip
                ))
            
            # Check for network reconnaissance
            if any(p in line.lower() for p in ["port scan", "nmap", "masscan"]) or ("firewall" in line.lower() and "spt=" in line.lower()):
                findings.append(ThreatFinding(
                    agent_name=self.name,
                    threat_type="NETWORK_RECON",
                    description="Abnormal connection patterns or port scanning",
                    severity="MEDIUM",
                    source_ip=ip
                ))

            # Check for Path Traversal
            if any(p in line.lower() for p in ["../", "/etc/passwd", "/windows/system32", "boot.ini", "/etc/shadow"]):
                findings.append(ThreatFinding(
                    agent_name=self.name,
                    threat_type="PATH_TRAVERSAL",
                    description="Attempt to access sensitive files via path traversal",
                    severity="HIGH",
                    source_ip=ip
                ))

            # Check for Command Injection / Reverse Shell
            if any(p in line.lower() for p in ["; cat ", "; ls ", "&& id", "|| whoami", "curl http", "wget http", "reverse_shell", "/tmp/"]):
                findings.append(ThreatFinding(
                    agent_name=self.name,
                    threat_type="COMMAND_INJECTION",
                    description="Potential OS command injection or suspicious process execution detected",
                    severity="CRITICAL",
                    source_ip=ip
                ))

            # Check for Data Exfiltration / Unusual Network
            if any(p in line.lower() for p in ["large outbound", "gb", "mb", "tor exit", "base64", "openssl enc"]):
                findings.append(ThreatFinding(
                    agent_name=self.name,
                    threat_type="DATA_EXFILTRATION",
                    description="Suspicious data transfer or network connection detected",
                    severity="HIGH",
                    source_ip=ip
                ))

            # Check for suspicious User Agents / Scanners (Existing)
            if any(p in line.lower() for p in ["sqlmap", "nikto", "dirbuster", "gobuster", "metasploit"]):
                findings.append(ThreatFinding(
                    agent_name=self.name,
                    threat_type="RECON_TOOL",
                    description=f"Automated security scanner detected",
                    severity="MEDIUM",
                    source_ip=ip
                ))

            # Check for SSH/FTP Brute Force
            if "ssh" in line.lower() and "failed" in line.lower() or "ftp" in line.lower() and "530" in line.lower():
                findings.append(ThreatFinding(
                    agent_name=self.name,
                    threat_type="BRUTE_FORCE",
                    description="Service-specific authentication failure (SSH/FTP)",
                    severity="HIGH",
                    source_ip=ip
                ))

        return findings