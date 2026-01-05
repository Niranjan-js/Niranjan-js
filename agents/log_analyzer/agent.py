import re
from dataclasses import dataclass, field
from typing import List, Optional
from agents.base_agent import BaseAgent

@dataclass
class ThreatFinding:
    threat_type: str
    description: str
    severity: str = "MEDIUM"
    source_ip: Optional[str] = "Unknown"
    metadata: dict = field(default_factory=dict)

    def __str__(self):
        return f"[{self.severity}] {self.threat_type} from {self.source_ip}: {self.description}"

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
                    threat_type="BRUTE_FORCE",
                    description="Repeated authentication failures detected",
                    severity="HIGH",
                    source_ip=ip
                ))
            
            # Check for SQL injection
            if any(p in line.upper() for p in ["SQL INJECTION", "SELECT", "UNION SELECT", "INSERT INTO", "DROP TABLE", "OR 1=1"]):
                findings.append(ThreatFinding(
                    threat_type="SQL_INJECTION",
                    description="SQL injection pattern in WAF/Application logs",
                    severity="CRITICAL",
                    source_ip=ip
                ))

            # Check for XSS
            if any(p in line.lower() for p in ["xss attempt", "<script>", "javascript:", "onerror="]):
                findings.append(ThreatFinding(
                    threat_type="XSS_ATTACK",
                    description="Cross-site scripting attempt blocked",
                    severity="HIGH",
                    source_ip=ip
                ))
            
            # Check for network reconnaissance
            if any(p in line.lower() for p in ["port scan", "nmap", "masscan"]) or ("firewall" in line.lower() and "spt=" in line.lower()):
                findings.append(ThreatFinding(
                    threat_type="NETWORK_RECON",
                    description="Abnormal connection patterns or port scanning",
                    severity="MEDIUM",
                    source_ip=ip
                ))

            # Check for Path Traversal
            if any(p in line.lower() for p in ["../", "/etc/passwd", "/windows/system32", "boot.ini"]):
                findings.append(ThreatFinding(
                    threat_type="PATH_TRAVERSAL",
                    description="Attempt to access sensitive files via path traversal",
                    severity="HIGH",
                    source_ip=ip
                ))

            # Check for Command Injection
            if any(p in line.lower() for p in ["; cat ", "; ls ", "&& id", "|| whoami", "curl http", "wget http"]):
                findings.append(ThreatFinding(
                    threat_type="COMMAND_INJECTION",
                    description="Potential OS command injection attempt",
                    severity="CRITICAL",
                    source_ip=ip
                ))

            # Check for Data Exfiltration patterns (large outbound data or suspicious tools)
            if any(p in line.lower() for p in ["base64", "openssl enc", "transfer.sh", "pastebin.com"]) or ("sent" in line.lower() and "mb" in line.lower()):
                findings.append(ThreatFinding(
                    threat_type="DATA_EXFILTRATION",
                    description="Suspicious data transfer or encoding pattern",
                    severity="HIGH",
                    source_ip=ip
                ))

            # Check for suspicious User Agents
            if any(p in line.lower() for p in ["sqlmap", "nikto", "dirbuster", "gobuster", "metasploit"]):
                findings.append(ThreatFinding(
                    threat_type="RECON_TOOL",
                    description=f"Automated security scanner detected: {line.strip()}",
                    severity="MEDIUM",
                    source_ip=ip
                ))

            # Check for SSH/FTP Brute Force
            if "ssh" in line.lower() and "failed" in line.lower() or "ftp" in line.lower() and "530" in line.lower():
                findings.append(ThreatFinding(
                    threat_type="BRUTE_FORCE",
                    description="Service-specific authentication failure (SSH/FTP)",
                    severity="HIGH",
                    source_ip=ip
                ))

        return findings