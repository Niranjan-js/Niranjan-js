from typing import List, Dict, DefaultDict
from collections import defaultdict
from agents.types import ThreatFinding

class CorrelationAgent:
    """
    Correlates multiple threat findings by Source IP and other metadata 
    to identify advanced multi-vector attack patterns.
    """

    def correlate(self, findings: List[ThreatFinding]) -> List[Dict]:
        correlated_events = []
        
        # Group findings by source IP
        ip_groups: DefaultDict[str, List[ThreatFinding]] = defaultdict(list)
        for f in findings:
            if f.source_ip and f.source_ip != "Unknown":
                ip_groups[f.source_ip].append(f)
            else:
                # If IP is unknown, track it separately
                correlated_events.append({
                    "attack": f.threat_type,
                    "severity": f.severity,
                    "source": "Unknown",
                    "agent": f.agent_name,
                    "description": f.description
                })

        for ip, ip_findings in ip_groups.items():
            threat_types = set(f.threat_type for f in ip_findings)
            agent_names = set(f.agent_name for f in ip_findings)
            
            # Pattern 1: Multi-Vector Attack (Email + Log)
            if "EmailVerificationAgent" in agent_names and "LogAnalysisAgent" in agent_names:
                correlated_events.append({
                    "attack": "MULTI_VECTOR_CAMPAIGN",
                    "severity": "CRITICAL",
                    "source": ip,
                    "description": f"IP {ip} linked to both Phishing Email and suspicious Log activity."
                })
            
            # Pattern 2: Targeted Exploitation (IP Scan + Log)
            elif "IPRangeAnalyzerAgent" in agent_names and "LogAnalysisAgent" in agent_names:
                correlated_events.append({
                    "attack": "TARGETED_EXPLOITATION",
                    "severity": "CRITICAL",
                    "source": ip,
                    "description": f"IP {ip} showed vulnerabilities in scan and now active exploit in logs."
                })

            # Pattern 3: Brute Force leading to Injection
            elif "BRUTE_FORCE" in threat_types and ("SQL_INJECTION" in threat_types or "XSS_ATTACK" in threat_types):
                correlated_events.append({
                    "attack": "ADVANCED_PERSISTENT_THREAT",
                    "severity": "CRITICAL",
                    "source": ip,
                    "description": f"IP {ip} exhibited brute force followed by injection attempts."
                })
            
            # Pass through individual findings
            else:
                for f in ip_findings:
                    correlated_events.append({
                        "attack": f.threat_type,
                        "severity": f.severity,
                        "source": ip,
                        "agent": f.agent_name,
                        "description": f.description
                    })

        return correlated_events