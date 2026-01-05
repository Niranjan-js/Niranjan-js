from typing import List, Dict, DefaultDict
from collections import defaultdict
from agents.log_analyzer.agent import ThreatFinding

class CorrelationAgent:
    """
    Correlates multiple threat findings by Source IP to identify advanced attack patterns.
    """

    def correlate(self, findings: List[ThreatFinding]) -> List[Dict]:
        correlated_events = []
        
        # Group findings by source IP
        ip_groups: DefaultDict[str, List[ThreatFinding]] = defaultdict(list)
        for f in findings:
            ip_groups[f.source_ip].append(f)

        for ip, ip_findings in ip_groups.items():
            threat_types = set(f.threat_type for f in ip_findings)
            
            # Pattern 1: Brute Force leading to Injection
            if "BRUTE_FORCE" in threat_types and ("SQL_INJECTION" in threat_types or "XSS_ATTACK" in threat_types):
                correlated_events.append({
                    "attack": "ADVANCED_PERSISTENT_THREAT",
                    "severity": "CRITICAL",
                    "source": ip,
                    "description": f"IP {ip} exhibited brute force followed by application-layer injection attempts."
                })
            
            # Pattern 2: Reconnaissance followed by Exploitation
            elif "NETWORK_RECON" in threat_types and ("BRUTE_FORCE" in threat_types or "SQL_INJECTION" in threat_types):
                correlated_events.append({
                    "attack": "TARGETED_ATTACK_CAMPAIGN",
                    "severity": "HIGH",
                    "source": ip,
                    "description": f"IP {ip} performed network reconnaissance followed by targeted exploitation."
                })

            # Pass through individual high-severity findings if not correlated
            else:
                for f in ip_findings:
                    if f.severity in ["HIGH", "CRITICAL"]:
                        correlated_events.append({
                            "attack": f.threat_type,
                            "severity": f.severity,
                            "source": ip,
                            "description": f.description
                        })

        return correlated_events