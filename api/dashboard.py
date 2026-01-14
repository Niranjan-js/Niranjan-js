from fastapi import APIRouter
from typing import Dict, Any, List
from collections import Counter

router = APIRouter()

# Shared state to hold latest results
class DashboardState:
    def __init__(self):
        self.results = {
            "raw_findings": [],
            "correlated_attacks": [],
            "llm_decisions": [],
            "remediated_ids": [],
            "mitre_tactics": {
                "Initial Access": 0,
                "Execution": 0,
                "Persistence": 0,
                "Privilege Escalation": 0,
                "Defense Evasion": 0,
                "Credential Access": 0,
                "Discovery": 0,
                "Lateral Movement": 0,
                "Collection": 0,
                "Exfiltration": 0,
                "Command and Control": 0
            },
            "history_stats": {
                "times": [],
                "threat_counts": [],
                "remediation_counts": []
            },
            "entity_counts": {
                "Resources": 681,
                "Identities": 100,
                "Machine": 150,
                "Roles": 280
            }
        }
        self.history = []
        self.max_history = 100

    def update(self, new_results: Dict[str, Any]):
        # Aggregate findings
        self.results["raw_findings"].extend(new_results.get("raw_findings", []))
        correlated = new_results.get("correlated_attacks", [])
        self.results["correlated_attacks"].extend(correlated)
        self.results["llm_decisions"].extend(new_results.get("llm_decisions", []))

        # Update MITRE tactics based on attack types
        for attack in correlated:
            name = attack.get("attack", "")
            if "BRUTE_FORCE" in name or "CREDENTIAL" in name:
                self.results["mitre_tactics"]["Credential Access"] += 1
            elif "INJECTION" in name or "XSS" in name:
                self.results["mitre_tactics"]["Execution"] += 1
            elif "RECON" in name or "SCAN" in name:
                self.results["mitre_tactics"]["Discovery"] += 1
            elif "EXFIL" in name:
                self.results["mitre_tactics"]["Exfiltration"] += 1

        # Update history for trend charts
        import datetime
        now = datetime.datetime.now().strftime("%H:%M")
        self.results["history_stats"]["times"].append(now)
        self.results["history_stats"]["threat_counts"].append(len(self.results["correlated_attacks"]))
        self.results["history_stats"]["remediation_counts"].append(len(self.results["remediated_ids"]))

        # Limit history
        if len(self.results["history_stats"]["times"]) > 20:
            for k in self.results["history_stats"]:
                self.results["history_stats"][k] = self.results["history_stats"][k][-20:]

        if len(self.results["raw_findings"]) > 500:
            self.results["raw_findings"] = self.results["raw_findings"][-500:]
        
        # Add to history
        self.history.append(new_results)
        if len(self.history) > self.max_history:
            self.history.pop(0)

state = DashboardState()

@router.get("/dashboard/summary")
async def dashboard_summary():
    """
    Returns dashboard metrics from the latest analysis
    """
    correlated = state.results.get("correlated_attacks", [])
    decisions = state.results.get("llm_decisions", [])
    raw_findings = state.results.get("raw_findings", [])

    severity_counter = Counter()
    type_counter = Counter()
    
    for attack in correlated:
        severity = attack.get("severity", "MEDIUM")
        severity_counter[severity] += 1
        type_counter[attack.get("attack", "OTHER")] += 1

    total = len(correlated)
    remediated_count = len(state.results.get("remediated_ids", []))
    critical = severity_counter.get("CRITICAL", 0) + severity_counter.get("HIGH", 0)
    
    # Simple Security Pulse calculation (1-100)
    # Starts at 100, drops by 5 for high, 10 for critical, up to 10 for regular threats
    pulse = max(10, 100 - (critical * 15) - (total * 2) + (remediated_count * 5))
    pulse = min(100, pulse)

    return {
        "total_threats": total,
        "active": total - remediated_count,
        "remediated": remediated_count,
        "critical": critical,
        "pulse": int(pulse),
        "by_severity": dict(severity_counter),
        "by_type": dict(type_counter),
        "decisions": decisions,
        "raw_count": len(raw_findings),
        "mitre_tactics": state.results["mitre_tactics"],
        "history": state.results["history_stats"],
        "entities": state.results["entity_counts"]
    }

@router.post("/dashboard/update-results")
async def update_results(analysis_result: Dict[str, Any]):
    """
    Update the latest results for the dashboard
    """
    state.update(analysis_result)
    return {"status": "updated"}

@router.post("/dashboard/remediate")
async def remediate_threat(request: Dict[str, str]):
    """
    Mark a threat as remediated
    """
    threat_id = request.get("threat_id")
    if threat_id and threat_id not in state.results["remediated_ids"]:
        state.results["remediated_ids"].append(threat_id)
        return {"status": "success", "message": f"Threat {threat_id} remediated"}
    return {"status": "error", "message": "Invalid threat ID or already remediated"}