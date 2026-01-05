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
            "llm_decisions": []
        }
        self.history = []
        self.max_history = 50

    def update(self, new_results: Dict[str, Any]):
        # Aggregate findings
        self.results["raw_findings"].extend(new_results.get("raw_findings", []))
        self.results["correlated_attacks"].extend(new_results.get("correlated_attacks", []))
        self.results["llm_decisions"].extend(new_results.get("llm_decisions", []))

        # Keep only latest for summary metrics if needed, but here we aggregate
        # Let's keep a sliding window for the last 100 raw findings to avoid bloat
        if len(self.results["raw_findings"]) > 100:
            self.results["raw_findings"] = self.results["raw_findings"][-100:]
        
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
    critical = severity_counter.get("CRITICAL", 0) + severity_counter.get("HIGH", 0)
    
    return {
        "total_threats": total,
        "active": total,
        "remediated": 0,
        "critical": critical,
        "by_severity": dict(severity_counter),
        "by_type": dict(type_counter),
        "decisions": decisions,
        "raw_count": len(raw_findings)
    }

@router.post("/dashboard/update-results")
async def update_results(analysis_result: Dict[str, Any]):
    """
    Update the latest results for the dashboard
    """
    state.update(analysis_result)
    return {"status": "updated"}