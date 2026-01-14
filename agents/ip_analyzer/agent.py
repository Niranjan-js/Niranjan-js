import os
import json
import asyncio
from typing import List, Dict, Optional
import google.generativeai as genai
from agents.base_agent import BaseAgent
from agents.types import ThreatFinding

class IPRangeAnalyzerAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="IPRangeAnalyzerAgent")
        api_key = os.getenv("GOOGLE_API_KEY")
        if api_key and api_key != "your_api_key_here":
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel('gemini-1.5-flash')
            self.has_api_key = True
        else:
            self.has_api_key = False

    async def analyze(self, ip_data: str) -> List[ThreatFinding]:
        """
        Processes IP scan data (e.g., Nmap output) or individual IP addresses.
        """
        findings = []
        
        # In a real implementation, we would parse Nmap XML here.
        # For now, we simulate the 'technical layer' processing basic text input.
        
        if self.has_api_key:
            semantic_findings = await self._vuln_analyze(ip_data)
            findings.extend(semantic_findings)
        else:
            # Fallback mock finding
            findings.append(ThreatFinding(
                agent_name=self.name,
                threat_type="EXPOSED_SERVICE",
                description="Potential exposed service detected on scanned target",
                severity="MEDIUM",
                source_ip="Detected IP"
            ))
        
        return findings

    async def _vuln_analyze(self, scan_data: str) -> List[ThreatFinding]:
        prompt = f"""
        Role: Network Vulnerability Researcher
        Task: Analyze the following network scan results (e.g., open ports, services) and identify critical exposures or CVE-related risks.
        
        Scan Data:
        \"\"\"{scan_data}\"\"\"
        
        Requirement:
        Return a JSON list of findings. Each finding must follow this schema:
        - "threat_type": e.g., "VULNERABLE_SERVICE", "UNSECURE_PROTOCOL", "POTENTIAL_CVE".
        - "description": Explain the risk of this open port/service.
        - "severity": "CRITICAL", "HIGH", "MEDIUM", or "LOW".
        - "source_ip": The IP address analyzed.
        - "metadata": Any identified CVE numbers or service versions.
        
        Return ONLY the raw JSON array.
        """
        
        try:
            response = await asyncio.to_thread(self.model.generate_content, prompt)
            text = response.text.strip()
            if text.startswith("```json"): text = text[7:-3].strip()
            elif text.startswith("```"): text = text[3:-3].strip()
            
            raw_findings = json.loads(text)
            return [ThreatFinding(agent_name=self.name, **f) for f in raw_findings]
        except Exception as e:
            print(f"Error in IP Vulnerability Analysis: {e}")
            return []
