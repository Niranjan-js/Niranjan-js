import re
import os
import json
import asyncio
from typing import List, Dict, Optional
import google.generativeai as genai
from agents.base_agent import BaseAgent
from agents.types import ThreatFinding

class EmailVerificationAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="EmailVerificationAgent")
        api_key = os.getenv("GOOGLE_API_KEY")
        if api_key and api_key != "your_api_key_here":
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel('gemini-1.5-flash')
            self.has_api_key = True
        else:
            self.has_api_key = False
        
        self.url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')

    async def analyze(self, email_content: str) -> List[ThreatFinding]:
        findings = []
        
        # 1. Basic Heuristic Analysis
        urls = self.url_pattern.findall(email_content)
        
        # 2. LLM Semantic Analysis (Primary according to paper)
        if self.has_api_key:
            semantic_findings = await self._semantic_analyze(email_content, urls)
            findings.extend(semantic_findings)
        else:
            # Fallback to basic heuristics if no API key
            if any(p in email_content.lower() for p in ["urgent", "password reset", "verify your account", "suspicious activity"]):
                findings.append(ThreatFinding(
                    agent_name=self.name,
                    threat_type="PHISHING_ATTEMPT",
                    description="Email contains urgent language typical of phishing",
                    severity="MEDIUM",
                    metadata={"urls": urls}
                ))
        
        return findings

    async def _semantic_analyze(self, content: str, urls: List[str]) -> List[ThreatFinding]:
        prompt = f"""
        Role: Cybersecurity Email Analyst Agent
        Task: Analyze the following email content for threats like phishing, spoofing, and social engineering.
        
        Email Content:
        \"\"\"{content}\"\"\"
        
        Detected URLs: {urls}
        
        Requirement:
        Return a JSON list of findings. Each finding must follow this schema:
        - "threat_type": e.g., "PHISHING", "SPOOFING", "SOCIAL_ENGINEERING", "MALICIOUS_LINK".
        - "description": Detailed explanation of why this is a threat.
        - "severity": "CRITICAL", "HIGH", "MEDIUM", or "LOW".
        - "source_ip": If a sender IP is identifiable or "Unknown".
        - "metadata": Any additional context (e.g., specific suspicious phrases).
        
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
            print(f"Error in Email Semantic Analysis: {e}")
            return []
