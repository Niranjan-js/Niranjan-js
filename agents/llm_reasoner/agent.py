import os
import json
import asyncio
from typing import List, Dict
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

class LLMReasoningAgent:
    def __init__(self):
        api_key = os.getenv("GOOGLE_API_KEY")
        if api_key and api_key != "your_api_key_here":
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel('gemini-1.5-flash')
            self.has_api_key = True
        else:
            self.has_api_key = False
            print("WARNING: Gemini API Key not found or invalid in .env. Falling back to mock reasoning.")

    async def reason(self, correlated_findings: List[Dict]) -> List[Dict]:
        if not correlated_findings:
            return []

        if not self.has_api_key:
            return self._mock_reason(correlated_findings)

        prompt = f"""
        Role: Senior Cyber Security Incident Responder (CSIR)
        Task: Analyze correlated attack patterns and provide strategic mitigation protocols.
        
        Input Data (Correlated Attacks):
        {json.dumps(correlated_findings, indent=2)}

        Requirement:
        Provide a JSON list of response objects. Each object must strictly follow this schema:
        - "decision": A professional response identifier (e.g., "NETWORK_SEGREGATION", "CREDENTIAL_INVALIDATION").
        - "severity": Must be one of ["CRITICAL", "HIGH", "MEDIUM", "LOW"].
        - "actions": A list of discrete, technical remediation steps.
        - "reason": A sophisticated justification based on the provided evidence.

        Output Constraint:
        Return ONLY the raw JSON array. DO NOT include markdown formatting, backticks, or any explanatory text outside the JSON.
        """

        try:
            # Run LLM call in a thread to avoid blocking if using older sync SDK, 
            # though gemini-1.5 supports async in newer versions.
            response = await asyncio.to_thread(self.model.generate_content, prompt)
            
            # Clean response text in case LLM added markdown backticks
            text = response.text.strip()
            if text.startswith("```json"):
                text = text[7:-3].strip()
            elif text.startswith("```"):
                text = text[3:-3].strip()
            
            return json.loads(text)
        except Exception as e:
            print(f"Error calling Gemini API: {e}. Falling back to mock.")
            return self._mock_reason(correlated_findings)

    def _mock_reason(self, correlated_findings: List[Dict]) -> List[Dict]:
        decisions = []
        for finding in correlated_findings:
            attack = finding.get("attack")
            if attack in ["ACCOUNT_COMPROMISE", "ADVANCED_PERSISTENT_THREAT"]:
                decisions.append({
                    "decision": "IMMEDIATE_LOCKDOWN",
                    "severity": "CRITICAL",
                    "actions": ["Disable affected account", "Force password reset", "Block attacker IP"],
                    "reason": "Correlated brute-force and high-risk injection attempts detected"
                })
            elif attack in ["DATABASE_ATTACK", "SQL_INJECTION"]:
                decisions.append({
                    "decision": "DATABASE_ISOLATION",
                    "severity": "CRITICAL",
                    "actions": ["Kill active DB sessions", "Reset database credentials", "Lock down database subnet"],
                    "reason": "High-severity SQL injection attempts detected"
                })
            else:
                decisions.append({
                    "decision": "PERIMETER_REINFORCEMENT",
                    "severity": "MEDIUM",
                    "actions": ["Update WAF rules", "Patch affected application components"],
                    "reason": f"Detected {attack} pattern requiring mitigation"
                })
        return decisions
