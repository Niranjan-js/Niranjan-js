import asyncio

from agents.log_analyzer.agent import LogAnalysisAgent
from agents.correlation.agent import CorrelationAgent
from agents.llm_reasoner.agent import LLMReasoningAgent


async def main():
    # 1. Raw logs
    sample_logs = """
    2026-01-04 12:00:01 [AUTH] Failed password for admin from 192.168.1.10
    2026-01-04 12:00:05 [WAF] SQL Injection Attempt: "SELECT * FROM users OR 1=1" from 192.168.1.10
    2026-01-04 12:00:10 [FIREWALL] Port scan detected from 10.0.0.5
    2026-01-04 12:00:15 [SYSTEM] Normal activity
    """

    # 2. Initialize agents
    log_agent = LogAnalysisAgent()
    correlation_agent = CorrelationAgent()
    llm_agent = LLMReasoningAgent()

    # 3. Step 1: Log analysis
    findings = await log_agent.analyze(sample_logs)

    print("\n--- Individual Findings ---")
    for f in findings:
        print(f)

    # 4. Step 2: Correlation (Synchronous)
    correlated = correlation_agent.correlate(findings)

    print("\n--- Correlated Attacks ---")
    for c in correlated:
        print(c)

    # 5. Step 3: LLM reasoning
    decisions = await llm_agent.reason(correlated)

    print("\n--- LLM Decisions ---")
    for d in decisions:
        print(d)


if __name__ == "__main__":
    asyncio.run(main())