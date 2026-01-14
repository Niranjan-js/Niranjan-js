import random
import asyncio
import httpx
from datetime import datetime

LOG_SAMPLES = [
    '{timestamp} [AUTH] pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}  user=admin',
    '{timestamp} [FIREWALL] SRC={ip} DST=10.0.0.1 PROTO=TCP SPT=12345 DPT=443 FLAGS=S',
    '{timestamp} [WAF] SQL Injection Attempt: "SELECT * FROM users WHERE id=1 OR 1=1" from {ip}',
    '{timestamp} [SYSTEM] Connection established from {ip} to port 22',
    '{timestamp} [IDS] Potential Brute Force: 10 failed logins in 5s from {ip}',
    '{timestamp} [WAF] XSS Attempt: "<script>alert(1)</script>" blocked from {ip}',
    '{timestamp} [FIREWALL] Port scan detected from {ip}: 50 ports probed in 2s',
    '{timestamp} [SYSTEM] Service sshd restarted by user root',
    '{timestamp} [DATA] Sensitive file access: /etc/shadow by unauthorized user from {ip}',
    '{timestamp} [NETWORK] Large outbound data transfer detected (1.2GB) to {ip}',
    '{timestamp} [WAF] Path Traversal Attempt: ../../../etc/passwd from {ip}',
    '{timestamp} [IDS] Tor Exit Node connection detected from {ip}',
    '{timestamp} [SYSCALL] Unexpected process execution: /tmp/reverse_shell from {ip}'
]

import os

# Use environment variable PORT or default to 8081
PORT = os.getenv("PORT", "8081")
API_URL = f"http://127.0.0.1:{PORT}/analyze/logs"

# Global control for automation
is_automation_on = True
log_speed = 5 # seconds

async def generate_logs():
    # Wait for the FastAPI server to start
    print("DEBUG: Log generator waiting 5s for server startup...")
    await asyncio.sleep(5)
    
    async with httpx.AsyncClient() as client:
        while True:
            if not is_automation_on:
                await asyncio.sleep(1)
                continue

            ips = ["192.168.1.10", "10.0.0.5", "172.16.0.8", "192.168.1.50", "45.33.22.11", "8.8.8.8"]
            
            logs = []
            num_logs = random.randint(1, 3)
            for _ in range(num_logs):
                raw_log = random.choice(LOG_SAMPLES)
                log = raw_log.format(
                    timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    ip=random.choice(ips)
                )
                logs.append(log)

            payload = {"logs": logs, "source": "Edge Network Monitor"}

            try:
                response = await client.post(API_URL, json=payload, timeout=5.0)
                if response.status_code == 200:
                    print(f"Auto logs sent (speed: {log_speed}s):", logs)
                else:
                    print(f"Warning: Server returned status {response.status_code} for logs")
            except httpx.ConnectError:
                print("Log generator: Server not reachable yet, retrying...")
            except Exception as e:
                print(f"Error sending logs: {type(e).__name__}: {e}")

            await asyncio.sleep(log_speed)
