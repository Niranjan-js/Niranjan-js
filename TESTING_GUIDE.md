# CyberGuard AI - Testing Guide

## Overview

This guide provides step-by-step instructions for testing the live log ingestion features of CyberGuard AI, including Windows Event Viewer monitoring, Web Server Log parsing, and Network Traffic Capture.

## Prerequisites

### System Requirements
- **Operating System**: Windows 10/11 (for Windows Event Ingestor) or Linux
- **Python**: 3.10 or higher
- **Administrator/Root Privileges**: Required for Windows Events and Network Capture
- **Dependencies**: All packages from `requirements.txt` installed

### Verify Installation
```powershell
# Check Python version
python --version

# Verify dependencies
pip list | Select-String "pywin32|scapy|watchdog"

# Test admin privileges (Windows)
net session
```

---

## Testing Windows Event Ingestor

### Purpose
Capture and analyze Windows Security Event Log for failed logins, privilege escalation, and suspicious processes.

### Setup

1. **Start CyberGuard AI**
   ```powershell
   python run.py
   ```

2. **Access Dashboard**
   - Open browser: `http://127.0.0.1:8081/dashboard`
   - Navigate to **Settings** module
   - Find **Live Log Ingestion Sources** section

3. **Enable Windows Event Viewer**
   - Toggle ON the **Windows Event Viewer** switch
   - Status should change to "Active" (green)
   - Check for notification: "✅ Windows Event Viewer activated"

### Testing Methods

#### Method 1: Trigger Failed Login
1. Open Windows login screen or Remote Desktop
2. Attempt login with incorrect password (3-5 times)
3. Return to dashboard
4. **Expected Result**:
   - New threat appears within 5 seconds
   - Threat type: "Failed Login Attempt" or "Brute Force"
   - Source IP: Your machine's IP or localhost
   - Severity: HIGH or CRITICAL
   - Sound alert for critical threat

#### Method 2: Create New User Account
```powershell
# Run as Administrator
net user testuser TestPass123! /add
```
- **Expected**: Event logged as "User Account Created" (MEDIUM severity)

#### Method 3: View Recent Events
- Check Settings panel for event statistics
- Events count should increment in real-time

### Troubleshooting

| Issue | Solution |
|-------|----------|
| "Access Denied" | Run PowerShell as Administrator |
| No events detected | Check Event Viewer (eventvwr.msc) has events |
| Toggle doesn't work | Check console for pywin32 errors |

---

## Testing Web Server Log Parser

### Purpose
Parse Apache/Nginx logs for SQL injection, XSS, path traversal, and scanner activity.

### Setup

#### Option 1: Use Existing Web Server
1. Locate your web server log file:
   - Apache: `C:\Apache24\logs\access.log` or `/var/log/apache2/access.log`
   - Nginx: `C:\nginx\logs\access.log` or `/var/log/nginx/access.log`

2. **Configure Log Path** in Dashboard:
   - Settings → Web Server Logs
   - Enter full path to log file
   - Click "Set Path"
   - Toggle ON

#### Option 2: Generate Test Logs
Create a test log file with sample threats:

```bash
# test_access.log
192.168.1.100 - - [15/Jan/2026:12:00:00 +0530] "GET /index.php?id=1' OR '1'='1 HTTP/1.1" 200 1234
10.0.0.5 - - [15/Jan/2026:12:00:01 +0530] "GET /admin.php HTTP/1.1" 403 567
172.16.0.8 - - [15/Jan/2026:12:00:02 +0530] "GET /test.php?file=../../etc/passwd HTTP/1.1" 200 890 "-" "Nikto/2.1.6"
192.168.1.50 - - [15/Jan/2026:12:00:03 +0530] "GET /search.php?q=<script>alert(1)</script> HTTP/1.1" 200 456
```

### Testing Methods

#### Method 1: SQL Injection Detection
Send request with SQL injection payload:
```bash
curl "http://localhost/test.php?id=1'%20OR%20'1'='1"
```
- **Expected**: Detection of SQL_INJECTION (CRITICAL)

#### Method 2: XSS Detection
```bash
curl "http://localhost/search?q=<script>alert(1)</script>"
```
- **Expected**: Detection of XSS (HIGH)

#### Method 3: Scanner Detection
Use Nikto or similar tool:
```bash
nikto -h http://localhost
```
- **Expected**: SCANNER_DETECTED (MEDIUM)

#### Method 4: Watch Live Logs
```powershell
# Append to active log file
echo '192.168.1.100 - - [15/Jan/2026:12:00:00 +0530] "GET /admin.php?id=1 UNION SELECT * FROM users-- HTTP/1.1" 200 1234' >> C:\Apache24\logs\access.log
```

---

## Testing Network Traffic Capture

### Purpose
Capture and analyze network packets for port scans, SYN floods, and unusual traffic patterns.

### Setup

1. **Run as Administrator**
   ```powershell
   # Right-click PowerShell → Run as Administrator
   python run.py
   ```

2. **Enable Network Capture**
   - Settings → Network Traffic Capture
   - Optionally specify network interface (e.g., `eth0`, `Ethernet`)
   - Toggle ON
   - Status: "Active"

### Testing Methods

#### Method 1: Port Scan Detection
Use nmap to scan your own machine:
```bash
# Install nmap first
nmap -sS -p 1-100 localhost
```
- **Expected**: PORT_SCAN detection (HIGH) after ~10 ports scanned

#### Method 2: SYN Flood Detection (Simulated)
```bash
# Use hping3 or similar tool
hping3 -S localhost -p 80 --flood --rand-source
```
- **Expected**: SYN_FLOOD detection (CRITICAL) after 50 packets

#### Method 3: Normal Traffic Monitoring
- Browse websites, use applications
- Check dashboard statistics
- Packets captured should increment

### Advanced: Using Scapy Directly
```python
from scapy.all import *

# Send test SYN packets
send(IP(dst="127.0.0.1")/TCP(dport=80, flags="S"), count=100)
```

---

## End-to-End Pipeline Validation

### Complete Flow Test

1. **Enable All Sources**
   - Windows Events: ON
   - Web Server Logs: ON (with valid log path)
   - Network Capture: ON

2. **Trigger Multi-Source Threats**
   ```powershell
   # Failed login (Windows Events)
   # Attempt wrong password on login screen
   
   # SQL Injection (Web Server)
   curl "http://localhost/test.php?id=1' OR '1'='1"
   
   # Port Scan (Network)
   nmap -sS -p 1-50 localhost
   ```

3. **Verify Dashboard Updates**
   - **Overview**: Total threats increment
   - **Threat Matrix**: New entries appear
   - **3D Network Map**: Threat markers added
   - **Notifications**: Toast alerts for each threat
   - **Sound Alerts**: Critical threats trigger audio

4. **Check Correlation**
   - Multiple threats from same IP should be correlated
   - LLM Reasoner provides recommendations
   - Remediation suggestions appear

### Success Criteria
- ✅ All three log sources active simultaneously
- ✅ Threats detected < 5 seconds after trigger
- ✅ Dashboard updates in real-time (WebSocket)
- ✅ Notifications show correct severity
- ✅ Sound alerts for CRITICAL threats
- ✅ Statistics accurate (events, threats counts)
- ✅ No console errors or crashes

---

## Quick Reference

### Tested Event Types

#### Windows Events
- ✅ Failed Login (4625)
- ✅ Successful Login (4624)
- ✅ Account Created (4720)
- ✅ User Added to Group (4732)
- ✅ Process Created (4688)

#### Web Server Threats
- ✅ SQL Injection
- ✅ XSS (Cross-Site Scripting)
- ✅ Path Traversal
- ✅ Scanner Detection (Nikto, SQLMap, Nmap)
- ✅ Forbidden Access (403)
- ✅ Unauthorized Access (401)

#### Network Threats
- ✅ Port Scan (10+ ports/60s)
- ✅ SYN Flood (50+ packets/10s)
- ✅ Unusual Traffic Patterns

---

## Next Steps

After successful testing:
1. Deploy to production environment
2. Configure log rotation
3. Set up alerting rules
4. Train team on dashboard usage
5. Review LAB_ATTACK_SCENARIOS.md for safe attack testing
