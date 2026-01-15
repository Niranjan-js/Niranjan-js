"""
Test Log Injector - Adds new logs to access.log to test real-time detection
Run this script to simulate live web server activity with various attack types
"""
import time
import random
from datetime import datetime

# Sample log entries
ATTACK_LOGS = [
    '192.168.1.{} - - [{}] "GET /login.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 200 890',
    '10.0.0.{} - - [{}] "GET /search.php?q=<script>alert(1)</script> HTTP/1.1" 200 456',
    '172.16.0.{} - - [{}] "GET /files?file=../../../../etc/passwd HTTP/1.1" 403 234',
    '45.33.22.{} - - [{}] "GET /admin/ HTTP/1.1" 404 192 "-" "Nikto/2.1.6"',
    '66.249.64.{} - - [{}] "GET /download?id=1 UNION SELECT password FROM users-- HTTP/1.1" 200 567',
]

NORMAL_LOGS = [
    '192.168.1.{} - - [{}] "GET /index.html HTTP/1.1" 200 1234',
    '192.168.1.{} - - [{}] "GET /about.html HTTP/1.1" 200 567',
    '192.168.1.{} - - [{}] "POST /contact.php HTTP/1.1" 200 89',
]

def generate_log():
    """Generate a random log entry"""
    ip_suffix = random.randint(1, 254)
    timestamp = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0530")
    
    # 30% chance of attack log, 70% normal
    if random.random() < 0.3:
        log_template = random.choice(ATTACK_LOGS)
    else:
        log_template = random.choice(NORMAL_LOGS)
    
    return log_template.format(ip_suffix, timestamp)

def main():
    log_file = r"C:\logs\access.log"
    print(f"🚀 Starting log injector...")
    print(f"📝 Writing to: {log_file}")
    print(f"⏱️  Interval: 3 seconds")
    print(f"🔴 Press Ctrl+C to stop\n")
    
    try:
        with open(log_file, "a") as f:
            while True:
                log = generate_log()
                f.write(log + "\n")
                f.flush()  # Force write to disk
                print(f"✅ Added: {log}")
                time.sleep(3)  # Wait 3 seconds between logs
    except KeyboardInterrupt:
        print("\n\n⏸️  Log injector stopped")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    main()
