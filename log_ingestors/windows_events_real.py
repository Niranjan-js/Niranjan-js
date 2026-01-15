"""
Windows Event Viewer Log Ingestor

Monitors Windows Security Event Log for authentication and security events.
Converts events to standardized format for threat detection.
"""

import win32evtlog
import win32evtlogutil
import win32con
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Dict, Optional
import threading
import time


class WindowsEventIngestor:
    """Monitor Windows Event Viewer for security events"""
    
    # Event IDs to monitor
    EVENT_IDS = {
        4625: "Failed Login Attempt",
        4624: "Successful Login",
        4720: "User Account Created",
        4732: "User Added to Security Group",
        4688: "Process Created",
        4672: "Special Privileges Assigned",
        4648: "Login with Explicit Credentials",
        4634: "Account Logged Off"
    }
    
    def __init__(self, callback=None):
        """
        Initialize Windows Event Ingestor
        
        Args:
            callback: Function to call with normalized log data
        """
        self.callback = callback
        self.running = False
        self.thread = None
        self.server = 'localhost'
        self.logtype = 'Security'
        self.hand = None
        self.flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
    def start(self):
        """Start monitoring Windows Event Log"""
        if self.running:
            print("[WindowsEventIngestor] Already running")
            return
            
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        print(f"[WindowsEventIngestor] Started monitoring {self.logtype} event log")
        
    def stop(self):
        """Stop monitoring"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
        if self.hand:
            win32evtlog.CloseEventLog(self.hand)
        print("[WindowsEventIngestor] Stopped")
        
    def _monitor_loop(self):
        """Main monitoring loop"""
        try:
            self.hand = win32evtlog.OpenEventLog(self.server, self.logtype)
            last_record = win32evtlog.GetNumberOfEventLogRecords(self.hand)
            
            while self.running:
                # Read new events
                events = win32evtlog.ReadEventLog(
                    self.hand,
                    self.flags,
                    0
                )
                
                if events:
                    for event in events:
                        # Only process events we care about
                        if event.EventID in self.EVENT_IDS:
                            normalized = self._normalize_event(event)
                            if normalized and self.callback:
                                self.callback(normalized)
                
                # Sleep to avoid excessive CPU usage
                time.sleep(2)
                
        except Exception as e:
            print(f"[WindowsEventIngestor] Error: {e}")
        finally:
            if self.hand:
                win32evtlog.CloseEventLog(self.hand)
                
    def _normalize_event(self, event) -> Optional[Dict]:
        """
        Normalize Windows event to standard format
        
        Args:
            event: Windows event object
            
        Returns:
            Normalized event dict or None
        """
        try:
            event_id = event.EventID
            event_type = self.EVENT_IDS.get(event_id, "Unknown Event")
            
            # Extract event data
            strings = event.StringInserts or []
            
            # Parse based on event ID
            source_ip = "Unknown"
            username = "Unknown"
            severity = "INFO"
            
            if event_id == 4625:  # Failed Login
                severity = "HIGH"
                if len(strings) >= 19:
                    username = strings[5] if strings[5] else "Unknown"
                    source_ip = strings[19] if strings[19] else "Unknown"
                    
            elif event_id == 4624:  # Successful Login
                severity = "INFO"
                if len(strings) >= 18:
                    username = strings[5] if strings[5] else "Unknown"
                    source_ip = strings[18] if strings[18] else "Unknown"
                    
            elif event_id == 4720:  # Account Created
                severity = "MEDIUM"
                if len(strings) >= 1:
                    username = strings[0] if strings[0] else "Unknown"
                    
            elif event_id == 4732:  # User Added to Group
                severity = "MEDIUM"
                if len(strings) >= 2:
                    username = strings[0] if strings[0] else "Unknown"
                    
            elif event_id == 4688:  # Process Created
                severity = "LOW"
                if len(strings) >= 5:
                    username = strings[1] if strings[1] else "Unknown"
            
            # Create normalized log entry
            normalized = {
                "timestamp": datetime.now().isoformat(),
                "source": "windows_event_log",
                "event_id": str(event_id),
                "event_type": event_type,
                "severity": severity,
                "source_ip": source_ip,
                "username": username,
                "message": f"{event_type}: User={username}, IP={source_ip}",
                "raw_data": {
                    "computer": event.ComputerName,
                    "record_number": event.RecordNumber,
                    "strings": strings[:10]  # Limit for size
                }
            }
            
            return normalized
            
        except Exception as e:
            print(f"[WindowsEventIngestor] Error normalizing event: {e}")
            return None
            
    def get_recent_events(self, count=10) -> List[Dict]:
        """
        Get recent security events
        
        Args:
            count: Number of events to retrieve
            
        Returns:
            List of normalized events
        """
        events = []
        try:
            hand = win32evtlog.OpenEventLog(self.server, self.logtype)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            raw_events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            for event in raw_events[:count]:
                if event.EventID in self.EVENT_IDS:
                    normalized = self._normalize_event(event)
                    if normalized:
                        events.append(normalized)
                        
            win32evtlog.CloseEventLog(hand)
            
        except Exception as e:
            print(f"[WindowsEventIngestor] Error getting recent events: {e}")
            
        return events


# Test function
if __name__ == "__main__":
    def print_event(event):
        print(f"\n[EVENT] {event['event_type']}")
        print(f"  Severity: {event['severity']}")
        print(f"  User: {event['username']}")
        print(f"  IP: {event['source_ip']}")
        print(f"  Message: {event['message']}")
    
    print("Testing Windows Event Ingestor...")
    print("Note: Requires Administrator privileges!")
    print("\nRecent events:")
    
    ingestor = WindowsEventIngestor(callback=print_event)
    
    # Get recent events
    recent = ingestor.get_recent_events(5)
    for event in recent:
        print_event(event)
    
    # Start monitoring
    print("\n\nStarting live monitoring (Ctrl+C to stop)...")
    ingestor.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
        ingestor.stop()
