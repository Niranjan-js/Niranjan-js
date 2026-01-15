"""
Log Ingestors Package

Provides real-world log ingestion from various sources:
- Windows Event Viewer
- Web Server Logs (Apache/Nginx)
- Network Traffic Capture
"""

from .windows_events_real import WindowsEventIngestor
from .web_server_logs import WebServerLogParser
from .network_capture import NetworkCapture

__all__ = ['WindowsEventIngestor', 'WebServerLogParser', 'NetworkCapture']
