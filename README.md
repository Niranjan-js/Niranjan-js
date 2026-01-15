# CyberGuard AI: Next-Gen Multi-Agent Cyber Threat Intelligence System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.6-009688.svg)](https://fastapi.tiangolo.com)

CyberGuard AI is a sophisticated multi-agent system designed for real-time cybersecurity threat detection, correlation, and response recommendation. It leverages Large Language Models (LLMs) and advanced visualization to analyze threats and suggest strategic mitigation protocols.

## 🚀 Features

### Core Capabilities
- **Multi-Agent Architecture**: Specialized agents for log analysis, correlation, and reasoning
- **Real-Time Dashboard**: Interactive web interface with WebSocket-powered instant updates
- **LLM-Powered Reasoning**: Integration with Google Gemini for intelligent incident response
- **Automated Log Generation**: Built-in background task for simulating and testing threat scenarios

### 🆕 Latest Enhancements (v2.0)
- **⚡ WebSocket Communication**: Instant threat updates with < 100ms latency (no polling!)
- **🔔 Advanced Notification System**: Toast notifications with sound alerts for critical threats
- **🌐 Enhanced 3D Network Map**: Real-time threat visualization on interactive globe
- **🎨 Premium UI/UX**: Glassmorphism effects, smooth animations, responsive design
- **📱 Mobile Responsive**: Optimized for desktop, tablet, and mobile devices
- **🎯 Real-Time Threat Markers**: Animated, color-coded threat indicators on 3D map

## 🛠️ Technology Stack

- **Backend**: FastAPI (Python)
- **Frontend**: HTML5, Vanilla CSS, JavaScript
- **Visualization**: Chart.js, Three.js, D3.js
- **Real-Time**: WebSocket
- **Intelligence**: Google Gemini (via `google-generativeai`)
- **Server**: Uvicorn

## 📋 Prerequisites

- Python 3.10+
- Google Gemini API Key (set in `.env`)

## ⚙️ Installation & Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Niranjan-js/niran.git
   cd niran
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**:
   Create a `.env` file in the root directory and add your Gemini API key:
   ```env
   GOOGLE_API_KEY=your_actual_api_key_here
   ```

## 🏃 Running the Application

Start the system using the provided runner:

```bash
python run.py
```

Access the dashboard at: **http://127.0.0.1:8081/dashboard**

## 🔴 Live Log Ingestion

CyberGuard AI supports **real-time threat detection** from live log sources, replacing manual log injection with automated monitoring:

### Supported Log Sources

1. **Windows Event Viewer** 🪟
   - Monitors Security Event Log in real-time
   - Detects: Failed logins, privilege escalation, suspicious processes
   - Requires: **Administrator privileges**

2. **Web Server Logs** 🌐 (Apache / Nginx)
   - Parses access logs for web attacks
   - Detects: SQL injection, XSS, path traversal, scanner activity
   - Requires: Log file path configuration

3. **Network Traffic Capture** 📡 (Scapy)
   - Captures and analyzes packet metadata
   - Detects: Port scans, SYN floods, unusual traffic patterns
   - Requires: **Administrator privileges**

### Enable Live Log Sources

1. Navigate to **Settings** module in dashboard
2. Find **Live Log Ingestion Sources** section
3. Toggle switches to enable/disable sources
4. Configure paths/interfaces as needed
5. Monitor real-time statistics

### Testing

See comprehensive guides:
- **[TESTING_GUIDE.md](TESTING_GUIDE.md)** - Step-by-step testing procedures
- **[LAB_ATTACK_SCENARIOS.md](LAB_ATTACK_SCENARIOS.md)** - Safe attack testing (lab only)



## 📁 Project Structure

```text
├── agents/                 # Multi-agent implementations
│   ├── log_analyzer/      # Log analysis agent
│   ├── correlation/       # Attack correlation agent
│   ├── llm_reasoner/      # LLM-powered reasoning
│   ├── email_verification/# Email threat detection
│   └── ip_analyzer/       # IP range analysis
├── api/                   # FastAPI backend & Frontend
│   ├── main.py           # Main application
│   ├── dashboard.py      # Dashboard routes & state
│   ├── websocket_manager.py  # WebSocket connection manager
│   ├── auto_logs.py      # Automated log generation
│   ├── static/           # CSS & JavaScript
│   │   ├── style.css     # Enhanced styling with glassmorphism
│   │   ├── dashboard.js  # Real-time dashboard logic
│   │   └── notification_system.js  # Toast notifications
│   └── templates/        # HTML templates
│       └── index.html    # Main dashboard
├── .env                  # Environment variables (secret)
├── run.py                # Application entry point
└── requirements.txt      # Project dependencies
```

## 🎯 Dashboard Modules

### 📊 Overview
- Real-time threat statistics and entity counts
- Severity distribution charts
- Threat trend analysis
- MITRE ATT&CK tactic mapping
- Alert funnel visualization

### 🛡️ Threat Matrix
- Comprehensive threat table with all detections
- Source IPs, attack types, and agent information
- One-click remediation

### 🔍 Investigation
- Interactive D3.js graph showing threat relationships
- Drag-and-drop node exploration
- Entity relationship visualization

### 🌐 Network Map (Enhanced!)
- 3D rotating globe with real-time threat markers
- Color-coded severity indicators:
  - 🔴 Red = CRITICAL
  - 🟠 Orange = HIGH
  - 🔵 Cyan = MEDIUM/LOW
- Pulsing animations for active threats
- Auto-fade after 10 seconds

### ☁️ Cloud Security
- AWS, Azure, GCP integration status
- Automated remediation logs
- Cloud assistance monitoring

### ⚖️ Compliance
- SOC2 Type II, ISO 27001, GDPR tracking
- Compliance percentage metrics

### ⚙️ Settings
- Agent configuration
- LLM sensitivity adjustment
- Scan interval settings
- Auto-remediation toggle

## 🔔 Notification System

Real-time toast notifications appear in the top-right corner:

| Type | Icon | Color | Sound | Use Case |
|------|------|-------|-------|----------|
| Success | ✅ | Green | No | Connection established, remediation complete |
| Info | ℹ️ | Cyan | No | General updates, medium threats |
| Warning | ⚠️ | Orange | No | High severity threats |
| Critical | 🚨 | Red | **Yes** | Critical threats, system alerts |
| Error | ❌ | Red | No | System errors |

## 🎨 UI/UX Features

- **Glassmorphism Effects**: Semi-transparent cards with backdrop blur
- **Smooth Animations**: Slide-in notifications, pulsing markers, floating elements
- **Custom Scrollbars**: Themed to match dashboard colors
- **Responsive Design**: Optimized for all screen sizes
- **Dark Theme**: Professional dark color scheme
- **Hover Effects**: Interactive feedback on all elements

## 🔧 API Endpoints

### Analysis Endpoints
- `POST /analyze/logs` - Analyze log entries
- `POST /analyze/email` - Verify email for phishing
- `POST /analyze/ip` - Analyze network scan data
- `POST /analyze/upload` - Upload and analyze files

### Dashboard Endpoints
- `GET /dashboard/summary` - Get dashboard metrics
- `POST /dashboard/remediate` - Mark threat as remediated

### WebSocket
- `WS /ws` - Real-time threat updates

## 🛡️ Threat Detection

The system detects various attack types:

- **Authentication Attacks**: Brute force, failed logins, credential stuffing
- **Injection Attacks**: SQL injection, command injection, XSS
- **Reconnaissance**: Port scanning, network mapping, service enumeration
- **Data Threats**: Exfiltration attempts, unauthorized file access
- **Tool Detection**: SQLMap, Nikto, Metasploit, automated scanners

## 🚀 Performance

- **Page Load**: < 2 seconds
- **WebSocket Latency**: < 100ms
- **Animation FPS**: 60fps maintained
- **Memory Usage**: Stable with automatic cleanup

## 📚 Documentation

- **User Guide**: Comprehensive guide for using all features
- **Implementation Plan**: Technical architecture and design decisions
- **Walkthrough**: Feature demonstrations and testing results

## 🔄 Real-Time Features

### WebSocket Connection
- Persistent connection for instant updates
- Automatic reconnection with exponential backoff
- Fallback to polling if WebSocket fails
- Connection status indicator

### Live Updates
- Threats appear instantly (< 100ms)
- Dashboard updates without page refresh
- Real-time charts and statistics
- Animated threat markers on 3D map

## 🎓 Getting Started

1. **Start the server**: `python run.py`
2. **Open dashboard**: http://127.0.0.1:8081/dashboard
3. **Watch for connection**: Green notification confirms WebSocket
4. **Observe threats**: Automated threats appear every 5 seconds
5. **Explore modules**: Click sidebar to navigate
6. **Try 3D map**: Click "Network Map" to see threat visualization

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

MIT License - see LICENSE file for details

## 🙏 Acknowledgments

- FastAPI for the excellent web framework
- Three.js for 3D visualization
- D3.js for interactive graphs
- Chart.js for beautiful charts
- Google Gemini for AI-powered reasoning

## 📞 Support

For issues, questions, or contributions, please open an issue on GitHub.

---

**Built with ❤️ for the cybersecurity community**
