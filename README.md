# CyberGuard AI: Next-Gen Multi-Agent Cyber Threat Intelligence System

CyberGuard AI is a sophisticated multi-agent system designed for real-time cybersecurity threat detection, correlation, and response recommendation. It leverages Large Language Models (LLMs) to analyze logs and suggest strategic mitigation protocols.

## 🚀 Features

- **Multi-Agent Architecture**: Specialized agents for log analysis, correlation, and reasoning.
- **Real-Time Dashboard**: Interactive web interface for monitoring threats and system status.
- **LLM-Powered Reasoning**: Integration with Google Gemini for intelligent incident response recommendations.
- **Automated Log Generation**: Built-in background task for simulating and testing threat scenarios.

## 🛠️ Technology Stack

- **Backend**: FastAPI (Python)
- **Frontend**: HTML5, Vanilla CSS, Chart.js
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

Access the dashboard at: [http://127.0.0.1:8000/dashboard](http://127.0.0.1:8000/dashboard)

## 📁 Project Structure

```text
├── agents/             # Multi-agent implementations
│   ├── log_analyzer/
│   ├── correlation/
│   └── llm_reasoner/
├── api/                # FastAPI backend & Frontend templates/static
├── .env                # Environment variables (secret)
├── run.py              # Application entry point
└── requirements.txt    # Project dependencies
```

## 🛡️ License

MIT License
