import sys
import os
import asyncio
from typing import List, Optional
from fastapi import FastAPI, Request, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from api.auto_logs import generate_logs
from api.websocket_manager import manager as ws_manager

# Add the project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ===== Import Agents =====
from agents.log_analyzer.agent import LogAnalysisAgent
from agents.correlation.agent import CorrelationAgent
from agents.llm_reasoner.agent import LLMReasoningAgent
from agents.email_verification.agent import EmailVerificationAgent
from agents.ip_analyzer.agent import IPRangeAnalyzerAgent

# ===== Import Dashboard Router =====
from api.dashboard import router as dashboard_router

# ===== Import Log Ingestors =====
try:
    from log_ingestors import WindowsEventIngestor, WebServerLogParser, NetworkCapture
    LOG_INGESTORS_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Log ingestors not available: {e}")
    import traceback
    traceback.print_exc()
    LOG_INGESTORS_AVAILABLE = False

# ===== Initialize FastAPI App =====
app = FastAPI(title="CyberGuard AI: Multi-Agent Detection")

background_tasks = set()
main_loop = None

@app.on_event("startup")
async def start_auto_logs():
    global main_loop
    main_loop = asyncio.get_running_loop()
    task = asyncio.create_task(generate_logs())
    background_tasks.add(task)
    task.add_done_callback(background_tasks.discard)
    print("DEBUG: Background log generator task started")

# ===== Middleware =====
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== Serve Static Files =====
app.mount(
    "/static",
    StaticFiles(directory=os.path.join("api", "static")),
    name="static"
)

# ===== Templates =====
templates = Jinja2Templates(directory=os.path.join("api", "templates"))

# ===== Initialize Agents =====
log_analyzer = LogAnalysisAgent()
correlation_agent = CorrelationAgent()
llm_agent = LLMReasoningAgent()
email_agent = EmailVerificationAgent()
ip_agent = IPRangeAnalyzerAgent()

# ===== Initialize Log Ingestors =====
log_ingestors = {
    "windows_events": None,
    "web_server_logs": None,
    "network_capture": None
}

log_sources_enabled = {
    "windows_events": False,
    "web_server_logs": False,
    "network_capture": False
}

# Statistics for live log sources
log_source_stats = {
    "windows_events": {"events": 0, "threats": 0},
    "web_server_logs": {"events": 0, "threats": 0},
    "network_capture": {"events": 0, "threats": 0}
}

def handle_live_log(log_data: dict):
    """Handle incoming live log from ingestors (called from background threads)"""
    try:
        # Use the stored main event loop
        global main_loop
        if main_loop is None:
            print("ERROR: Main loop not initialized yet")
            return
            
        source = log_data.get("source", "live_ingestion")
        
        # Update event stats
        if source in log_source_stats:
            log_source_stats[source]["events"] += 1
            
        # Convert to log format and analyze
        log_text = log_data.get("message", "")
        
        # Run async analysis in the main loop
        future = asyncio.run_coroutine_threadsafe(log_analyzer.analyze(log_text), main_loop)
        findings = future.result(timeout=10)
        
        if findings:
            # Process through existing pipeline
            correlated = correlation_agent.correlate(findings)
            
            # Update threat stats
            if source in log_source_stats and correlated:
                log_source_stats[source]["threats"] += len(correlated)
            
            # Run async reasoning in the main loop
            reason_future = asyncio.run_coroutine_threadsafe(llm_agent.reason(correlated), main_loop)
            decisions = reason_future.result(timeout=10)
            
            # Update dashboard state
            from api.dashboard import state
            state.update({
                "raw_findings": [str(f) for f in findings],
                "correlated_attacks": correlated,
                "llm_decisions": decisions,
                "source": source
            })
            
            # Broadcast via WebSocket safely
            asyncio.run_coroutine_threadsafe(
                ws_manager.broadcast_threat_update({
                    "new_threats": correlated,
                    "source": source
                }),
                main_loop
            )
            
            # Send alert for critical threats
            for attack in correlated:
                if attack.get("severity") in ["CRITICAL", "HIGH"]:
                    asyncio.run_coroutine_threadsafe(
                        ws_manager.broadcast_alert(
                            "live_threat",
                            f"Live threat detected: {attack.get('attack', 'Unknown')} from {log_data.get('source_ip', 'unknown')}",
                            attack.get("severity", "HIGH")
                        ),
                        main_loop
                    )
        
        # Always broadcast log source stats update
        if source in log_source_stats:
            asyncio.run_coroutine_threadsafe(
                ws_manager.broadcast_log_source_update(source, log_source_stats[source]),
                main_loop
            )
            
    except Exception as e:
        print(f"Error handling live log: {e}")

# ===== Request Models =====
class LogRequest(BaseModel):
    logs: List[str]
    source: Optional[str] = "Manual Input"

class EmailRequest(BaseModel):
    content: str
    source: Optional[str] = "Manual Input"

class IPRequest(BaseModel):
    scan_data: str
    source: Optional[str] = "Network Scan"

# ===== Unified Processor =====
async def _process_all(findings: List, source: str):
    correlated = correlation_agent.correlate(findings)
    decisions = await llm_agent.reason(correlated)

    results = {
        "raw_findings": [str(f) for f in findings],
        "correlated_attacks": correlated,
        "llm_decisions": decisions,
        "source": source
    }

    # Automatically update dashboard state
    from api.dashboard import state
    state.update(results)
    
    # Broadcast real-time update via WebSocket
    await ws_manager.broadcast_threat_update({
        "total_threats": len(correlated),
        "new_threats": correlated,
        "decisions": decisions,
        "source": source
    })
    
    # Send alert for critical threats
    critical_threats = [t for t in correlated if t.get("severity") in ["CRITICAL", "HIGH"]]
    if critical_threats:
        await ws_manager.broadcast_alert(
            "critical_threat",
            f"{len(critical_threats)} critical threat(s) detected from {source}",
            "CRITICAL"
        )
    
    return results

# ===== Endpoints =====
@app.post("/analyze/logs")
async def analyze_logs(request: LogRequest):
    raw_logs_text = "\n".join(request.logs)
    findings = await log_analyzer.analyze(raw_logs_text)
    return await _process_all(findings, request.source)

@app.post("/analyze/email")
async def analyze_email(request: EmailRequest):
    findings = await email_agent.analyze(request.content)
    return await _process_all(findings, request.source)

@app.post("/analyze/ip")
async def analyze_ip(request: IPRequest):
    findings = await ip_agent.analyze(request.scan_data)
    return await _process_all(findings, request.source)

@app.post("/analyze/upload")
async def analyze_upload(file: UploadFile = File(...)):
    content = await file.read()
    text = content.decode("utf-8")
    
    if "email" in file.filename.lower() or "subject:" in text.lower():
        findings = await email_agent.analyze(text)
    elif "nmap" in text.lower() or "port" in text.lower():
        findings = await ip_agent.analyze(text)
    else:
        findings = await log_agent.analyze(text)
    
    return await _process_all(findings, f"Uploaded File: {file.filename}")

# ===== Register Dashboard Routes =====
app.include_router(dashboard_router)

# ===== Serve Dashboard Page =====
@app.get("/dashboard")
def dashboard(request: Request):
    import time
    version = int(time.time())
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "version": version}
    )

# ===== Log Source Management Endpoints =====
@app.get("/ingest/sources")
async def get_log_sources():
    """Get status of all log sources"""
    return {
        "available": LOG_INGESTORS_AVAILABLE,
        "sources": {
            "windows_events": {
                "enabled": log_sources_enabled["windows_events"],
                "description": "Windows Security Event Log",
                "requires_admin": True
            },
            "web_server_logs": {
                "enabled": log_sources_enabled["web_server_logs"],
                "description": "Apache/Nginx Web Server Logs",
                "requires_admin": False
            },
            "network_capture": {
                "enabled": log_sources_enabled["network_capture"],
                "description": "Network Traffic Capture",
                "requires_admin": True
            }
        }
    }

@app.post("/ingest/sources/{source_name}/toggle")
async def toggle_log_source(source_name: str):
    """Enable or disable a log source"""
    if not LOG_INGESTORS_AVAILABLE:
        return {"error": "Log ingestors not available. Install dependencies: pip install pywin32 watchdog scapy"}
    
    if source_name not in log_sources_enabled:
        return {"error": f"Unknown source: {source_name}"}
    
    current_state = log_sources_enabled[source_name]
    new_state = not current_state
    
    try:
        if source_name == "windows_events":
            if new_state:
                # Start Windows Event ingestor
                if log_ingestors["windows_events"] is None:
                    log_ingestors["windows_events"] = WindowsEventIngestor(callback=handle_live_log)
                log_ingestors["windows_events"].start()
                log_sources_enabled["windows_events"] = True
                message = "Windows Event Viewer monitoring started"
            else:
                # Stop Windows Event ingestor
                if log_ingestors["windows_events"]:
                    log_ingestors["windows_events"].stop()
                log_sources_enabled["windows_events"] = False
                message = "Windows Event Viewer monitoring stopped"
        
        elif source_name == "web_server_logs":
            if new_state:
                # Start web server log parser
                if log_ingestors["web_server_logs"] is None:
                    log_ingestors["web_server_logs"] = WebServerLogParser(callback=handle_live_log)
                
                # Default log paths (user can configure via environment or config file)
                default_log_paths = [
                    r"C:\logs\access.log",  # Custom path
                    r"C:\Apache24\logs\access.log",  # Apache Windows
                    r"C:\nginx\logs\access.log",  # Nginx Windows
                    r"/var/log/apache2/access.log",  # Apache Linux
                    r"/var/log/nginx/access.log"  # Nginx Linux
                ]
                
                # Check which paths exist and use them
                import os
                existing_paths = [p for p in default_log_paths if os.path.exists(p)]
                
                if existing_paths:
                    log_ingestors["web_server_logs"].start(existing_paths)
                    log_sources_enabled["web_server_logs"] = True
                    message = f"Web server log monitoring started for {len(existing_paths)} file(s): {', '.join(existing_paths)}"
                else:
                    log_sources_enabled["web_server_logs"] = False
                    message = "No web server log files found. Create C:\\logs\\access.log or configure Apache/Nginx paths"
                    return {
                        "error": "No log files found",
                        "message": message,
                        "enabled": False
                    }
            else:
                if log_ingestors["web_server_logs"]:
                    log_ingestors["web_server_logs"].stop()
                log_sources_enabled["web_server_logs"] = False
                message = "Web server log monitoring stopped"
        
        elif source_name == "network_capture":
            if new_state:
                # Start network capture
                if log_ingestors["network_capture"] is None:
                    log_ingestors["network_capture"] = NetworkCapture(callback=handle_live_log)
                log_ingestors["network_capture"].start()
                log_sources_enabled["network_capture"] = True
                message = "Network traffic capture started"
            else:
                if log_ingestors["network_capture"]:
                    log_ingestors["network_capture"].stop()
                log_sources_enabled["network_capture"] = False
                message = "Network traffic capture stopped"
        
        return {
            "source": source_name,
            "enabled": log_sources_enabled[source_name],
            "message": message
        }
    
    except Exception as e:
        return {
            "error": str(e),
            "message": "Failed to toggle log source. Make sure you're running as Administrator."
        }

# ===== WebSocket Endpoint =====
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time threat updates"""
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive and handle client messages
            data = await websocket.receive_text()
            # Echo back or handle client requests
            if data == "ping":
                await ws_manager.send_personal_message({"type": "pong"}, websocket)
            elif data == "stats":
                stats = ws_manager.get_stats()
                await ws_manager.send_personal_message({"type": "stats", "data": stats}, websocket)
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        print(f"WebSocket error: {e}")
        ws_manager.disconnect(websocket)

# ===== Root Health Check =====
@app.get("/")
def root():
    return {"status": "CyberGuard AI: Multi-Agent Detection API running"}
