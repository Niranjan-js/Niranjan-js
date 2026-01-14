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

# ===== Initialize FastAPI App =====
app = FastAPI(title="CyberGuard AI: Multi-Agent Detection")

background_tasks = set()

@app.on_event("startup")
async def start_auto_logs():
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
log_agent = LogAnalysisAgent()
email_agent = EmailVerificationAgent()
ip_agent = IPRangeAnalyzerAgent()
correlation_agent = CorrelationAgent()
llm_agent = LLMReasoningAgent()

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
    findings = await log_agent.analyze(raw_logs_text)
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
    return templates.TemplateResponse(
        "index.html",
        {"request": request}
    )

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
