import sys
import os

# Add the project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import List, Optional
import os
import asyncio
from api.auto_logs import generate_logs

# ===== Import Agents =====
from agents.log_analyzer.agent import LogAnalysisAgent
from agents.correlation.agent import CorrelationAgent
from agents.llm_reasoner.agent import LLMReasoningAgent

# ===== Import Dashboard Router =====
from api.dashboard import router as dashboard_router

# ===== Initialize FastAPI App =====
app = FastAPI(title="Cyber Threat Detection API")

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
correlation_agent = CorrelationAgent()
llm_agent = LLMReasoningAgent()

# ===== Request Model =====
class LogRequest(BaseModel):
    logs: List[str]
    source: Optional[str] = "Manual Input"

# ===== Analyze Logs Endpoint =====
@app.post("/analyze/logs")
async def analyze_logs(request: LogRequest):
    raw_logs_text = "\n".join(request.logs)
    return await _process_logs(raw_logs_text, request.source)

# ===== Upload/Analyze Real File Endpoint =====
@app.post("/analyze/upload")
async def analyze_upload(file: UploadFile = File(...)):
    content = await file.read()
    raw_logs_text = content.decode("utf-8")
    return await _process_logs(raw_logs_text, f"Uploaded File: {file.filename}")

async def _process_logs(raw_logs_text: str, source: str):
    findings = await log_agent.analyze(raw_logs_text)
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
    print(f"DEBUG: Updated dashboard state from {source}")

    return results

# ===== Register Dashboard Routes =====
app.include_router(dashboard_router)

# ===== Serve Dashboard Page =====
@app.get("/dashboard")
def dashboard(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request}
    )

# ===== Root Health Check =====
@app.get("/")
def root():
    return {"status": "Cyber Threat Detection API running"}