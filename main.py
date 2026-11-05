import hmac
import logging
import os
import time
from collections import defaultdict, deque
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, Header, HTTPException, Request  # noqa: E402
from fastapi.responses import HTMLResponse, JSONResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from fastapi.templating import Jinja2Templates  # noqa: E402
from pydantic import BaseModel, Field  # noqa: E402

import agent  # noqa: E402

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(name)s: %(message)s")

BASE_DIR = Path(__file__).resolve().parent
# Key for the programmatic /honeypot endpoint. Set API_KEY in .env for real use.
API_KEY = os.getenv("API_KEY", "ai_honeypot_demo_key")

app = FastAPI(title="Agentic Honey-Pot")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


# ---------- simple in-memory rate limit (per client IP) ----------
RATE_LIMIT = 30          # requests
RATE_WINDOW = 60         # seconds
_hits: dict[str, deque] = defaultdict(deque)


def check_rate_limit(request: Request):
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    q = _hits[ip]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        raise HTTPException(status_code=429,
                            detail="Too many requests. Please wait a minute.")
    q.append(now)


class ChatIn(BaseModel):
    message: str = Field(min_length=1, max_length=2000)
    session_id: str | None = Field(default=None, max_length=64)


# ---------- WEB UI ----------
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.get("/health")
async def health():
    return {"ok": True}


@app.get("/api/status")
async def api_status():
    return agent.status()


# ---------- UI chat endpoint (same-origin, rate limited) ----------
@app.post("/api/chat")
async def chat(body: ChatIn, request: Request):
    check_rate_limit(request)
    if not body.message.strip():
        raise HTTPException(status_code=422, detail="Message is empty")
    return agent.handle(body.session_id, body.message)


@app.get("/api/report/{session_id}")
async def report(session_id: str, request: Request):
    check_rate_limit(request)
    data = agent.build_report(session_id)
    if data is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return JSONResponse(
        data,
        headers={"Content-Disposition":
                 f'attachment; filename="honeypot-report-{session_id[:8]}.json"'},
    )


# ---------- HONEYPOT API (API-key protected, backwards compatible) ----------
@app.post("/honeypot")
async def honeypot(body: ChatIn, request: Request,
                   x_api_key: str = Header(None)):
    if not x_api_key or not hmac.compare_digest(x_api_key, API_KEY):
        raise HTTPException(status_code=401, detail="Invalid API Key")
    check_rate_limit(request)
    return agent.handle(body.session_id, body.message)
