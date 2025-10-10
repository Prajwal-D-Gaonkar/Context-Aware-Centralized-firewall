# manager/main.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import sqlite3
import datetime
import json
import uvicorn

# ML integration
from .ml.detector import ml_score_model

DB_FILE = "manager.db"
app = FastAPI(title="CACF - Central Manager", version="0.4")

# ------------------------- CORS
origins = ["http://localhost:3000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------- Pydantic models
class RequestContext(BaseModel):
    app: str
    ip: str
    path: Optional[str] = "/"
    method: Optional[str] = "GET"
    headers: Optional[Dict[str, Any]] = {}
    body: Optional[str] = None
    user: Optional[str] = None
    timestamp: Optional[str] = None

class PolicyCreate(BaseModel):
    app: str
    name: str
    description: Optional[str] = ""
    action: str  # allow / block / review
    conditions: Dict[str, Any]

class Policy(PolicyCreate):
    id: int

# ------------------------- Database helpers
def init_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            app TEXT,
            ip TEXT,
            path TEXT,
            method TEXT,
            user TEXT,
            verdict TEXT,
            reason TEXT,
            ml_score REAL,
            payload TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app TEXT,
            name TEXT,
            description TEXT,
            action TEXT,
            conditions TEXT
        )
    """)
    conn.commit()
    return conn

db = init_db()

def save_event(event: dict):
    c = db.cursor()
    c.execute("""
        INSERT INTO events (ts, app, ip, path, method, user, verdict, reason, ml_score, payload)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        event.get("ts"),
        event.get("app"),
        event.get("ip"),
        event.get("path"),
        event.get("method"),
        event.get("user"),
        event.get("verdict"),
        event.get("reason"),
        event.get("ml_score"),
        event.get("payload"),
    ))
    db.commit()
    return c.lastrowid

def get_policies_list():
    c = db.cursor()
    c.execute("SELECT * FROM policies")
    rows = c.fetchall()
    cols = [desc[0] for desc in c.description]
    policies = []
    for r in rows:
        rec = dict(zip(cols, r))
        rec["conditions"] = json.loads(rec["conditions"]) if rec["conditions"] else {}
        policies.append(rec)
    return policies

def count_events_from_ip_last_seconds(ip: str, seconds: int) -> int:
    c = db.cursor()
    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(seconds=seconds)).isoformat()
    c.execute("SELECT COUNT(*) FROM events WHERE ip = ? AND ts >= ?", (ip, cutoff))
    r = c.fetchone()
    return r[0] if r else 0

# ------------------------- Evaluation with rules + ML + DDoS
GLOBAL_DDOS_THRESHOLD = 50  # requests per 10 seconds triggers DDoS block

def evaluate_with_policies(ctx: RequestContext):
    policies = get_policies_list()
    relevant = [p for p in policies if p["app"] == ctx.app or p["app"] == "*"]

    body_lower = (ctx.body or "").lower().replace("'", "").replace("--", "")
    path_lower = (ctx.path or "").lower()
    headers_concat = " ".join([f"{k}:{v}" for k, v in (ctx.headers or {}).items()]).lower()

    # ---- Rule-based policies
    for p in relevant:
        cond = p.get("conditions", {}) or {}

        blocked_ips = cond.get("blocked_ips", [])
        if ctx.ip in blocked_ips:
            return "block", f"IP {ctx.ip} in blocked_ips (policy: {p['name']})", 1.0

        allowed_ips = cond.get("allowed_ips", None)
        if allowed_ips is not None and ctx.ip not in allowed_ips:
            return "block", f"IP {ctx.ip} not in allowed_ips (policy: {p['name']})", 1.0

        block_if_contains = cond.get("block_if_contains", [])
        for token in block_if_contains:
            if token.lower() in body_lower or token.lower() in headers_concat or token.lower() in path_lower:
                return "block", f"Matched token '{token}' in request (policy: {p['name']})", 1.0

        rate_limit = cond.get("rate_limit_per_min", None)
        if rate_limit:
            count = count_events_from_ip_last_seconds(ctx.ip, 60)
            if count >= int(rate_limit):
                return "block", f"Rate limit exceeded ({count} reqs/min) (policy: {p['name']})", 1.0

        if p.get("action") == "review":
            return "review", f"Matched policy {p['name']} requiring review", 0.5

    # ---- Global DDoS detection
    recent_count = count_events_from_ip_last_seconds(ctx.ip, 10)
    if recent_count >= GLOBAL_DDOS_THRESHOLD:
        return "block", f"DDoS detected: {recent_count} reqs in last 10s", 1.0

    # ---- ML evaluation
    ml_score = ml_score_model(ctx)
    suspicious_tokens = ["select", "union", "drop", "insert", "update", "<script>", "or 1=1", "' or 1=1"]
    token_count = sum(t in (ctx.body or "").lower() for t in suspicious_tokens)

    if ml_score > 0.5 or token_count >= 1:
        return "block", f"ML anomaly score {ml_score:.2f} or suspicious token detected", ml_score
    if ml_score > 0.4:
        return "review", f"ML anomaly score {ml_score:.2f}", ml_score

    return "allow", "Passed rules + ML + DDoS check", ml_score

# ------------------------- API endpoints
@app.post("/check")
async def check_request(ctx: RequestContext):
    if not ctx.timestamp:
        ctx.timestamp = datetime.datetime.utcnow().isoformat()
    verdict, reason, score = evaluate_with_policies(ctx)
    event = {
        "ts": ctx.timestamp,
        "app": ctx.app,
        "ip": ctx.ip,
        "path": ctx.path,
        "method": ctx.method,
        "user": ctx.user,
        "verdict": verdict,
        "reason": reason,
        "ml_score": score,
        "payload": ctx.body or "",
    }
    save_event(event)
    return {"allowed": verdict == "allow", "verdict": verdict, "reason": reason, "ml_score": score}

@app.get("/health")
async def health():
    return {"status": "ok", "time": datetime.datetime.utcnow().isoformat()}

# ------------------------- Event endpoints
@app.get("/events")
async def list_events(limit: int = 100):
    c = db.cursor()
    c.execute("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    cols = [desc[0] for desc in c.description]
    events = [dict(zip(cols, r)) for r in rows]
    return {"events": events}

@app.get("/events/{event_id}")
async def get_event(event_id: int):
    c = db.cursor()
    c.execute("SELECT * FROM events WHERE id = ?", (event_id,))
    row = c.fetchone()
    if not row:
        return {"error": "Event not found"}
    cols = [desc[0] for desc in c.description]
    return dict(zip(cols, row))

# ------------------------- Policy endpoints
@app.post("/policies")
async def create_policy(p: PolicyCreate):
    c = db.cursor()
    c.execute("""
        INSERT INTO policies (app, name, description, action, conditions)
        VALUES (?, ?, ?, ?, ?)
    """, (
        p.app,
        p.name,
        p.description,
        p.action,
        json.dumps(p.conditions),
    ))
    db.commit()
    return {"status": "ok", "id": c.lastrowid}

@app.get("/policies")
async def list_policies():
    return {"policies": get_policies_list()}

# ------------------------- Bootstrap sample policies
def seed_sample_policies():
    if not get_policies_list():
        save_event({
            "ts": datetime.datetime.utcnow().isoformat(),
            "app": "*",
            "ip": "127.0.0.1",
            "path": "/",
            "method": "GET",
            "user": "system",
            "verdict": "allow",
            "reason": "Bootstrap event",
            "ml_score": 0.0,
            "payload": ""
        })

seed_sample_policies()

# ------------------------- Run server
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
