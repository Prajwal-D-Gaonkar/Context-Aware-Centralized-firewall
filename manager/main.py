# manager/main.py
import sys
import os
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import sqlite3
import datetime
import json
import uvicorn

# Relative import: ml package is inside manager/
from .ml.detector import ml_score_model

DB_FILE = os.path.join(os.path.dirname(__file__), "manager.db")
app = FastAPI(title="CACF - Central Manager", version="0.1")

# -------------------------
# CORS
origins = ["http://localhost:3000"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------
# Pydantic models
class RequestContext(BaseModel):
    app: str
    ip: str
    path: Optional[str] = "/"
    method: Optional[str] = "GET"
    headers: Optional[Dict[str, Any]] = None
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


# -------------------------
# DB helpers
def init_db():
    created = os.path.exists(DB_FILE)
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    c = conn.cursor()
    c.execute(
        """
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
        """
    )
    c.execute(
        """
        CREATE TABLE IF NOT EXISTS policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app TEXT,
            name TEXT,
            description TEXT,
            action TEXT,
            conditions TEXT
        )
        """
    )
    conn.commit()
    return conn


db = init_db()


def save_event(event: dict):
    c = db.cursor()
    c.execute(
        """
        INSERT INTO events (ts, app, ip, path, method, user, verdict, reason, ml_score, payload)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
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
        ),
    )
    db.commit()
    return c.lastrowid


def fetch_events(limit: int = 100, app: Optional[str] = None):
    c = db.cursor()
    if app:
        c.execute("SELECT * FROM events WHERE app = ? ORDER BY id DESC LIMIT ?", (app, limit))
    else:
        c.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    cols = [desc[0] for desc in c.description]
    return [dict(zip(cols, r)) for r in rows]


def save_policy_record(policy: PolicyCreate):
    c = db.cursor()
    c.execute(
        "INSERT INTO policies (app, name, description, action, conditions) VALUES (?, ?, ?, ?, ?)",
        (policy.app, policy.name, policy.description, policy.action, json.dumps(policy.conditions)),
    )
    db.commit()
    return c.lastrowid


def get_policies_list():
    c = db.cursor()
    c.execute("SELECT * FROM policies ORDER BY id ASC")
    rows = c.fetchall()
    cols = [desc[0] for desc in c.description]
    policies = []
    for r in rows:
        rec = dict(zip(cols, r))
        rec["conditions"] = json.loads(rec["conditions"]) if rec["conditions"] else {}
        policies.append(rec)
    return policies


def get_policy(policy_id: int):
    c = db.cursor()
    c.execute("SELECT * FROM policies WHERE id = ?", (policy_id,))
    r = c.fetchone()
    if not r:
        return None
    cols = [desc[0] for desc in c.description]
    rec = dict(zip(cols, r))
    rec["conditions"] = json.loads(rec["conditions"]) if rec["conditions"] else {}
    return rec


def update_policy_record(policy_id: int, data: PolicyCreate):
    c = db.cursor()
    c.execute(
        "UPDATE policies SET app = ?, name = ?, description = ?, action = ?, conditions = ? WHERE id = ?",
        (data.app, data.name, data.description, data.action, json.dumps(data.conditions), policy_id),
    )
    db.commit()
    return c.rowcount


def delete_policy_record(policy_id: int):
    c = db.cursor()
    c.execute("DELETE FROM policies WHERE id = ?", (policy_id,))
    db.commit()
    return c.rowcount


# -------------------------
# Utility: count events from IP in last N seconds
def count_events_from_ip_last_seconds(ip: str, seconds: int) -> int:
    c = db.cursor()
    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(seconds=seconds)).isoformat()
    c.execute("SELECT COUNT(*) FROM events WHERE ip = ? AND ts >= ?", (ip, cutoff))
    r = c.fetchone()
    return r[0] if r else 0


# -------------------------
# Evaluation logic (rules first, then ML) - aggressive blocking for SQLi/XSS
def evaluate_with_policies(ctx: RequestContext):
    policies = get_policies_list()
    relevant = [p for p in policies if p["app"] == ctx.app or p["app"] == "*"]

    body_lower = (ctx.body or "").lower().replace("'", "").replace("--", "")
    path_lower = (ctx.path or "").lower()
    headers_concat = " ".join([f"{k}:{v}" for k, v in (ctx.headers or {}).items()]).lower() if ctx.headers else ""

    # ----------------- Rule evaluation
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
            token_lower = token.lower()
            if token_lower in body_lower or token_lower in headers_concat or token_lower in path_lower:
                return "block", f"Matched token '{token}' in request (policy: {p['name']})", 1.0

        rate_limit = cond.get("rate_limit_per_min", None)
        if rate_limit:
            count = count_events_from_ip_last_seconds(ctx.ip, 60)
            if count >= int(rate_limit):
                return "block", f"Rate limit exceeded ({count} reqs/min) (policy: {p['name']})", 1.0

        if p.get("action") == "review":
            return "review", f"Matched policy {p['name']} requiring review", 0.5

    # ----------------- ML evaluation
    suspicious_tokens = [
        "select",
        "union",
        "drop",
        "insert",
        "update",
        "<script>",
        "or 1=1",
        "' or 1=1",
        "or 1 = 1",
        "javascript:",
        "../",
        "../../",
    ]
    body_normalized = (ctx.body or "").lower()
    token_count = sum(t in body_normalized for t in suspicious_tokens)

    # Call ML model
    try:
        ml_score = ml_score_model(ctx)
    except Exception as e:
        # If ML fails, default to conservative score 0.0 and log reason
        ml_score = 0.0
        # We'll still allow rules to block; but ML won't block if it fails
        # Optionally you can set ml_score = 0.9 to be pessimistic
        print("ML scoring error:", e)

    # Lowered thresholds for more aggressive blocking
    if ml_score > 0.5 or token_count >= 1:
        return "block", f"ML anomaly score {ml_score:.2f} or suspicious token detected", ml_score
    if ml_score > 0.4:
        return "review", f"ML anomaly score {ml_score:.2f}", ml_score

    return "allow", "Passed rules + ML check", ml_score


# -------------------------
# API endpoints
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


@app.get("/events")
async def get_events(limit: int = 100, app_name: Optional[str] = None):
    ev = fetch_events(limit=limit, app=app_name)
    return {"count": len(ev), "events": ev}


@app.get("/health")
async def health():
    return {"status": "ok", "time": datetime.datetime.utcnow().isoformat()}


# -------------------------
# Policies CRUD
@app.get("/policies", response_model=List[Policy])
async def list_policies():
    return get_policies_list()


@app.post("/policies", response_model=Policy)
async def create_policy(p: PolicyCreate):
    pid = save_policy_record(p)
    created = get_policy(pid)
    return created


@app.get("/policies/{policy_id}", response_model=Policy)
async def read_policy(policy_id: int):
    p = get_policy(policy_id)
    if not p:
        raise HTTPException(status_code=404, detail="Policy not found")
    return p


@app.put("/policies/{policy_id}", response_model=Policy)
async def update_policy(policy_id: int, payload: PolicyCreate):
    rows = update_policy_record(policy_id, payload)
    if rows == 0:
        raise HTTPException(status_code=404, detail="Policy not found")
    return get_policy(policy_id)


@app.delete("/policies/{policy_id}")
async def delete_policy(policy_id: int):
    rows = delete_policy_record(policy_id)
    if rows == 0:
        raise HTTPException(status_code=404, detail="Policy not found")
    return {"deleted": True}


# -------------------------
# Logs endpoint (paginated simple)
@app.get("/logs")
async def get_logs(page: int = 1, page_size: int = 10, search: Optional[str] = None):
    all_events = fetch_events(limit=1000)
    if search:
        search_lower = search.lower()
        all_events = [
            e
            for e in all_events
            if search_lower in e["ip"].lower()
            or search_lower in (e["path"] or "").lower()
            or search_lower in (e["reason"] or "").lower()
        ]
    total = len(all_events)
    start = (page - 1) * page_size
    end = start + page_size
    data = all_events[start:end]

    logs = [
        {
            "id": e["id"],
            "timestamp": e["ts"],
            "sourceIP": e["ip"],
            "protocol": e.get("method", "HTTP"),
            "verdict": "Allowed" if e["verdict"] == "allow" else "Blocked",
            "reason": e["reason"],
        }
        for e in data
    ]
    return {"data": logs, "total": total}


# -------------------------
# Dashboard summary
@app.get("/dashboard")
async def get_dashboard():
    events = fetch_events(limit=1000)
    total_requests = len(events)
    blocked_requests = sum(1 for e in events if e["verdict"] == "block")
    unique_ips = len(set(e["ip"] for e in events))

    # requests per minute (simple)
    now = datetime.datetime.utcnow()
    rpm = []
    for i in range(60):
        minute = now - datetime.timedelta(minutes=i)
        count = sum(
            1
            for e in events
            if e["ts"]
            and datetime.datetime.fromisoformat(e["ts"]).replace(second=0, microsecond=0)
            == minute.replace(second=0, microsecond=0)
        )
        rpm.append({"time": minute.strftime("%H:%M"), "value": count})
    rpm.reverse()

    attacks = {}
    for e in events:
        reason = e["reason"].split("(")[0].strip() if e.get("reason") else "unknown"
        attacks[reason] = attacks.get(reason, 0) + 1
    attacks_by_type = [{"type": k, "count": v} for k, v in attacks.items()]

    verdicts = {"allow": 0, "review": 0, "block": 0}
    for e in events:
        verdicts[e["verdict"]] += 1
    verdict_colors = {"allow": "#4ade80", "review": "#facc15", "block": "#f87171"}
    verdict_distribution = [
        {"name": k.capitalize(), "value": v, "color": verdict_colors[k]} for k, v in verdicts.items()
    ]

    return {
        "totalRequests": total_requests,
        "blockedRequests": blocked_requests,
        "uniqueIPs": unique_ips,
        "requestsPerMinute": rpm,
        "attacksByType": attacks_by_type,
        "verdictDistribution": verdict_distribution,
    }


# -------------------------
# Seed a sample policy if DB empty
def seed_sample_policy():
    if not get_policies_list():
        c = db.cursor()
        c.execute(
            "INSERT INTO policies (app,name,description,action,conditions) VALUES (?,?,?,?,?)",
            (
                "*",
                "Block SQLi/XSS",
                "Block known attack tokens",
                "block",
                json.dumps({"block_if_contains": ["or 1=1", "union select", "<script>"]}),
            ),
        )
        db.commit()


seed_sample_policy()


# -------------------------
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
