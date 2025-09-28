# manager/main.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import sqlite3
import datetime
import json
import uvicorn
import os

DB_FILE = "manager.db"

app = FastAPI(title="CACF - Central Manager", version="0.1")


# -------------------------
# Pydantic models
# -------------------------
class RequestContext(BaseModel):
    app: str
    ip: str
    path: Optional[str] = "/"
    method: Optional[str] = "GET"
    headers: Optional[Dict[str, Any]] = {}
    body: Optional[str] = None
    user: Optional[str] = None
    timestamp: Optional[str] = None  # ISO string optional


class PolicyCreate(BaseModel):
    app: str
    name: str
    description: Optional[str] = ""
    action: str  # "allow" / "block" / "review"
    conditions: Dict[str, Any]  # e.g. {"blocked_ips": ["1.2.3.4"], "block_if_contains": ["<script>"]}


class Policy(PolicyCreate):
    id: int


# -------------------------
# DB helpers
# -------------------------
def init_db():
    created = os.path.exists(DB_FILE)
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    c = conn.cursor()
    # events table logs decisions
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
    # policies stored as JSON in DB
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
    c.execute("SELECT * FROM policies")
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
# Simple policy evaluation logic
# -------------------------
def evaluate_with_policies(ctx: RequestContext):
    """
    Returns: verdict (allow/review/block), reason, ml_score (float)
    Simple logic:
      - Load all policies for ctx.app (and global ones)
      - Evaluate conditions: blocked_ips, allowed_ips, block_if_contains (strings in body/headers)
      - If any policy triggers block => block
      - Else run a placeholder ML scoring (0..1 anomaly) and decide based on threshold
    """
    policies = get_policies_list()
    # collect policies that apply to this ctx.app or global "*"
    relevant = [p for p in policies if p["app"] == ctx.app or p["app"] == "*"]

    body_lower = (ctx.body or "").lower()
    headers_concat = " ".join([f"{k}:{v}" for k, v in (ctx.headers or {}).items()]).lower()

    # Rule checks from policies
    for p in relevant:
        cond = p.get("conditions", {}) or {}
        # blocked_ips
        blocked_ips = cond.get("blocked_ips", [])
        if ctx.ip in blocked_ips:
            return "block", f"IP {ctx.ip} in blocked_ips (policy: {p['name']})", 1.0
        # allowed_ips (if defined, and ip not in list -> block)
        allowed_ips = cond.get("allowed_ips", None)
        if allowed_ips is not None and ctx.ip not in allowed_ips:
            return "block", f"IP {ctx.ip} not in allowed_ips (policy: {p['name']})", 1.0
        # block_if_contains - substrings to search in body/headers/path
        block_if_contains = cond.get("block_if_contains", [])
        for token in block_if_contains:
            if token.lower() in body_lower or token.lower() in headers_concat or token.lower() in (ctx.path or "").lower():
                return "block", f"Matched token '{token}' in request (policy: {p['name']})", 1.0
        # rate_limit_per_min - simple check: if events from this IP in last 60s > threshold -> block
        rate_limit = cond.get("rate_limit_per_min", None)
        if rate_limit:
            count = count_events_from_ip_last_seconds(ctx.ip, 60)
            if count >= int(rate_limit):
                return "block", f"Rate limit exceeded ({count} reqs/min) (policy: {p['name']})", 1.0
        # action review -> treat as review if matched
        if p.get("action") == "review":
            return "review", f"Matched policy {p['name']} requiring review", 0.5

    # Placeholder ML scoring: simple heuristic anomaly:
    ml_score = ml_score_placeholder(ctx)
    # threshold: if ml_score > 0.8 -> anomaly -> block
    if ml_score > 0.8:
        return "block", f"Anomaly score {ml_score:.2f} > 0.8", ml_score
    if ml_score > 0.6:
        return "review", f"Anomaly score {ml_score:.2f} > 0.6", ml_score

    return "allow", "Passed rules + ML check", ml_score


def ml_score_placeholder(ctx: RequestContext) -> float:
    """
    Very simple scoring for MVP/demo:
    - long URLs or bodies, or presence of suspicious tokens increases score
    - returns 0..1
    """
    score = 0.0
    suspicious_tokens = ["union select", "or 1=1", "<script", "javascript:", "../../", "select ", "insert ", "update ", "drop "]
    body = (ctx.body or "").lower()
    path = (ctx.path or "").lower()
    concat = " ".join([body, path, json.dumps(ctx.headers or {})]).lower()
    if len(concat) > 200:
        score += 0.2
    for t in suspicious_tokens:
        if t in concat:
            score += 0.3
    # add small random-ish heuristic from IP octets (not truly random to keep reproducible)
    try:
        parts = ctx.ip.split(".")
        if len(parts) == 4:
            last = int(parts[-1]) % 10
            score += (last / 100)  # up to 0.09
    except Exception:
        pass
    # clamp
    return min(1.0, score)


def count_events_from_ip_last_seconds(ip: str, seconds: int) -> int:
    c = db.cursor()
    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(seconds=seconds)).isoformat()
    c.execute("SELECT COUNT(*) FROM events WHERE ip = ? AND ts >= ?", (ip, cutoff))
    r = c.fetchone()
    return r[0] if r else 0


# -------------------------
# API endpoints
# -------------------------
@app.post("/check")
async def check_request(ctx: RequestContext):
    """
    Main endpoint used by Agents.
    Returns: { allowed: bool, verdict: 'allow'|'block'|'review', reason: str, ml_score: float }
    Also stores a log event in SQLite.
    """
    # ensure timestamp
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
    """
    Returns most recent events (default limit=100). Optional filter by app_name.
    """
    ev = fetch_events(limit=limit, app=app_name)
    return {"count": len(ev), "events": ev}


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


@app.get("/health")
async def health():
    return {"status": "ok", "time": datetime.datetime.utcnow().isoformat()}


# -------------------------
# Bootstrap sample policy(s)
# -------------------------
def seed_sample_policies():
    # if no policies exist, create a few sensible demo policies
    if not get_policies_list():
        demo1 = PolicyCreate(
            app="demo_app",
            name="Block SQLi keywords",
            description="Block if request contains common SQL injection patterns",
            action="block",
            conditions={"block_if_contains": ["union select", "or 1=1", "' or '", ";--", "drop table"]},
        )
        save_policy_record(demo1)

        demo2 = PolicyCreate(
            app="*",
            name="Block obvious XSS",
            description="Block if <script> or javascript: found",
            action="block",
            conditions={"block_if_contains": ["<script", "javascript:"]},
        )
        save_policy_record(demo2)

        demo3 = PolicyCreate(
            app="demo_app",
            name="Rate-limit brute-force",
            description="If >20 reqs/min from same IP, block",
            action="block",
            conditions={"rate_limit_per_min": 20},
        )
        save_policy_record(demo3)


# -------------------------
# Start server
# -------------------------
if __name__ == "__main__":
    seed_sample_policies()
    print("Starting Central Manager (FastAPI) on http://0.0.0.0:8000")
    uvicorn.run(app, host="0.0.0.0", port=8000)
