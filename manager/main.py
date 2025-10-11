# manager/main.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import sqlite3
import datetime
import json
import uvicorn

from manager.ml.detector import ml_score_model, ddos_score, anomaly_score, RequestContext

# ---------------- DB Setup ----------------
DB_FILE = "manager.db"
db = sqlite3.connect(DB_FILE, check_same_thread=False)

def init_db(conn):
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, app TEXT, ip TEXT, path TEXT, method TEXT, user TEXT,
        verdict TEXT, reason TEXT, ml_score REAL, payload TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS policies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        app TEXT, name TEXT, description TEXT, action TEXT, conditions TEXT
    )""")
    conn.commit()

init_db(db)

# ---------------- Policies ----------------
def setup_initial_policies():
    c = db.cursor()
    c.execute("INSERT OR REPLACE INTO policies (id, app, name, action, conditions) VALUES (?, ?, ?, ?, ?)", 
              (1, 'global', 'block_admin_post', 'block', json.dumps({"path": "/admin", "method": "POST"})))
    c.execute("INSERT OR REPLACE INTO policies (id, app, name, action, conditions) VALUES (?, ?, ?, ?, ?)", 
              (2, 'app_x', 'allow_test_ip', 'allow', json.dumps({"ip": "127.0.0.1"})))
    db.commit()

setup_initial_policies()

# ---------------- Policy Loader/Checker ----------------
def load_policies(app_name: str) -> List[Dict[str, Any]]:
    c = db.cursor()
    c.execute("SELECT id, app, action, conditions FROM policies WHERE app=? OR app='global'", (app_name,))
    policies = []
    for policy_id, app, action, conditions_json in c.fetchall():
        try:
            conditions = json.loads(conditions_json)
            policies.append({"id": policy_id, "app": app, "action": action, "conditions": conditions})
        except:
            continue
    return policies

def check_policies(ctx: RequestContext, policies: List[Dict[str, Any]]) -> Optional[Dict[str, str]]:
    for policy in policies:
        conditions = policy["conditions"]
        match = True
        for key, required_value in conditions.items():
            ctx_value = getattr(ctx, key, None)
            ctx_str_value = str(ctx_value or "")
            required_str_value = str(required_value or "")
            if isinstance(required_value, str):
                if ctx_str_value.lower() != required_str_value.lower():
                    match = False
                    break
            elif isinstance(required_value, list):
                if ctx_str_value.lower() not in [v.lower() for v in required_value]:
                    match = False
                    break
        if match:
            return {"action": policy["action"], "reason": f"Policy matched: id={policy['id']}"}
    return None

# ---------------- FastAPI ----------------
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

class RequestModel(BaseModel):
    app: str
    ip: str
    path: Optional[str] = "/"
    method: Optional[str] = "GET"
    headers: Optional[Dict[str, Any]] = {}
    body: Optional[str] = None
    user: Optional[str] = None
    timestamp: Optional[str] = None

def save_event(event):
    c = db.cursor()
    ml_score_val = event.get("ml_score", -1.0)
    c.execute("""INSERT INTO events (ts, app, ip, path, method, user, verdict, reason, ml_score, payload)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
             (event["ts"], event["app"], event["ip"], event["path"], event["method"], event["user"],
              event["verdict"], event["reason"], ml_score_val, event["payload"]))
    db.commit()
    return c.lastrowid

# ---------------- Thresholds ----------------
ANOMALY_THRESHOLD = 0.95
DDOS_THRESHOLD = 0.95

@app.post("/check")
async def check_request(req: RequestModel):
    if not req.app or not req.ip:
        raise HTTPException(status_code=400, detail="Missing app or ip")

    ctx = RequestContext()
    ctx.app = req.app
    ctx.ip = req.ip
    ctx.path = req.path
    ctx.method = req.method
    ctx.headers = req.headers
    ctx.body = req.body
    ctx.user = req.user
    ctx.timestamp = req.timestamp or datetime.datetime.utcnow().isoformat()

    verdict = "allow"
    reason = "No policy matched, ML scores below threshold"
    ml_score_val = None

    # 1. Policy Check
    policies = load_policies(ctx.app)
    policy_result = check_policies(ctx, policies)
    if policy_result:
        verdict = policy_result["action"]
        reason = policy_result["reason"]
    else:
        # 2. DDoS ML Check
        ddos_val = ddos_score(ctx)
        if ddos_val >= DDOS_THRESHOLD:
            verdict = "block"
            reason = f"DDoS ML score {ddos_val:.3f} >= threshold {DDOS_THRESHOLD}"
            ml_score_val = ddos_val
        else:
            # 3. Anomaly ML Check
            anomaly_val = anomaly_score(ctx)
            ml_score_val = anomaly_val
            if anomaly_val >= ANOMALY_THRESHOLD:
                verdict = "block"
                reason = f"Anomaly ML score {anomaly_val:.3f} >= threshold {ANOMALY_THRESHOLD}"

    event = {
        "ts": ctx.timestamp, "app": ctx.app, "ip": ctx.ip, "path": ctx.path,
        "method": ctx.method, "user": ctx.user, "verdict": verdict,
        "reason": reason, "ml_score": ml_score_val, "payload": ctx.body or ""
    }
    save_event(event)

    return {"allowed": verdict=="allow", "verdict": verdict, "reason": reason, "ml_score": ml_score_val}

@app.get("/health")
async def health():
    return {"status": "ok", "time": datetime.datetime.utcnow().isoformat()}

@app.get("/events")
async def list_events(limit: int = 100):
    c = db.cursor()
    c.execute("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    cols = [desc[0] for desc in c.description]
    return {"events": [dict(zip(cols, r)) for r in rows]}

if __name__=="__main__":
    uvicorn.run("manager.main:app", host="0.0.0.0", port=8000, reload=True)
