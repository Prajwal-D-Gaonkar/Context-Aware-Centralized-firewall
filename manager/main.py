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


from manager.agent.summarizerAgent import summarizer

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
    c.execute(
        "INSERT OR REPLACE INTO policies (id, app, name, action, conditions) VALUES (?, ?, ?, ?, ?)",
        (1, 'global', 'block_admin_post', 'block', json.dumps({"path": "/admin", "method": "POST"}))
    )
    c.execute(
        "INSERT OR REPLACE INTO policies (id, app, name, action, conditions) VALUES (?, ?, ?, ?, ?)",
        (2, 'app_x', 'allow_test_ip', 'allow', json.dumps({"ip": "127.0.0.1"}))
    )
    db.commit()

setup_initial_policies()

# ---------------- Policy Loader/Checker ----------------
def load_policies(app_name: str) -> List[Dict[str, Any]]:
    c = db.cursor()
    c.execute("SELECT id, app, name, action, conditions FROM policies WHERE app=? OR app='global'", (app_name,))
    policies = []
    for policy_id, app, name, action, conditions_json in c.fetchall():
        try:
            conditions = json.loads(conditions_json)
            policies.append({"id": policy_id, "app": app, "name": name, "action": action, "conditions": conditions})
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
app = FastAPI(title="CACF Policy Advisor", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ---------------- Request Models ----------------
class RequestModel(BaseModel):
    app: str
    ip: str
    path: Optional[str] = "/"
    method: Optional[str] = "GET"
    headers: Optional[Dict[str, Any]] = {}
    body: Optional[str] = None
    user: Optional[str] = None
    timestamp: Optional[str] = None

class PolicyModel(BaseModel):
    app: str
    name: str
    description: Optional[str] = ""
    action: str  # "allow" or "block"
    conditions: Dict[str, Any]

# ---------------- Event Save ----------------
def save_event(event):
    c = db.cursor()
    ml_score_val = event.get("ml_score", -1.0)
    c.execute(
        """INSERT INTO events (ts, app, ip, path, method, user, verdict, reason, ml_score, payload)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (event["ts"], event["app"], event["ip"], event["path"], event["method"], event["user"],
         event["verdict"], event["reason"], ml_score_val, event["payload"])
    )
    db.commit()
    return c.lastrowid

# ---------------- Thresholds ----------------
ANOMALY_THRESHOLD = 0.95
DDOS_THRESHOLD = 0.95

# ---------------- Check Request Endpoint ----------------
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

    # 1️⃣ Policy Check
    policies = load_policies(ctx.app)
    policy_result = check_policies(ctx, policies)
    if policy_result:
        verdict = policy_result["action"]
        reason = policy_result["reason"]
    else:
        # 2️⃣ DDoS ML Check
        ddos_val = ddos_score(ctx)
        if ddos_val >= DDOS_THRESHOLD:
            verdict = "block"
            reason = f"DDoS ML score {ddos_val:.3f} >= threshold {DDOS_THRESHOLD}"
            ml_score_val = ddos_val
        else:
            # 3️⃣ Anomaly ML Check
            anomaly_val = anomaly_score(ctx)
            ml_score_val = anomaly_val
            if anomaly_val >= ANOMALY_THRESHOLD:
                verdict = "block"
                reason = f"Anomaly ML score {anomaly_val:.3f} >= threshold {ANOMALY_THRESHOLD}"

    # 4️⃣ Save Event
    event = {
        "ts": ctx.timestamp, "app": ctx.app, "ip": ctx.ip, "path": ctx.path,
        "method": ctx.method, "user": ctx.user, "verdict": verdict,
        "reason": reason, "ml_score": ml_score_val, "payload": ctx.body or ""
    }
    save_event(event)

    # 5️⃣ Generate Summary for any block
    summary = None
    if verdict == "block":
        ml_result_str = json.dumps({
            "allowed": False,
            "verdict": verdict,
            "reason": reason,
            "ml_score": ml_score_val
        })
        summary = summarizer(ml_result_str)

    response = {
        "allowed": verdict == "allow",
        "verdict": verdict,
        "reason": reason,
        "ml_score": ml_score_val,
    }
    if summary:
        response["summary"] = summary

    return response

# ---------------- Add/Update Policy Endpoint ----------------
@app.post("/policies")
async def add_policy(policy: PolicyModel):
    c = db.cursor()
    c.execute("SELECT id FROM policies WHERE app=? AND name=?", (policy.app, policy.name))
    existing = c.fetchone()
    if existing:
        # Update existing
        c.execute(
            "UPDATE policies SET description=?, action=?, conditions=? WHERE id=?",
            (policy.description, policy.action, json.dumps(policy.conditions), existing[0])
        )
        db.commit()
        return {"status": "updated", "policy_id": existing[0]}
    else:
        # Insert new
        c.execute(
            "INSERT INTO policies (app, name, description, action, conditions) VALUES (?, ?, ?, ?, ?)",
            (policy.app, policy.name, policy.description, policy.action, json.dumps(policy.conditions))
        )
        db.commit()
        return {"status": "created", "policy_id": c.lastrowid}

# ---------------- List Policies ----------------
@app.get("/policies")
async def list_policies(app_name: Optional[str] = None):
    c = db.cursor()
    if app_name:
        c.execute("SELECT * FROM policies WHERE app=? OR app='global'", (app_name,))
    else:
        c.execute("SELECT * FROM policies")
    rows = c.fetchall()
    cols = [desc[0] for desc in c.description]
    return {"policies": [dict(zip(cols, r)) for r in rows]}
@app.post("/policies")
async def add_policy(policy: PolicyModel):
    c = db.cursor()
    # Check if a policy with the same app and name already exists
    c.execute("SELECT id FROM policies WHERE app=? AND name=?", (policy.app, policy.name))
    existing = c.fetchone()
    if existing:
        # Update the existing policy
        c.execute(
            "UPDATE policies SET description=?, action=?, conditions=? WHERE id=?",
            (policy.description, policy.action, json.dumps(policy.conditions), existing[0])
        )
        db.commit()
        return {"status": "updated", "policy_id": existing[0]}
    else:
        # Insert a new policy
        c.execute(
            "INSERT INTO policies (app, name, description, action, conditions) VALUES (?, ?, ?, ?, ?)",
            (policy.app, policy.name, policy.description, policy.action, json.dumps(policy.conditions))
        )
        db.commit()
        return {"status": "created", "policy_id": c.lastrowid}


# ---------------- Health & Events ----------------
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

# ---------------- Run Server ----------------
if __name__=="__main__":
    uvicorn.run("manager.main:app", host="0.0.0.0", port=8000, reload=True)
