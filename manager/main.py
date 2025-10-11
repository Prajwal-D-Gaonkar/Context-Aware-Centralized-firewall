from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import sqlite3
import datetime
import json
from passlib.context import CryptContext
import os
import jwt
from jwt import PyJWTError

# ----------------------------
# CACF Modules
# ----------------------------
from manager.ml.detector import ml_score_model, ddos_score, anomaly_score, RequestContext
from manager.auth_db import get_auth_db, init_auth_db

# ----------------------------
# Security Config
# ----------------------------
SECRET_KEY = "supersecretkey-change_this"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# ----------------------------
# Initialize Auth DB
# ----------------------------
init_auth_db()

# ----------------------------
# FastAPI App
# ----------------------------
app = FastAPI(title="CACF Policy Advisor", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ----------------------------
# Models
# ----------------------------
class RegisterRequest(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

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
    action: str
    conditions: Dict[str, Any]

# ----------------------------
# Policy DB Setup
# ----------------------------
DB_FILE = os.path.join(os.path.dirname(__file__), "manager.db")
db = sqlite3.connect(DB_FILE, check_same_thread=False)

def init_policy_db():
    c = db.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT, app TEXT, ip TEXT, path TEXT, method TEXT, user TEXT,
        verdict TEXT, reason TEXT, ml_score REAL, payload TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS policies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        app TEXT, name TEXT, description TEXT, action TEXT, conditions TEXT
    )""")
    db.commit()

init_policy_db()

# ----------------------------
# Auth Helpers
# ----------------------------
def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_admin(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                          detail="Invalid credentials",
                                          headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except PyJWTError:
        raise credentials_exception
    return {"username": username}

# ----------------------------
# Auth Routes
# ----------------------------
@app.post("/auth/register")
def register(req: RegisterRequest):
    conn = get_auth_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admins WHERE username=?", (req.username,))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Username already exists")
    cursor.execute("INSERT INTO admins (username, hashed_password) VALUES (?, ?)",
                   (req.username, hash_password(req.password)))
    conn.commit()
    conn.close()
    return {"message": "Admin registered successfully"}

@app.post("/auth/login")
def login(req: LoginRequest):
    conn = get_auth_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM admins WHERE username=?", (req.username,))
    admin = cursor.fetchone()
    conn.close()
    if not admin or not verify_password(req.password, admin["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = create_access_token({"sub": req.username})
    return {"access_token": token, "token_type": "bearer"}

# ----------------------------
# Protected Policy Routes
# ----------------------------
@app.post("/policies")
def create_policy(policy: PolicyModel, current_admin: dict = Depends(get_current_admin)):
    c = db.cursor()
    c.execute(
        "INSERT INTO policies (app, name, description, action, conditions) VALUES (?, ?, ?, ?, ?)",
        (policy.app, policy.name, policy.description, policy.action, json.dumps(policy.conditions))
    )
    db.commit()
    return {"message": f"Policy '{policy.name}' created successfully by {current_admin['username']}"}

@app.get("/policies")
def list_policies(current_admin: dict = Depends(get_current_admin)):
    c = db.cursor()
    c.execute("SELECT * FROM policies")
    rows = c.fetchall()
    cols = [desc[0] for desc in c.description]
    return {"policies": [dict(zip(cols, r)) for r in rows], "admin": current_admin["username"]}

@app.put("/policies/{policy_id}")
def update_policy(policy_id: int, policy: PolicyModel, current_admin: dict = Depends(get_current_admin)):
    c = db.cursor()
    c.execute(
        "UPDATE policies SET app=?, name=?, description=?, action=?, conditions=? WHERE id=?",
        (policy.app, policy.name, policy.description, policy.action, json.dumps(policy.conditions), policy_id)
    )
    db.commit()
    return {"message": f"Policy ID {policy_id} updated by {current_admin['username']}"}

@app.delete("/policies/{policy_id}")
def delete_policy(policy_id: int, current_admin: dict = Depends(get_current_admin)):
    c = db.cursor()
    c.execute("DELETE FROM policies WHERE id=?", (policy_id,))
    db.commit()
    return {"message": f"Policy ID {policy_id} deleted by {current_admin['username']}"}

# ----------------------------
# Request Check Endpoint
# ----------------------------
ANOMALY_THRESHOLD = 0.95
DDOS_THRESHOLD = 0.95

def save_event(event):
    c = db.cursor()
    ml_score_val = event.get("ml_score", -1.0)
    c.execute("""INSERT INTO events (ts, app, ip, path, method, user, verdict, reason, ml_score, payload)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
             (event["ts"], event["app"], event["ip"], event["path"], event["method"], event["user"],
              event["verdict"], event["reason"], ml_score_val, event["payload"]))
    db.commit()

@app.post("/check")
def check_request(req: RequestModel):
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

    # Policy Check
    policies = list_policies(current_admin={"username":"system"})["policies"]
    for policy in policies:
        conditions = json.loads(policy["conditions"])
        match = True
        for key, val in conditions.items():
            ctx_val = str(getattr(ctx, key, "") or "")
            if isinstance(val, str) and ctx_val.lower() != val.lower():
                match = False
            elif isinstance(val, list) and ctx_val.lower() not in [v.lower() for v in val]:
                match = False
        if match:
            verdict = policy["action"]
            reason = f"Policy matched: id={policy['id']}"
            break

    # ML Check
    if verdict == "allow":
        ddos_val = ddos_score(ctx)
        if ddos_val >= DDOS_THRESHOLD:
            verdict = "block"
            reason = f"DDoS ML score {ddos_val:.3f} >= threshold {DDOS_THRESHOLD}"
            ml_score_val = ddos_val
        else:
            anomaly_val = anomaly_score(ctx)
            if anomaly_val >= ANOMALY_THRESHOLD:
                verdict = "block"
                reason = f"Anomaly ML score {anomaly_val:.3f} >= threshold {ANOMALY_THRESHOLD}"
                ml_score_val = anomaly_val

    save_event({
        "ts": ctx.timestamp, "app": ctx.app, "ip": ctx.ip, "path": ctx.path,
        "method": ctx.method, "user": ctx.user, "verdict": verdict,
        "reason": reason, "ml_score": ml_score_val, "payload": ctx.body or ""
    })

    return {"allowed": verdict=="allow", "verdict": verdict, "reason": reason, "ml_score": ml_score_val}

# ----------------------------
# Health & Events
# ----------------------------
@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.datetime.utcnow().isoformat()}

@app.get("/events")
def list_events(current_admin: dict = Depends(get_current_admin), limit: int = 100):
    c = db.cursor()
    c.execute("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    cols = [desc[0] for desc in c.description]
    return {"events": [dict(zip(cols, r)) for r in rows], "admin": current_admin["username"]}

# ----------------------------
# Run Server
# ----------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("manager.main:app", host="0.0.0.0", port=8000, reload=True)
