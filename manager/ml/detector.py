# manager/ml/detector.py
import joblib
import numpy as np
import pandas as pd
from typing import Optional, Dict, Any
import os

# ------------------------- Constants
ANOMALY_METHOD_MAP = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3}

BASE_DIR = os.path.dirname(__file__)
ANOMALY_MODEL_PATH = os.path.join(BASE_DIR, "ml_model.pkl")
DDOS_MODEL_PATH = os.path.join(BASE_DIR, "ddos_model.pkl")
DDOS_FEATURES_PATH = os.path.join(BASE_DIR, "ddos_features.npy")
DDOS_ENCODERS_PATH = os.path.join(BASE_DIR, "ddos_encoders.pkl")

# ------------------------- Load models
ml_model = None
try:
    ml_model = joblib.load(ANOMALY_MODEL_PATH)
    print("✅ Loaded anomaly ML model.")
except Exception as e:
    print(f"⚠️ Could not load anomaly ML model: {e}")

ddos_model = None
ddos_features = None
ddos_encoders = {}
try:
    ddos_model = joblib.load(DDOS_MODEL_PATH)
    ddos_features = np.load(DDOS_FEATURES_PATH, allow_pickle=True)
    ddos_encoders = joblib.load(DDOS_ENCODERS_PATH)
    print(f"✅ Loaded DDoS ML model with {len(ddos_features)} features.")
except Exception as e:
    print(f"⚠️ Could not load DDoS model or encoders: {e}")

# ------------------------- Request context
class RequestContext:
    app: str = "default"
    ip: str = "0.0.0.0"
    path: Optional[str] = "/"
    method: Optional[str] = "GET"
    headers: Optional[Dict[str, Any]] = {}
    body: Optional[str] = None
    user: Optional[str] = None
    timestamp: Optional[str] = None

# ------------------------- Heuristic score
def heuristic_score(ctx: RequestContext) -> float:
    tokens = ["select", "union", "drop", "insert", "update", "<script>", "or 1=1"]
    count = sum(t in (ctx.body or "").lower() for t in tokens)
    score = min(1.0, 0.1 * count + 0.05 * len(ctx.body or "") / 100)
    return score

# ------------------------- DDoS score
def ddos_score(ctx: RequestContext) -> float:
    if not ddos_model or ddos_features is None:
        return 0.0
    data = pd.DataFrame(np.zeros((1, len(ddos_features))), columns=ddos_features)
    if 'Src IP' in ddos_encoders:
        try:
            data['Src IP'] = ddos_encoders['Src IP'].transform([ctx.ip])[0]
        except ValueError:
            data['Src IP'] = 0
    if "Flow Duration" in data.columns:
        data["Flow Duration"] = 1000
    if 'BodyLength' in data.columns:
        data['BodyLength'] = len(ctx.body or "")
    try:
        return float(ddos_model.predict_proba(data)[0][1])
    except Exception:
        return 0.0

# ------------------------- Anomaly score
def anomaly_score(ctx: RequestContext) -> float:
    if ml_model is None:
        return heuristic_score(ctx)
    method_encoded = ANOMALY_METHOD_MAP.get(ctx.method.upper(), 4)
    path_len = len(ctx.path or "")
    body_len = len(ctx.body or "")
    has_query = 1 if "?" in (ctx.path or "") else 0
    tokens = ["select", "union", "drop", "insert", "update", "<script>", "or 1=1"]
    num_suspicious_tokens = sum(t in (ctx.body or "").lower() for t in tokens)
    features = [[method_encoded, path_len, body_len, num_suspicious_tokens, has_query]]
    try:
        return float(ml_model.predict_proba(features)[0][1])
    except Exception:
        return heuristic_score(ctx)

# ------------------------- Master ML scoring
def ml_score_model(ctx: RequestContext) -> float:
    score_ddos = ddos_score(ctx)
    score_anom = anomaly_score(ctx)
    final_score = 0.7 * score_anom + 0.3 * score_ddos
    return round(final_score, 3)
