import joblib
import numpy as np
from typing import Optional

# Load model
ml_model = joblib.load("manager/ml/ml_model.pkl")  # relative to project root

class RequestContext:
    app: str
    ip: str
    path: Optional[str] = "/"
    method: Optional[str] = "GET"
    headers: Optional[dict] = {}
    body: Optional[str] = None
    user: Optional[str] = None
    timestamp: Optional[str] = None

def ml_score_model(ctx: "RequestContext") -> float:
    """
    Returns a float between 0 and 1 representing anomaly probability
    """
    tokens = ["select", "union", "drop", "insert", "update", "<script>", "or 1=1"]
    susp_count = sum(t in (ctx.body or "").lower() for t in tokens)

    features = np.array([
        0 if ctx.method == "GET" else 1,
        len(ctx.path or ""),
        len(ctx.body or ""),
        susp_count,
        1 if "?" in (ctx.path or "") else 0
    ]).reshape(1, -1)

    score = float(ml_model.predict_proba(features)[0][1])
    return score
