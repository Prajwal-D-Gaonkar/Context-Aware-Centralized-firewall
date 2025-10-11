# manager/ml/train_model.py
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

# ------------------------- Constants
BASE_DIR = os.path.dirname(__file__)
CSV_PATH = os.path.join(BASE_DIR, "csic_database.csv")  # Your CSV file
MODEL_PATH = os.path.join(BASE_DIR, "ml_model.pkl")

# ------------------------- Load dataset
df = pd.read_csv(CSV_PATH)

# ------------------------- Feature engineering
df['method'] = df['Method']
df['path'] = df['URL']
df['body'] = df['content']

# Encode method
ANOMALY_METHOD_MAP = {"GET": 0, "POST": 1, "PUT": 2, "DELETE": 3}
df['method_encoded'] = df['method'].map(ANOMALY_METHOD_MAP).fillna(4).astype(int)

# Path length
df['path_len'] = df['path'].astype(str).str.len()

# Body length
df['body_len'] = df['body'].astype(str).str.len()

# Suspicious tokens
tokens = ["select", "union", "drop", "insert", "update", "<script>", "or 1=1"]
df['num_suspicious_tokens'] = df['body'].astype(str).apply(
    lambda x: sum(t in x.lower() for t in tokens)
)

# Query string in path
df['has_query'] = df['path'].astype(str).str.contains(r'\?').astype(int)

# ------------------------- Features and target
feature_cols = ["method_encoded", "path_len", "body_len", "num_suspicious_tokens", "has_query"]
X = df[feature_cols]

# Target column
y = df['classification']  # 0 = normal, 1 = attack

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)


clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)


acc = clf.score(X_test, y_test)
print(f"✅ RandomForest trained. Test accuracy: {acc:.3f}")


joblib.dump(clf, MODEL_PATH)
print(f"✅ Model saved to {MODEL_PATH}")
