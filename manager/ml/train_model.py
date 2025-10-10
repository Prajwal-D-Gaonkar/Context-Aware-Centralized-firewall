# ml/train_model.py
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib
import os

# -----------------------------
# Load CSV
csv_path = os.path.join(os.path.dirname(__file__), "csic_database.csv")
df = pd.read_csv(csv_path)

# Strip column names of extra spaces (safer)
df.columns = df.columns.str.strip()

# -----------------------------
# Feature extraction
# Encode HTTP methods
df["method_encoded"] = df["Method"].map({"GET":0, "POST":1, "PUT":2, "DELETE":3}).fillna(4)

# Path and body lengths
df["path_len"] = df["URL"].fillna("").apply(lambda x: len(str(x)))
df["body_len"] = df["content"].fillna("").apply(lambda x: len(str(x)))

# Count suspicious tokens in the body/content
tokens = ["select", "union", "drop", "insert", "update", "<script>", "or 1=1"]
df["num_suspicious_tokens"] = df["content"].fillna("").apply(
    lambda x: sum(t in str(x).lower() for t in tokens)
)

# Check if URL has query parameters
df["has_query"] = df["URL"].fillna("").apply(lambda x: 1 if "?" in str(x) else 0)

# -----------------------------
# Prepare features and labels
features = ["method_encoded", "path_len", "body_len", "num_suspicious_tokens", "has_query"]
X = df[features]
y = df["classification"]

# Split train/test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# -----------------------------
# Train model
model = RandomForestClassifier(n_estimators=120, random_state=42)
model.fit(X_train, y_train)

# Evaluate
acc = model.score(X_test, y_test)
print(f"Model accuracy on test set: {acc:.2f}")

# Save model
joblib.dump(model, os.path.join(os.path.dirname(__file__), "ml_model.pkl"))
print("✅ Model trained and saved in ml/ml_model.pkl")
