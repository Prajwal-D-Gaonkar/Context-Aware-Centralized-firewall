import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score
import joblib
import os

# ------------------------- Config
CSV_PATH = os.path.join(os.path.dirname(__file__), "5percent_NetBIOS.csv")
MODEL_PATH = os.path.join(os.path.dirname(__file__), "ddos_model.pkl")

print(f"Loading data from {CSV_PATH} ...")
df = pd.read_csv(CSV_PATH, low_memory=False)

# ------------------------- Basic preprocessing
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.fillna(0, inplace=True)

if "Label" not in df.columns:
    raise ValueError("Dataset must contain a 'Label' column.")

# Separate features and target
X = df.drop("Label", axis=1)
y = df["Label"]

# Encode non-numeric columns
for col in X.columns:
    if X[col].dtype == "object":
        le = LabelEncoder()
        try:
            X[col] = le.fit_transform(X[col].astype(str))
        except Exception:
            X.drop(col, axis=1, inplace=True)

# Remove columns with absurdly large values (to prevent overflow)
X = X.applymap(lambda v: 0 if isinstance(v, (int, float)) and (v > 1e12 or v < -1e12) else v)

# Encode target if needed
if y.dtype == "object":
    le_y = LabelEncoder()
    y = le_y.fit_transform(y)

# ------------------------- Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# ------------------------- Train model
clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)

# ------------------------- Evaluate
y_pred = clf.predict(X_test)
acc = accuracy_score(y_test, y_pred)
print(f"✅ Model accuracy on test set: {acc:.2f}")

# ------------------------- Save model
joblib.dump(clf, MODEL_PATH)
print(f"✅ Model trained and saved at {MODEL_PATH}")
