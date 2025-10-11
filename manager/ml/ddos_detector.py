import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score
import joblib
import os

BASE_DIR = os.path.dirname(__file__)
CSV_PATH = os.path.join(BASE_DIR, "5percent_NetBIOS.csv") 
MODEL_PATH = os.path.join(BASE_DIR, "ddos_model.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "ddos_features.npy")
ENCODERS_PATH = os.path.join(BASE_DIR, "ddos_encoders.pkl") 

if not os.path.exists(CSV_PATH):
    df = pd.DataFrame({
        'Flow Duration': np.random.randint(100, 10000, 10),
        'Src IP': ['192.168.1.1']*7 + ['10.0.0.1']*3,
        'Dst Port': [80, 443, 80, 21, 53, 80, 443, 80, 53, 443],
        'Protocol': [6, 6, 6, 17, 17, 6, 6, 6, 17, 6],
        'Packet Length Max': np.random.randint(50, 1500, 10),
        'Flow ID': ['1.1-2.2-80-443-6']*7 + ['3.3-4.4-21-53-17']*3,
        'Label': ['BENIGN'] * 7 + ['DDOS'] * 3
    })
else:
    df = pd.read_csv(CSV_PATH, low_memory=False)

df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.fillna(0, inplace=True)
if "Label" not in df.columns:
    raise ValueError("Dataset must contain 'Label' column.")

X = df.drop("Label", axis=1)
y = df["Label"]
label_encoders = {}

for col in X.columns:
    if X[col].dtype == "object" or X[col].nunique() < 50:
        X[col] = X[col].astype(str)
        le = LabelEncoder()
        X[col] = le.fit_transform(X[col])
        label_encoders[col] = le

if y.dtype == "object":
    le_y = LabelEncoder()
    y = le_y.fit_transform(y)
    label_encoders["Label"] = le_y
    if 'DDOS' in le_y.classes_:
        ddos_encoded_value = le_y.transform(['DDOS'])[0]
        if ddos_encoded_value == 0:
            y = 1 - y
            print("✅ DDoS label corrected to 1")

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
clf = RandomForestClassifier(n_estimators=500, random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)
print(f"✅ DDoS model accuracy: {accuracy_score(y_test, y_pred):.4f}")

joblib.dump(clf, MODEL_PATH)
np.save(FEATURES_PATH, list(X.columns), allow_pickle=True)
joblib.dump(label_encoders, ENCODERS_PATH)
print("💾 DDoS model, features, and encoders saved.")
