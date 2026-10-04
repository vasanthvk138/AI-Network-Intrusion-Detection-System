import pandas as pd
import joblib
import numpy as np
import os

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report, accuracy_score

# =========================
# 📂 PATH SETUP
# =========================
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 🔥 FORCE correct dataset path
data_path = os.path.join(BASE_DIR, 'data', 'final_dataset.csv')

model_dir = os.path.join(BASE_DIR, 'model')

print("📂 USING DATASET:", data_path)
print("📂 USING DATASET:", data_path)
print("📦 FILE SIZE (MB):", os.path.getsize(data_path) / (1024*1024))

# =========================
# 📊 LOAD DATASET
# =========================
df = pd.read_csv(data_path)

print("Initial shape:", df.shape)

# =========================
# 🧹 CLEANING
# =========================
df.columns = df.columns.str.strip()

# Fix label encoding issue
df['Label'] = df['Label'].astype(str)
df['Label'] = df['Label'].str.replace('�', '-', regex=False)
df['Label'] = df['Label'].str.strip()

# Standardize naming
df['Label'] = df['Label'].str.replace('Sql Injection', 'SQL Injection')

# Remove infinity
df.replace([np.inf, -np.inf], np.nan, inplace=True)

# Drop missing labels
df = df[df['Label'].notna()]

# Fill NaN
df.fillna(0, inplace=True)

print("After cleaning:", df.shape)

# 🔥 DEBUG: SHOW LABEL DISTRIBUTION
print("\n📊 LABEL DISTRIBUTION:\n")
print(df['Label'].value_counts())

# =========================
# 🔥 FEATURE ENGINEERING
# =========================
# =========================
# 🔥 MATCH CAPTURE FEATURES
# =========================

df['duration'] = df['Flow Duration']
df['packets'] = df['Total Fwd Packets'] + df['Total Backward Packets']
df['bytes'] = df['Total Length of Fwd Packets'] + df['Total Length of Bwd Packets']

df['mean_len'] = df['Packet Length Mean']
df['std_len'] = df['Packet Length Std']

df['fwd_packets'] = df['Total Fwd Packets']
df['bwd_packets'] = df['Total Backward Packets']

# =========================
# 🎯 FINAL FEATURES (MUST MATCH capture.py)
# =========================
feature_cols = [
    'duration',
    'packets',
    'bytes',
    'mean_len',
    'std_len',
    'fwd_packets',
    'bwd_packets'
]

X = df[feature_cols]
y = df['Label']

# =========================
# 🧠 ENCODE LABELS
# =========================
le = LabelEncoder()
y_encoded = le.fit_transform(y)

print("\n🎯 CLASSES:\n", list(le.classes_))

# =========================
# ⚖️ SCALING
# =========================
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# =========================
# 🔀 SPLIT
# =========================
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y_encoded, test_size=0.2, random_state=42
)

# =========================
# 🌲 MODEL
# =========================
model = RandomForestClassifier(
    n_estimators=120,
    max_depth=20,
    class_weight='balanced',   # 🔥 VERY IMPORTANT
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

# =========================
# 📊 EVALUATION
# =========================
y_pred = model.predict(X_test)

print("\n✅ Accuracy:", accuracy_score(y_test, y_pred))
print("\n📊 Classification Report:\n")
print(classification_report(y_test, y_pred, target_names=le.classes_))

# =========================
# 💾 SAVE
# =========================
os.makedirs(model_dir, exist_ok=True)

joblib.dump(model, os.path.join(model_dir, 'model.pkl'))
joblib.dump(scaler, os.path.join(model_dir, 'scaler.pkl'))
joblib.dump(le, os.path.join(model_dir, 'label_encoder.pkl'))
joblib.dump(feature_cols, os.path.join(model_dir, 'features.pkl'))

print("\n✅ Model trained & saved successfully")