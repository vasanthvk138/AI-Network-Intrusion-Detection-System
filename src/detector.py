from alert import send_alert
import joblib
import pandas as pd
import os
import sqlite3
from datetime import datetime
import numpy as np

# =========================
# 📂 PATH SETUP
# =========================
BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

model_path = os.path.join(
    BASE_DIR,
    "model",
    "model.pkl"
)

scaler_path = os.path.join(
    BASE_DIR,
    "model",
    "scaler.pkl"
)

le_path = os.path.join(
    BASE_DIR,
    "model",
    "label_encoder.pkl"
)

features_path = os.path.join(
    BASE_DIR,
    "model",
    "features.pkl"
)

db_path = os.path.join(
    BASE_DIR,
    "database",
    "logs.db"
)

# =========================
# 🔄 LOAD MODEL
# =========================
print(f"✅ Loading model from: {model_path}")

model = joblib.load(model_path)
scaler = joblib.load(scaler_path)
le = joblib.load(le_path)

feature_names = joblib.load(features_path)

EXPECTED_FEATURES = len(feature_names)

# =========================
# 🚨 ALERT MEMORY
# =========================
alerted_ips = set()

# =========================
# 🔍 PREDICTION FUNCTION
# =========================
def predict(features, ip, force_label=None):

    try:

        # =========================
        # 🛠️ FIX FEATURE SIZE
        # =========================
        features = list(features)

        if len(features) < EXPECTED_FEATURES:

            features.extend(
                [0] * (EXPECTED_FEATURES - len(features))
            )

        features = features[:EXPECTED_FEATURES]

        # =========================
        # 📊 DATAFRAME
        # =========================
        df = pd.DataFrame(
            [features],
            columns=feature_names
        )

        # =========================
        # ⚖️ SCALE FEATURES
        # =========================
        scaled = scaler.transform(df)

        # =========================
        # 🤖 MODEL PREDICTION
        # =========================
        pred = model.predict(scaled)

        proba = model.predict_proba(scaled)

        label = le.inverse_transform(pred)[0]

        confidence = float(np.max(proba))

        # =========================
        # 🚨 FORCE LABEL
        # =========================
        if force_label:

            label = force_label

        # =========================
        # 🚨 RULE-BASED DETECTION
        # =========================
        try:

            packets = features[1]

            # Apply rules ONLY if no force label
            if not force_label:

                # PORTSCAN
                if packets > 300:

                    label = "PortScan"

                # DDOS
                elif packets > 150:

                    label = "DDoS"

                # BRUTE FORCE
                elif packets > 50:

                    label = "BruteForce"

        except Exception as rule_error:

            print(
                "⚠️ Rule Detection Error:",
                rule_error
            )

        # =========================
        # 💾 SAVE TO DATABASE
        # =========================
        with sqlite3.connect(db_path) as conn:

            conn.execute(
                """
                INSERT INTO logs (
                    ip,
                    attack,
                    timestamp
                )
                VALUES (?, ?, ?)
                """,
                (
                    ip,
                    label,
                    datetime.now().isoformat()
                )
            )

            conn.commit()

        # =========================
        # 🚨 ALERT HANDLING
        # =========================
        if label != "BENIGN":

            print(
                f"🚨 ALERT: {ip} → {label} ({confidence:.2f})"
            )

            # Prevent duplicate emails
            if ip not in alerted_ips:

                try:

                    send_alert(ip, label)

                    alerted_ips.add(ip)

                    print(
                        f"📧 Email alert sent for {label}"
                    )

                except Exception as email_error:

                    print(
                        "❌ Email alert failed:",
                        email_error
                    )

        else:

            print(f"🔍 ML: {ip} → {label}")

        return label

    except Exception as e:

        print("❌ Prediction error:", e)

        return "ERROR"