from flask import Flask, render_template, request
import sqlite3
import subprocess
import os
import time

app = Flask(__name__)

# ✅ Absolute base directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
db_path = os.path.join(BASE_DIR, 'database', 'logs.db')

# =========================
# 🏠 HOME PAGE
# =========================
@app.route('/')
def home():
    print("🏠 HOME ROUTE HIT")
    return render_template('index.html')


# =========================
# 🚀 START MONITORING
# =========================
@app.route('/start', methods=['POST'])
def start():

    ip = request.form.get('ip')

    try:

        if ip:
            print(f"🚀 Starting capture for IP: {ip}")

            subprocess.Popen(
                ["python", "src/capture.py", ip]
            )

        else:
            print("🚀 Starting full network capture")

            subprocess.Popen(
                ["python", "src/capture.py"]
            )

        return render_template(
            "monitoring.html",
            ip=ip
        )

    except Exception as e:

        print("❌ Error starting capture:", e)

        return str(e)
# =========================
# 📊 DASHBOARD
# =========================
@app.route('/dashboard')
def dashboard():
    print("🔥 DASHBOARD ROUTE HIT")

    try:
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()

            # 📋 Logs
            cursor.execute("SELECT * FROM logs ORDER BY id DESC")
            data = cursor.fetchall()

            # 📊 Attack counts
            cursor.execute("""
                SELECT attack, COUNT(*) 
                FROM logs 
                GROUP BY attack
            """)
            counts = cursor.fetchall()

            # 🧠 Top attacker IP
            cursor.execute("""
                SELECT ip, COUNT(*) as c 
                FROM logs 
                GROUP BY ip 
                ORDER BY c DESC 
                LIMIT 1
            """)
            top_ip = cursor.fetchone()

        print("DATA:", data[:5])
        print("COUNTS:", counts)
        print("TOP IP:", top_ip)

    except Exception as e:
        print("❌ ERROR:", e)
        data, counts, top_ip = [], [], None

    return render_template(
        'dashboard.html',
        data=data,
        counts=counts,
        top_ip=top_ip
    )

# =========================
# 🧪 TEST ROUTE
# =========================
@app.route('/test')
def test():
    print("✅ TEST ROUTE WORKING")
    return "Test OK"


# =========================
# ▶️ RUN APP
# =========================
if __name__ == "__main__":
    print("🚀 Starting Flask App...")
    print("📂 Database path:", db_path)
    app.run(debug=False)