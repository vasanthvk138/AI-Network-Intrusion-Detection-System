import os
import sqlite3
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'database', 'logs.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        attack TEXT,
        timestamp TEXT
    )''')

    conn.commit()
    conn.close()

def log_to_db(ip, attack):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("INSERT INTO logs (ip, attack, timestamp) VALUES (?, ?, ?)",
              (ip, attack, str(datetime.now())))

    conn.commit()
    conn.close()