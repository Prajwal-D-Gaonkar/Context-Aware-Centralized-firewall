# manager/auth_db.py
import sqlite3
import os

DB_FILE = os.path.join(os.path.dirname(__file__), "auth.db")

def get_auth_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_auth_db():
    conn = get_auth_db()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()
