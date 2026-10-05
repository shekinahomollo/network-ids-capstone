import sqlite3
import time

DB_FILE = "ids_alerts.db"

def init_db():
    """Initializes the SQLite database table for storing alerts."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            status TEXT,
            anomaly_score REAL,
            pkt_rate REAL,
            byte_rate REAL,
            syn_ratio REAL,
            unique_dst_ips INTEGER
        )
    """)
    conn.commit()
    conn.close()

def log_alert(status, score, pkt_rate, byte_rate, syn_ratio, unique_ips):
    """Logs a single traffic event into the SQLite database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO alerts (timestamp, status, anomaly_score, pkt_rate, byte_rate, syn_ratio, unique_dst_ips)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, status, score, pkt_rate, byte_rate, syn_ratio, unique_ips))
    conn.commit()
    conn.close()

def get_recent_alerts(limit=50):
    """Fetches recent security log entries."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows

if __name__ == "__main__":
    init_db()
    print("[✓] SQLite database initialized successfully.")