"""
Security Alert Management Module for NETGUARD AI
Persists alerts, severity, and investigation notes into SQLite database.
"""

import sqlite3
import os
import pandas as pd
from datetime import datetime


def init_db(db_path: str):
    """
    Initializes SQLite tables for alerts and notes.
    """
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        timestamp TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        source_port INTEGER,
        destination_port INTEGER,
        protocol TEXT,
        predicted_category TEXT,
        severity TEXT,
        status TEXT,
        confidence REAL,
        detection_reason TEXT,
        packet_count INTEGER,
        byte_count INTEGER,
        flow_rate REAL
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS investigation_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id TEXT,
        author TEXT,
        timestamp TEXT,
        note_text TEXT,
        status_change TEXT,
        FOREIGN KEY (alert_id) REFERENCES alerts(id)
    );
    """)

    conn.commit()
    conn.close()


def sync_alerts_from_predictions(predictions_df: pd.DataFrame, db_path: str) -> int:
    """
    Inserts newly detected suspicious flows into the SQLite database.
    Avoids duplicate entries.
    """
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # Get existing alert IDs
    cur.execute("SELECT id FROM alerts")
    existing_ids = {row[0] for row in cur.fetchall()}

    new_count = 0
    sus_rows = predictions_df[predictions_df["Predicted_Label"] == "SUSPICIOUS"]

    for idx, row in sus_rows.iterrows():
        alert_id = f"ALT-2026-{idx+1:04d}"
        if alert_id in existing_ids:
            continue

        ts = str(row.get("Timestamp", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")))
        src_ip = str(row.get("Source_IP", "192.168.1.100"))
        dst_ip = str(row.get("Destination_IP", "192.168.1.1"))
        src_port = int(row.get("Source_Port", 49152))
        dst_port = int(row.get("Destination_Port", 80))
        proto = str(row.get("Protocol", "TCP"))
        cat = str(row.get("Attack_Category", "Unknown Anomaly"))
        sev = str(row.get("Severity", "MEDIUM"))
        conf = float(row.get("Confidence", 0.85))
        reason = str(row.get("Detection_Reason", "Suspicious traffic signature detected by ML model."))
        pkts = int(row.get("Packet_Count", 1))
        bytes_cnt = int(row.get("Byte_Count", 60))
        rate = float(row.get("Flow_Rate", 0.0))

        cur.execute("""
        INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'New', ?, ?, ?, ?, ?)
        """, (alert_id, ts, src_ip, dst_ip, src_port, dst_port, proto, cat, sev, conf, reason, pkts, bytes_cnt, rate))

        # Add initial engine note
        cur.execute("""
        INSERT INTO investigation_notes (alert_id, author, timestamp, note_text, status_change)
        VALUES (?, 'Detection Engine', ?, ?, 'New')
        """, (alert_id, ts, f"Alert created by ML classifier. Assigned {sev} severity based on flow metrics."))

        existing_ids.add(alert_id)
        new_count += 1

    conn.commit()
    conn.close()
    return new_count


def get_all_alerts(db_path: str) -> pd.DataFrame:
    """
    Fetches all alerts from SQLite database.
    """
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    df = pd.read_sql_query("SELECT * FROM alerts ORDER BY timestamp DESC", conn)
    conn.close()
    return df


def update_alert_status(db_path: str, alert_id: str, new_status: str, note_text: str, author: str = "Junior SOC Analyst"):
    """
    Updates an alert's status and logs an investigation note.
    """
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("UPDATE alerts SET status = ? WHERE id = ?", (new_status, alert_id))

    if note_text:
        cur.execute("""
        INSERT INTO investigation_notes (alert_id, author, timestamp, note_text, status_change)
        VALUES (?, ?, datetime('now'), ?, ?)
        """, (alert_id, author, note_text, new_status))

    conn.commit()
    conn.close()


def get_investigation_notes(db_path: str, alert_id: str) -> list[dict]:
    """
    Retrieves all investigation notes for a specific alert.
    """
    init_db(db_path)
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("""
    SELECT author, timestamp, note_text, status_change 
    FROM investigation_notes 
    WHERE alert_id = ? 
    ORDER BY id ASC
    """, (alert_id,))
    notes = [
        {"author": r[0], "timestamp": r[1], "note": r[2], "status_change": r[3]}
        for r in cur.fetchall()
    ]
    conn.close()
    return notes
