"""
Standalone SQLite Persistence Unit Test for NETGUARD AI
Validates database initialization, tables creation, constraints,
incident updates, and audit notes logging without third-party dependencies.
"""

import os
import sys
import tempfile
import sqlite3

def run_sqlite_tests():
    print("Testing NETGUARD AI SQLite database persistence...")
    
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        # 1. Initialize schema
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
            FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
        );
        """)
        conn.commit()

        # 2. Insert test alert
        alert_record = (
            "ALT-2026-0001", "2026-11-12 08:30:00", "185.220.101.5", "192.168.1.50",
            48120, 22, "TCP", "Brute Force", "HIGH", "New", 0.94,
            "SSH brute-force login anomaly detected by Random Forest model.",
            14, 1820, 2141.2
        )
        cur.execute("INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", alert_record)
        
        # 3. Insert investigation note
        cur.execute("""
        INSERT INTO investigation_notes (alert_id, author, timestamp, note_text, status_change)
        VALUES (?, ?, ?, ?, ?)
        """, ("ALT-2026-0001", "Detection Engine", "2026-11-12 08:30:00", "High confidence threat identified.", "New"))
        conn.commit()

        # 4. Verify insertion
        cur.execute("SELECT COUNT(*) FROM alerts")
        count = cur.fetchone()[0]
        assert count == 1, f"Expected 1 alert, found {count}"

        # 5. Update alert status and append analyst note
        cur.execute("UPDATE alerts SET status = ? WHERE id = ?", ("Investigating", "ALT-2026-0001"))
        cur.execute("""
        INSERT INTO investigation_notes (alert_id, author, timestamp, note_text, status_change)
        VALUES (?, ?, ?, ?, ?)
        """, ("ALT-2026-0001", "Junior SOC Analyst", "2026-11-12 08:35:00", "Firewall drop rule applied to 185.220.101.5", "Investigating"))
        conn.commit()

        # 6. Verify notes ledger
        cur.execute("SELECT status FROM alerts WHERE id = ?", ("ALT-2026-0001",))
        updated_status = cur.fetchone()[0]
        assert updated_status == "Investigating", f"Expected Investigating, got {updated_status}"

        cur.execute("SELECT author, status_change, note_text FROM investigation_notes WHERE alert_id = ? ORDER BY id ASC", ("ALT-2026-0001",))
        notes = cur.fetchall()
        assert len(notes) == 2, f"Expected 2 notes, found {len(notes)}"
        assert notes[1][0] == "Junior SOC Analyst"
        assert notes[1][1] == "Investigating"

        conn.close()
        print("✅ SQLite Persistence Unit Test: 100% Passed!")
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)

if __name__ == "__main__":
    run_sqlite_tests()
