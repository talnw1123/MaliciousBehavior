"""
Database module for storing scan history using SQLite
"""

import sqlite3
import json
import os
from datetime import datetime


class ScanDatabase:
    """SQLite database for storing scan history."""

    def __init__(self, db_path="scan_history.db"):
        """
        Initialize the database.

        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        """Get a database connection."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initialize the database schema."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                findings_count INTEGER NOT NULL,
                findings_json TEXT,
                scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()

    def save_scan(self, url, risk_level, risk_score, findings):
        """
        Save a scan result to the database.

        Args:
            url: The scanned URL
            risk_level: Risk level (LOW, MEDIUM, HIGH, CRITICAL)
            risk_score: Risk score (0-100)
            findings: List of findings
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO scan_history (url, risk_level, risk_score, findings_count, findings_json)
            VALUES (?, ?, ?, ?, ?)
        """, (url, risk_level, risk_score, len(findings), json.dumps(findings)))
        conn.commit()
        conn.close()

    def get_history(self, limit=50):
        """
        Get scan history.

        Args:
            limit: Maximum number of records to return

        Returns:
            list: List of scan history records
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, url, risk_level, risk_score, findings_count, scanned_at
            FROM scan_history
            ORDER BY scanned_at DESC
            LIMIT ?
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

    def get_scan_detail(self, scan_id):
        """
        Get detailed scan result by ID.

        Args:
            scan_id: The scan record ID

        Returns:
            dict: Scan detail with findings
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM scan_history WHERE id = ?
        """, (scan_id,))
        row = cursor.fetchone()
        conn.close()
        if row:
            result = dict(row)
            result["findings"] = json.loads(result["findings_json"])
            return result
        return None

    def delete_scan(self, scan_id):
        """
        Delete a scan record.

        Args:
            scan_id: The scan record ID
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_history WHERE id = ?", (scan_id,))
        conn.commit()
        conn.close()

    def clear_history(self):
        """Clear all scan history."""
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scan_history")
        conn.commit()
        conn.close()
