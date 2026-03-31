"""
init_db.py

Responsibilities:
- Initialize SQLite database
- Create analysis_history table if it does not exist
"""

from __future__ import annotations

import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "history.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS analysis_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analyzed_at TEXT NOT NULL,
            raw_input TEXT NOT NULL,
            input_type TEXT,
            language_hint TEXT,
            urls TEXT,
            risk_score INTEGER,
            risk_level TEXT,
            flags TEXT,
            reasons TEXT,
            summary TEXT,
            recommendations TEXT,
            full_result TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS analysis_feedback (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            feedback TEXT NOT NULL,
            comment TEXT,
            submitted_at TEXT NOT NULL,
            FOREIGN KEY (analysis_id) REFERENCES analysis_history(id)
        )
        """
    )

    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Database initialized at: {DB_PATH}")
