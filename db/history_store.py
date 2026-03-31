"""
history_store.py

Responsibilities:
- Save analysis results into SQLite
- Read analysis history from SQLite
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "history.db"


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def save_analysis(result: Dict[str, Any]) -> int:
    pre = result.get("preprocessed", {})
    rule_result = result.get("rule_result", {})
    score_result = result.get("score_result", {})
    explanation_result = result.get("explanation_result", {})
    recommendation_result = result.get("recommendation_result", {})

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO analysis_history (
            analyzed_at,
            raw_input,
            input_type,
            language_hint,
            urls,
            risk_score,
            risk_level,
            flags,
            reasons,
            summary,
            recommendations,
            full_result
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            result.get("analyzed_at", ""),
            pre.get("raw_text", ""),
            pre.get("input_type", ""),
            pre.get("language_hint", ""),
            json.dumps(pre.get("urls", []), ensure_ascii=False),
            score_result.get("risk_score", 0),
            score_result.get("risk_level", "low"),
            json.dumps(rule_result.get("flags", []), ensure_ascii=False),
            json.dumps(rule_result.get("reasons", []), ensure_ascii=False),
            explanation_result.get("summary", ""),
            json.dumps(
                recommendation_result.get("recommendations", []), ensure_ascii=False
            ),
            json.dumps(result, ensure_ascii=False),
        ),
    )

    conn.commit()
    row_id = cursor.lastrowid
    conn.close()
    return row_id


def get_recent_history(limit: int = 20) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            analyzed_at,
            raw_input,
            input_type,
            language_hint,
            urls,
            risk_score,
            risk_level,
            flags,
            reasons,
            summary,
            recommendations
        FROM analysis_history
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )

    rows = cursor.fetchall()
    conn.close()

    results = []
    for row in rows:
        results.append(dict(row))
    return results


def get_analysis_by_id(record_id: int) -> Dict[str, Any] | None:
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT full_result
        FROM analysis_history
        WHERE id = ?
        """,
        (record_id,),
    )

    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    return json.loads(row["full_result"])


def save_feedback(analysis_id: int, feedback: str, comment: str = "") -> None:
    """
    Save user feedback for an analysis result.

    feedback: 'correct' | 'wrong_too_high' | 'wrong_too_low'
    comment: optional free-text note
    """
    from datetime import datetime

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO analysis_feedback (analysis_id, feedback, comment, submitted_at)
        VALUES (?, ?, ?, ?)
        """,
        (
            analysis_id,
            feedback,
            comment,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )

    conn.commit()
    conn.close()
