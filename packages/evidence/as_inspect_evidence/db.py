import json
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from as_inspect_core import AnalysisReport, EvidenceItem

class EvidenceDatabase:
    def __init__(self, db_path: str = ":memory:"):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self.init_schema()

    def init_schema(self):
        cursor = self.conn.cursor()
        cursor.executescript(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                path TEXT NOT NULL,
                filename TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                file_type TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                report_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                analysis_id TEXT NOT NULL,
                evidence_id TEXT NOT NULL,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                source TEXT NOT NULL,
                location TEXT NOT NULL,
                confidence TEXT NOT NULL,
                category TEXT NOT NULL,
                analyzer TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                details_json TEXT
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        self.conn.commit()

    def save_report(self, report: AnalysisReport, raw_json: str) -> str:
        analysis_id = str(uuid.uuid4())
        target_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        cursor = self.conn.cursor()
        cursor.execute(
            """
            INSERT INTO targets (id, project_id, path, filename, size_bytes, file_type, created_at)
            VALUES (?, NULL, ?, ?, ?, ?, ?)
            """,
            (
                target_id,
                report.target.path,
                report.target.filename,
                report.target.size_bytes,
                report.target.detected_type.value,
                now,
            ),
        )

        cursor.execute(
            """
            INSERT INTO analyses (id, target_id, started_at, finished_at, report_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                analysis_id,
                target_id,
                report.started_at,
                report.finished_at,
                raw_json,
            ),
        )

        for ev in report.all_evidence:
            ev_uuid = str(uuid.uuid4())
            details = json.dumps(ev.details) if ev.details else None
            cursor.execute(
                """
                INSERT INTO evidence (id, analysis_id, evidence_id, type, value, source, location, confidence, category, analyzer, timestamp, details_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ev_uuid,
                    analysis_id,
                    ev.id,
                    ev.type,
                    ev.value,
                    ev.source,
                    ev.location,
                    ev.confidence.value,
                    ev.category.value,
                    ev.analyzer,
                    ev.timestamp,
                    details,
                ),
            )

        self.conn.commit()
        return analysis_id

    def get_total_analyses(self) -> int:
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM analyses")
        return cursor.fetchone()[0]

    def get_recent_analyses(self, limit: int = 10) -> List[Dict[str, Any]]:
        cursor = self.conn.cursor()
        cursor.execute(
            """
            SELECT a.id, t.filename, t.path, t.size_bytes, a.finished_at
            FROM analyses a
            JOIN targets t ON a.target_id = t.id
            ORDER BY a.finished_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        return [dict(r) for r in cursor.fetchall()]
