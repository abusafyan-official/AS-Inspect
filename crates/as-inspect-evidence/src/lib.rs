use as_inspect_core::{AnalysisReport, EvidenceItem};
use chrono::Utc;
use rusqlite::{params, Connection, Result};
use std::path::Path;

pub struct EvidenceDatabase {
    conn: Connection,
}

impl EvidenceDatabase {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let db = Self { conn };
        db.init_schema()?;
        Ok(db)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
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
                created_at TEXT NOT NULL,
                FOREIGN KEY(project_id) REFERENCES projects(id)
            );

            CREATE TABLE IF NOT EXISTS analyses (
                id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                report_json TEXT NOT NULL,
                FOREIGN KEY(target_id) REFERENCES targets(id)
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
                details_json TEXT,
                FOREIGN KEY(analysis_id) REFERENCES analyses(id)
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    pub fn save_report(&self, report: &AnalysisReport) -> Result<String> {
        let analysis_id = uuid::Uuid::new_v4().to_string();
        let target_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();

        self.conn.execute(
            "INSERT INTO targets (id, project_id, path, filename, size_bytes, file_type, created_at)
             VALUES (?1, NULL, ?2, ?3, ?4, ?5, ?6)",
            params![
                target_id,
                report.target.path,
                report.target.filename,
                report.target.size_bytes as i64,
                serde_json::to_string(&report.target.detected_type).unwrap_or_default(),
                now
            ],
        )?;

        let report_json = serde_json::to_string(report).unwrap_or_default();
        self.conn.execute(
            "INSERT INTO analyses (id, target_id, started_at, finished_at, report_json)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                analysis_id,
                target_id,
                report.started_at.to_rfc3339(),
                report.finished_at.to_rfc3339(),
                report_json
            ],
        )?;

        let mut stmt = self.conn.prepare(
            "INSERT INTO evidence (id, analysis_id, evidence_id, type, value, source, location, confidence, category, analyzer, timestamp, details_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"
        )?;

        for ev in &report.all_evidence {
            let row_id = uuid::Uuid::new_v4().to_string();
            let conf = serde_json::to_string(&ev.confidence).unwrap_or_default();
            let cat = serde_json::to_string(&ev.category).unwrap_or_default();
            let details = ev.details.as_ref().map(|d| d.to_string());
            stmt.execute(params![
                row_id,
                analysis_id,
                ev.id,
                ev.r#type,
                ev.value,
                ev.source,
                ev.location,
                conf,
                cat,
                ev.analyzer,
                ev.timestamp.to_rfc3339(),
                details
            ])?;
        }

        Ok(analysis_id)
    }

    pub fn get_recent_analyses(&self, limit: usize) -> Result<Vec<(String, String, String, i64, String)>> {
        let mut stmt = self.conn.prepare(
            "SELECT a.id, t.filename, t.path, t.size_bytes, a.finished_at 
             FROM analyses a
             JOIN targets t ON a.target_id = t.id
             ORDER BY a.finished_at DESC
             LIMIT ?1"
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        })?;

        let mut results = Vec::new();
        for r in rows {
            results.push(r?);
        }
        Ok(results)
    }

    pub fn get_total_analyses_count(&self) -> Result<i64> {
        let mut stmt = self.conn.prepare("SELECT COUNT(*) FROM analyses")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count)
    }

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let mut stmt = self.conn.prepare("SELECT value FROM settings WHERE key = ?1")?;
        let mut rows = stmt.query(params![key])?;
        if let Some(row) = rows.next()? {
            Ok(Some(row.get(0)?))
        } else {
            Ok(None)
        }
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        self.conn.execute(
            "INSERT INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(key) DO UPDATE SET value = ?2, updated_at = ?3",
            params![key, value, now],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use as_inspect_core::*;

    #[test]
    fn test_evidence_db_in_memory() {
        let db = EvidenceDatabase::in_memory().unwrap();
        let target = TargetMetadata {
            path: "C:\\test\\app.exe".to_string(),
            filename: "app.exe".to_string(),
            size_bytes: 1024,
            kind: TargetKind::File,
            detected_type: SupportedFileType::PeExe,
            created_at: None,
            modified_at: None,
        };

        let report = AnalysisReport {
            target,
            started_at: Utc::now(),
            finished_at: Utc::now(),
            results: vec![],
            all_evidence: vec![EvidenceItem {
                id: "EV-000001".to_string(),
                r#type: "test".to_string(),
                value: "val".to_string(),
                source: "source".to_string(),
                location: "loc".to_string(),
                confidence: EvidenceConfidence::Certain,
                category: EvidenceCategory::Observed,
                analyzer: "test".to_string(),
                timestamp: Utc::now(),
                details: None,
            }],
            warnings: vec![],
            limitations: vec![],
            ai_analysis: None,
        };

        let id = db.save_report(&report).unwrap();
        assert!(!id.is_empty());
        let count = db.get_total_analyses_count().unwrap();
        assert_eq!(count, 1);
    }
}
