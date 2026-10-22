use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    File,
    Folder,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SupportedFileType {
    PeExe,
    PeDll,
    Msi,
    Asar,
    JavaScript,
    Json,
    Folder,
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetMetadata {
    pub path: String,
    pub filename: String,
    pub size_bytes: u64,
    pub kind: TargetKind,
    pub detected_type: SupportedFileType,
    pub created_at: Option<DateTime<Utc>>,
    pub modified_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceConfidence {
    Low,
    Medium,
    High,
    Certain,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCategory {
    Observed,
    Inferred,
    AiGeneratedExplanation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub id: String,
    pub r#type: String,
    pub value: String,
    pub source: String,
    pub location: String,
    pub confidence: EvidenceConfidence,
    pub category: EvidenceCategory,
    pub analyzer: String,
    pub timestamp: DateTime<Utc>,
    #[serde(default)]
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnalyzerStatus {
    Success,
    Partial,
    Skipped,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzerResult {
    pub analyzer: String,
    pub status: AnalyzerStatus,
    pub evidence: Vec<EvidenceItem>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub duration_ms: u64,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub target: TargetMetadata,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub results: Vec<AnalyzerResult>,
    pub all_evidence: Vec<EvidenceItem>,
    pub warnings: Vec<String>,
    pub limitations: Vec<String>,
    pub ai_analysis: Option<AiAnalysisOutput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAnalysisOutput {
    pub provider: String,
    pub model: String,
    pub summary: String,
    pub answers: Vec<AiAnswerItem>,
    pub cited_evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAnswerItem {
    pub question: String,
    pub answer: String,
    pub evidence_ids: Vec<String>,
}

pub trait Analyzer: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn can_analyze(&self, target: &TargetMetadata) -> bool;
    fn analyze(&self, target: &TargetMetadata) -> AnalyzerResult;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_serialization() {
        let ev = EvidenceItem {
            id: "EV-000001".to_string(),
            r#type: "hash_sha256".to_string(),
            value: "abcdef123456".to_string(),
            source: "hash_analyzer".to_string(),
            location: "file_body".to_string(),
            confidence: EvidenceConfidence::Certain,
            category: EvidenceCategory::Observed,
            analyzer: "hash_analyzer".to_string(),
            timestamp: Utc::now(),
            details: None,
        };

        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("EV-000001"));
        assert!(json.contains("observed"));
    }
}
