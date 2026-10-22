use as_inspect_core::{
    Analyzer, AnalyzerResult, AnalyzerStatus, EvidenceCategory, EvidenceConfidence, EvidenceItem,
    TargetKind, TargetMetadata,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderAnalysisReport {
    pub total_files: usize,
    pub total_dirs: usize,
    pub total_size_bytes: u64,
    pub extension_distribution: HashMap<String, usize>,
    pub key_files_found: Vec<String>,
}

pub struct FolderAnalyzer;

impl Analyzer for FolderAnalyzer {
    fn name(&self) -> &'static str {
        "folder_analyzer"
    }

    fn description(&self) -> &'static str {
        "Scans application directory structures, detects package manifests, binaries, and configurations"
    }

    fn can_analyze(&self, target: &TargetMetadata) -> bool {
        target.kind == TargetKind::Folder || Path::new(&target.path).is_dir()
    }

    fn analyze(&self, target: &TargetMetadata) -> AnalyzerResult {
        let start = Instant::now();
        let mut total_files = 0;
        let mut total_dirs = 0;
        let mut total_size_bytes = 0u64;
        let mut extension_distribution = HashMap::new();
        let mut key_files_found = Vec::new();

        for entry in WalkDir::new(&target.path).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_dir() {
                total_dirs += 1;
            } else if entry.file_type().is_file() {
                total_files += 1;
                if let Ok(meta) = entry.metadata() {
                    total_size_bytes += meta.len();
                }

                let fname = entry.file_name().to_string_lossy().to_string();
                let lower_name = fname.to_lowercase();

                if lower_name == "package.json"
                    || lower_name == "app.asar"
                    || lower_name.ends_with(".exe")
                    || lower_name.ends_with(".dll")
                    || lower_name == "electron.exe"
                    || lower_name.ends_with(".config")
                {
                    key_files_found.push(entry.path().to_string_lossy().to_string());
                }

                if let Some(ext) = entry.path().extension().and_then(|e| e.to_str()) {
                    *extension_distribution.entry(ext.to_lowercase()).or_insert(0) += 1;
                }
            }
        }

        let now = Utc::now();
        let mut evidence = Vec::new();

        evidence.push(EvidenceItem {
            id: "EV-DIR-SCAN".to_string(),
            r#type: "directory_structure".to_string(),
            value: format!(
                "Folder contains {} files and {} directories ({} bytes total)",
                total_files, total_dirs, total_size_bytes
            ),
            source: "filesystem_walk".to_string(),
            location: target.path.clone(),
            confidence: EvidenceConfidence::Certain,
            category: EvidenceCategory::Observed,
            analyzer: self.name().to_string(),
            timestamp: now,
            details: Some(serde_json::to_value(&key_files_found).unwrap_or_default()),
        });

        let report = FolderAnalysisReport {
            total_files,
            total_dirs,
            total_size_bytes,
            extension_distribution,
            key_files_found,
        };

        AnalyzerResult {
            analyzer: self.name().to_string(),
            status: AnalyzerStatus::Success,
            evidence,
            warnings: Vec::new(),
            errors: Vec::new(),
            duration_ms: start.elapsed().as_millis() as u64,
            data: Some(serde_json::to_value(&report).unwrap_or_default()),
        }
    }
}
