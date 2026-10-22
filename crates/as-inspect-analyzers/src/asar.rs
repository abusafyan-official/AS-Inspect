use as_inspect_core::{
    Analyzer, AnalyzerResult, AnalyzerStatus, EvidenceCategory, EvidenceConfidence, EvidenceItem,
    TargetMetadata,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsarFileInfo {
    pub path: String,
    pub size: u64,
    pub offset: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsarInspectionReport {
    pub total_files: usize,
    pub total_size: u64,
    pub files: Vec<AsarFileInfo>,
    pub extension_counts: HashMap<String, usize>,
}

pub struct AsarAnalyzer;

impl AsarAnalyzer {
    // ASAR Header format:
    // [4 bytes: 0x04 0x00 0x00 0x00]
    // [4 bytes: header_size + 4]
    // [4 bytes: header_size]
    // [4 bytes: header_json_size]
    // [header_json_size bytes: JSON header tree]
    pub fn parse_asar_header(path: &str) -> Result<AsarInspectionReport, String> {
        let mut file = File::open(path).map_err(|e| format!("Failed to open ASAR: {}", e))?;

        let mut magic = [0u8; 16];
        file.read_exact(&mut magic)
            .map_err(|e| format!("Invalid ASAR header size: {}", e))?;

        if u32::from_le_bytes([magic[0], magic[1], magic[2], magic[3]]) != 4 {
            return Err("Not a valid ASAR file (magic mismatch)".to_string());
        }

        let json_size = u32::from_le_bytes([magic[12], magic[13], magic[14], magic[15]]) as usize;
        let mut json_buf = vec![0u8; json_size];
        file.read_exact(&mut json_buf)
            .map_err(|e| format!("Failed to read ASAR header JSON: {}", e))?;

        let header_json: serde_json::Value = serde_json::from_slice(&json_buf)
            .map_err(|e| format!("Failed to parse ASAR JSON directory: {}", e))?;

        let mut files = Vec::new();
        let mut ext_counts = HashMap::new();

        Self::walk_asar_tree(&header_json, "", &mut files, &mut ext_counts);

        let total_size = files.iter().map(|f| f.size).sum();
        let total_files = files.len();

        Ok(AsarInspectionReport {
            total_files,
            total_size,
            files,
            extension_counts: ext_counts,
        })
    }

    fn walk_asar_tree(
        node: &serde_json::Value,
        current_path: &str,
        files: &mut Vec<AsarFileInfo>,
        ext_counts: &mut HashMap<String, usize>,
    ) {
        if let Some(files_map) = node.get("files").and_then(|f| f.as_object()) {
            for (name, item) in files_map {
                let path = if current_path.is_empty() {
                    name.clone()
                } else {
                    format!("{}/{}", current_path, name)
                };

                if item.get("files").is_some() {
                    Self::walk_asar_tree(item, &path, files, ext_counts);
                } else {
                    let size = item.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
                    let offset = item.get("offset").and_then(|o| {
                        if let Some(num) = o.as_u64() {
                            Some(num)
                        } else if let Some(s) = o.as_str() {
                            s.parse::<u64>().ok()
                        } else {
                            None
                        }
                    });

                    let ext = std::path::Path::new(name)
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("no_ext")
                        .to_lowercase();
                    *ext_counts.entry(ext).or_insert(0) += 1;

                    files.push(AsarFileInfo {
                        path,
                        size,
                        offset,
                    });
                }
            }
        }
    }
}

impl Analyzer for AsarAnalyzer {
    fn name(&self) -> &'static str {
        "asar_analyzer"
    }

    fn description(&self) -> &'static str {
        "Parses Electron ASAR packages to extract file structure, scripts, and assets safely"
    }

    fn can_analyze(&self, target: &TargetMetadata) -> bool {
        target.path.to_lowercase().ends_with(".asar")
    }

    fn analyze(&self, target: &TargetMetadata) -> AnalyzerResult {
        let start = Instant::now();
        match Self::parse_asar_header(&target.path) {
            Ok(report) => {
                let now = Utc::now();
                let evidence = vec![
                    EvidenceItem {
                        id: "EV-ASAR-DETECT".to_string(),
                        r#type: "asar_archive".to_string(),
                        value: format!("Electron ASAR Package: {} files, {} bytes total", report.total_files, report.total_size),
                        source: "asar_header".to_string(),
                        location: "Header -> files".to_string(),
                        confidence: EvidenceConfidence::Certain,
                        category: EvidenceCategory::Observed,
                        analyzer: self.name().to_string(),
                        timestamp: now,
                        details: Some(serde_json::to_value(&report.extension_counts).unwrap_or_default()),
                    },
                ];

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
            Err(e) => AnalyzerResult {
                analyzer: self.name().to_string(),
                status: AnalyzerStatus::Failed,
                evidence: Vec::new(),
                warnings: Vec::new(),
                errors: vec![e],
                duration_ms: start.elapsed().as_millis() as u64,
                data: None,
            },
        }
    }
}
