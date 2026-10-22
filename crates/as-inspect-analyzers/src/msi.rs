use as_inspect_core::{
    Analyzer, AnalyzerResult, AnalyzerStatus, EvidenceCategory, EvidenceConfidence, EvidenceItem,
    TargetMetadata,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::Read;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MsiInspectionReport {
    pub is_valid_ole: bool,
    pub detected_streams: Vec<String>,
}

pub struct MsiAnalyzer;

impl Analyzer for MsiAnalyzer {
    fn name(&self) -> &'static str {
        "msi_analyzer"
    }

    fn description(&self) -> &'static str {
        "Analyzes Microsoft Windows Installer (MSI) Compound File Binary format structures"
    }

    fn can_analyze(&self, target: &TargetMetadata) -> bool {
        target.path.to_lowercase().ends_with(".msi")
    }

    fn analyze(&self, target: &TargetMetadata) -> AnalyzerResult {
        let start = Instant::now();
        let mut file = match File::open(&target.path) {
            Ok(f) => f,
            Err(e) => {
                return AnalyzerResult {
                    analyzer: self.name().to_string(),
                    status: AnalyzerStatus::Failed,
                    evidence: Vec::new(),
                    warnings: Vec::new(),
                    errors: vec![format!("Failed to open MSI: {}", e)],
                    duration_ms: start.elapsed().as_millis() as u64,
                    data: None,
                };
            }
        };

        let mut header = [0u8; 8];
        if let Err(e) = file.read_exact(&mut header) {
            return AnalyzerResult {
                analyzer: self.name().to_string(),
                status: AnalyzerStatus::Failed,
                evidence: Vec::new(),
                warnings: Vec::new(),
                errors: vec![format!("Failed to read MSI header: {}", e)],
                duration_ms: start.elapsed().as_millis() as u64,
                data: None,
            };
        }

        // OLE Compound File header magic: D0 CF 11 E0 A1 B1 1A E1
        let is_ole = header == [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

        let now = Utc::now();
        let mut evidence = Vec::new();

        if is_ole {
            evidence.push(EvidenceItem {
                id: "EV-MSI-OLE-MAGIC".to_string(),
                r#type: "installer_package".to_string(),
                value: "Valid Microsoft Windows Installer Compound Binary File (MSI)".to_string(),
                source: "file_header".to_string(),
                location: "0x00000000".to_string(),
                confidence: EvidenceConfidence::Certain,
                category: EvidenceCategory::Observed,
                analyzer: self.name().to_string(),
                timestamp: now,
                details: None,
            });
        }

        let report = MsiInspectionReport {
            is_valid_ole: is_ole,
            detected_streams: Vec::new(),
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
