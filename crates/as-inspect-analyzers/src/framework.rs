use as_inspect_core::{
    Analyzer, AnalyzerResult, AnalyzerStatus, EvidenceCategory, EvidenceConfidence, EvidenceItem,
    TargetMetadata,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrameworkIndicator {
    pub framework: String,
    pub confidence: String,
    pub reasons: Vec<String>,
}

pub struct FrameworkDetector;

impl FrameworkDetector {
    pub fn detect_from_bytes(bytes: &[u8], filename: &str) -> Vec<FrameworkIndicator> {
        let mut results = Vec::new();
        let content_str = String::from_utf8_lossy(bytes);

        // Electron detection
        let mut electron_reasons = Vec::new();
        if content_str.contains("resources.pak") {
            electron_reasons.push("Found 'resources.pak' indicator".to_string());
        }
        if content_str.contains("app.asar") {
            electron_reasons.push("Found 'app.asar' indicator".to_string());
        }
        if content_str.contains("ELECTRON_RUN_AS_NODE") {
            electron_reasons.push("Found ELECTRON_RUN_AS_NODE environment flag".to_string());
        }
        if content_str.contains("Chrome/\\d+") || content_str.contains("Chromium") {
            electron_reasons.push("Found Chromium user-agent/resource strings".to_string());
        }

        if !electron_reasons.is_empty() {
            let conf = if electron_reasons.len() >= 2 { "High" } else { "Medium" };
            results.push(FrameworkIndicator {
                framework: "Electron".to_string(),
                confidence: conf.to_string(),
                reasons: electron_reasons,
            });
        }

        // .NET detection
        let mut dotnet_reasons = Vec::new();
        if content_str.contains("mscorlib.dll") {
            dotnet_reasons.push("References mscorlib.dll".to_string());
        }
        if content_str.contains("System.Runtime") {
            dotnet_reasons.push("References System.Runtime (.NET Core / 5+)".to_string());
        }
        if content_str.contains("_CorExeMain") || content_str.contains("_CorDllMain") {
            dotnet_reasons.push("Uses CLR entrypoint _CorExeMain / _CorDllMain".to_string());
        }

        if !dotnet_reasons.is_empty() {
            let conf = if dotnet_reasons.len() >= 2 { "High" } else { "Medium" };
            results.push(FrameworkIndicator {
                framework: ".NET".to_string(),
                confidence: conf.to_string(),
                reasons: dotnet_reasons,
            });
        }

        // Python detection
        let mut python_reasons = Vec::new();
        if content_str.contains("python3.dll") || content_str.contains("python310.dll") || content_str.contains("python311.dll") || content_str.contains("python312.dll") {
            python_reasons.push("Bundles Python shared library DLL".to_string());
        }
        if content_str.contains("PyInstaller") || content_str.contains("MEI") {
            python_reasons.push("Contains PyInstaller loader markers".to_string());
        }

        if !python_reasons.is_empty() {
            results.push(FrameworkIndicator {
                framework: "Python (Frozen/Bundled)".to_string(),
                confidence: "High".to_string(),
                reasons: python_reasons,
            });
        }

        // Qt detection
        if content_str.contains("Qt5Core.dll") || content_str.contains("Qt6Core.dll") || content_str.contains("QApplication") {
            results.push(FrameworkIndicator {
                framework: "Qt Framework".to_string(),
                confidence: "High".to_string(),
                reasons: vec!["References Qt runtime libraries/symbols".to_string()],
            });
        }

        // Java detection
        if content_str.contains("jvm.dll") || filename.ends_with(".jar") {
            results.push(FrameworkIndicator {
                framework: "Java / JVM".to_string(),
                confidence: "High".to_string(),
                reasons: vec!["References JVM launcher or library".to_string()],
            });
        }

        results
    }
}

impl Analyzer for FrameworkDetector {
    fn name(&self) -> &'static str {
        "framework_detector"
    }

    fn description(&self) -> &'static str {
        "Detects runtime frameworks (Electron, .NET, Python, Qt, JVM) from evidence"
    }

    fn can_analyze(&self, target: &TargetMetadata) -> bool {
        target.kind == as_inspect_core::TargetKind::File
    }

    fn analyze(&self, target: &TargetMetadata) -> AnalyzerResult {
        let start = Instant::now();
        let bytes = match fs::read(&target.path) {
            Ok(b) => b,
            Err(e) => {
                return AnalyzerResult {
                    analyzer: self.name().to_string(),
                    status: AnalyzerStatus::Failed,
                    evidence: Vec::new(),
                    warnings: Vec::new(),
                    errors: vec![format!("Failed to read target file: {}", e)],
                    duration_ms: start.elapsed().as_millis() as u64,
                    data: None,
                };
            }
        };

        let filename = Path::new(&target.path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("");

        let indicators = Self::detect_from_bytes(&bytes, filename);
        let mut evidence = Vec::new();
        let now = Utc::now();

        for ind in &indicators {
            evidence.push(EvidenceItem {
                id: format!("EV-FW-{}", ind.framework.replace(' ', "_")),
                r#type: "framework_detection".to_string(),
                value: format!("{} (Confidence: {})", ind.framework, ind.confidence),
                source: "binary_analysis".to_string(),
                location: "content_strings_and_imports".to_string(),
                confidence: if ind.confidence == "High" {
                    EvidenceConfidence::High
                } else {
                    EvidenceConfidence::Medium
                },
                category: EvidenceCategory::Inferred,
                analyzer: self.name().to_string(),
                timestamp: now,
                details: Some(serde_json::to_value(&ind.reasons).unwrap_or_default()),
            });
        }

        AnalyzerResult {
            analyzer: self.name().to_string(),
            status: AnalyzerStatus::Success,
            evidence,
            warnings: Vec::new(),
            errors: Vec::new(),
            duration_ms: start.elapsed().as_millis() as u64,
            data: Some(serde_json::to_value(&indicators).unwrap_or_default()),
        }
    }
}
