use crate::asar::AsarAnalyzer;
use crate::folder::FolderAnalyzer;
use crate::framework::FrameworkDetector;
use crate::hashing::HashAnalyzer;
use crate::javascript::JavaScriptAnalyzer;
use crate::msi::MsiAnalyzer;
use crate::pe::PeAnalyzer;
use crate::strings::StringAnalyzer;
use as_inspect_core::{AnalysisReport, Analyzer, AnalyzerResult, TargetKind, TargetMetadata, SupportedFileType};
use chrono::Utc;
use std::fs;
use std::path::Path;

pub struct AnalysisPipeline {
    analyzers: Vec<Box<dyn Analyzer>>,
}

impl Default for AnalysisPipeline {
    fn default() -> Self {
        Self::new()
    }
}

impl AnalysisPipeline {
    pub fn new() -> Self {
        let analyzers: Vec<Box<dyn Analyzer>> = vec![
            Box::new(HashAnalyzer),
            Box::new(PeAnalyzer),
            Box::new(FrameworkDetector),
            Box::new(StringAnalyzer::default()),
            Box::new(AsarAnalyzer),
            Box::new(JavaScriptAnalyzer),
            Box::new(MsiAnalyzer),
            Box::new(FolderAnalyzer),
        ];

        Self { analyzers }
    }

    pub fn inspect_target<P: AsRef<Path>>(&self, path: P) -> std::io::Result<AnalysisReport> {
        let p = path.as_ref();
        let metadata = fs::metadata(p)?;
        let started_at = Utc::now();

        let is_dir = metadata.is_dir();
        let filename = p.file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("")
            .to_string();

        let ext = p.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();

        let detected_type = if is_dir {
            SupportedFileType::Folder
        } else {
            match ext.as_str() {
                "exe" => SupportedFileType::PeExe,
                "dll" => SupportedFileType::PeDll,
                "msi" => SupportedFileType::Msi,
                "asar" => SupportedFileType::Asar,
                "js" | "mjs" | "cjs" => SupportedFileType::JavaScript,
                "json" => SupportedFileType::Json,
                _ => SupportedFileType::Unknown(ext),
            }
        };

        let target_meta = TargetMetadata {
            path: p.to_string_lossy().to_string(),
            filename,
            size_bytes: metadata.len(),
            kind: if is_dir { TargetKind::Folder } else { TargetKind::File },
            detected_type,
            created_at: metadata.created().ok().map(|t| t.into()),
            modified_at: metadata.modified().ok().map(|t| t.into()),
        };

        let mut results = Vec::new();
        let mut all_evidence = Vec::new();
        let mut warnings = Vec::new();
        let mut limitations = Vec::new();

        for analyzer in &self.analyzers {
            if analyzer.can_analyze(&target_meta) {
                let res = analyzer.analyze(&target_meta);
                for ev in &res.evidence {
                    all_evidence.push(ev.clone());
                }
                for w in &res.warnings {
                    warnings.push(w.clone());
                }
                results.push(res);
            }
        }

        if all_evidence.is_empty() {
            limitations.push("No evidence could be gathered with available analyzers for this file type.".to_string());
        }

        let finished_at = Utc::now();

        Ok(AnalysisReport {
            target: target_meta,
            started_at,
            finished_at,
            results,
            all_evidence,
            warnings,
            limitations,
            ai_analysis: None,
        })
    }
}
