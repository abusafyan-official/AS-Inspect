use as_inspect_core::{
    Analyzer, AnalyzerResult, AnalyzerStatus, EvidenceCategory, EvidenceConfidence, EvidenceItem,
    TargetMetadata,
};
use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsAnalysisReport {
    pub total_lines: usize,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub function_names: Vec<String>,
    pub detected_urls: Vec<String>,
    pub package_dependencies: Vec<String>,
}

pub struct JavaScriptAnalyzer;

impl Analyzer for JavaScriptAnalyzer {
    fn name(&self) -> &'static str {
        "javascript_analyzer"
    }

    fn description(&self) -> &'static str {
        "Performs static analysis of JavaScript/TypeScript files: imports, exports, functions, and external endpoints"
    }

    fn can_analyze(&self, target: &TargetMetadata) -> bool {
        let p = target.path.to_lowercase();
        p.ends_with(".js") || p.ends_with(".mjs") || p.ends_with(".cjs") || p.ends_with(".ts")
    }

    fn analyze(&self, target: &TargetMetadata) -> AnalyzerResult {
        let start = Instant::now();
        let content = match fs::read_to_string(&target.path) {
            Ok(c) => c,
            Err(e) => {
                return AnalyzerResult {
                    analyzer: self.name().to_string(),
                    status: AnalyzerStatus::Failed,
                    evidence: Vec::new(),
                    warnings: Vec::new(),
                    errors: vec![format!("Failed to read JS file: {}", e)],
                    duration_ms: start.elapsed().as_millis() as u64,
                    data: None,
                };
            }
        };

        let total_lines = content.lines().count();

        let re_require = Regex::new(r#"(?m)require\(\s*['"]([^'"]+)['"]\s*\)"#).unwrap();
        let re_import = Regex::new(r#"(?m)import\s+(?:[^'"]+\s+from\s+)?['"]([^'"]+)['"]"#).unwrap();
        let re_func = Regex::new(r#"(?m)function\s+([a-zA-Z0-9_$]+)\s*\("#).unwrap();
        let re_export = Regex::new(r#"(?m)export\s+(?:default\s+)?(?:class|function|const|let|var)\s+([a-zA-Z0-9_$]+)"#).unwrap();
        let re_url = Regex::new(r#"(?i)\bhttps?://[a-zA-Z0-9_\-.]+(?::[0-9]+)?(?:/[^\s<>\x22\x27]*)?"#).unwrap();

        let mut imports = Vec::new();
        for cap in re_require.captures_iter(&content) {
            imports.push(cap[1].to_string());
        }
        for cap in re_import.captures_iter(&content) {
            imports.push(cap[1].to_string());
        }

        let mut exports = Vec::new();
        for cap in re_export.captures_iter(&content) {
            exports.push(cap[1].to_string());
        }

        let mut functions = Vec::new();
        for cap in re_func.captures_iter(&content) {
            functions.push(cap[1].to_string());
        }

        let mut urls = Vec::new();
        for mat in re_url.find_iter(&content) {
            urls.push(mat.as_str().to_string());
        }

        let mut evidence = Vec::new();
        let now = Utc::now();

        if !imports.is_empty() {
            evidence.push(EvidenceItem {
                id: "EV-JS-IMPORTS".to_string(),
                r#type: "javascript_dependencies".to_string(),
                value: format!("Found {} import/require dependencies", imports.len()),
                source: "static_js_ast".to_string(),
                location: "Top-level script".to_string(),
                confidence: EvidenceConfidence::Certain,
                category: EvidenceCategory::Observed,
                analyzer: self.name().to_string(),
                timestamp: now,
                details: Some(serde_json::to_value(&imports).unwrap_or_default()),
            });
        }

        let report = JsAnalysisReport {
            total_lines,
            imports,
            exports,
            function_names: functions,
            detected_urls: urls,
            package_dependencies: Vec::new(),
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
