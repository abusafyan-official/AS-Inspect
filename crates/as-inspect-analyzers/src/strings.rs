use as_inspect_core::{
    Analyzer, AnalyzerResult, AnalyzerStatus, EvidenceCategory, EvidenceConfidence, EvidenceItem,
    TargetMetadata,
};
use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{BufReader, Read};
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringCategoryItem {
    pub category: String,
    pub value: String,
    pub location: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringsSummary {
    pub total_extracted: usize,
    pub urls: Vec<StringCategoryItem>,
    pub domains: Vec<StringCategoryItem>,
    pub file_paths: Vec<StringCategoryItem>,
    pub registry_paths: Vec<StringCategoryItem>,
    pub emails: Vec<StringCategoryItem>,
    pub sample_general: Vec<String>,
}

pub struct StringAnalyzer {
    pub min_length: usize,
    pub max_scan_bytes: usize,
}

impl Default for StringAnalyzer {
    fn default() -> Self {
        Self {
            min_length: 5,
            max_scan_bytes: 50 * 1024 * 1024, // 50MB limit for safe fast string scanning
        }
    }
}

impl StringAnalyzer {
    pub fn mask_potential_secrets(s: &str) -> String {
        // Safe pattern check for secret-like tokens
        // e.g., sk-..., AIza..., Bearer ..., standard 32+ hex/base64 tokens
        let re_sk = Regex::new(r"(sk-[a-zA-Z0-9]{10,})").unwrap();
        let re_gapi = Regex::new(r"(AIza[0-9A-Za-z-_]{35})").unwrap();

        let s1 = re_sk.replace_all(s, "sk-**************").to_string();
        let s2 = re_gapi.replace_all(&s1, "AIza**************").to_string();
        s2
    }

    pub fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<(usize, String)> {
        let mut result = Vec::new();
        let mut start_idx = 0;
        let mut current_bytes = Vec::new();

        for (i, &b) in data.iter().enumerate() {
            if (0x20..=0x7E).contains(&b) || b == b'\t' {
                if current_bytes.is_empty() {
                    start_idx = i;
                }
                current_bytes.push(b);
            } else {
                if current_bytes.len() >= min_len {
                    if let Ok(s) = String::from_utf8(current_bytes.clone()) {
                        result.push((start_idx, s));
                    }
                }
                current_bytes.clear();
            }
        }
        if current_bytes.len() >= min_len {
            if let Ok(s) = String::from_utf8(current_bytes) {
                result.push((start_idx, s));
            }
        }
        result
    }

    pub fn extract_utf16_strings(data: &[u8], min_len: usize) -> Vec<(usize, String)> {
        let mut result = Vec::new();
        let mut start_idx = 0;
        let mut current_chars = Vec::new();

        let mut i = 0;
        while i + 1 < data.len() {
            let u = u16::from_le_bytes([data[i], data[i + 1]]);
            if (0x0020..=0x007E).contains(&u) || u == 0x0009 {
                if current_chars.is_empty() {
                    start_idx = i;
                }
                current_chars.push(u);
            } else {
                if current_chars.len() >= min_len {
                    if let Ok(s) = String::from_utf16(&current_chars) {
                        result.push((start_idx, s));
                    }
                }
                current_chars.clear();
            }
            i += 2;
        }
        if current_chars.len() >= min_len {
            if let Ok(s) = String::from_utf16(&current_chars) {
                result.push((start_idx, s));
            }
        }
        result
    }
}

impl Analyzer for StringAnalyzer {
    fn name(&self) -> &'static str {
        "string_analyzer"
    }

    fn description(&self) -> &'static str {
        "Extracts and categorizes ASCII and UTF-16 strings (URLs, domains, paths, registry) with secret masking"
    }

    fn can_analyze(&self, target: &TargetMetadata) -> bool {
        target.kind == as_inspect_core::TargetKind::File
    }

    fn analyze(&self, target: &TargetMetadata) -> AnalyzerResult {
        let start = Instant::now();
        let file = match File::open(&target.path) {
            Ok(f) => f,
            Err(e) => {
                return AnalyzerResult {
                    analyzer: self.name().to_string(),
                    status: AnalyzerStatus::Failed,
                    evidence: Vec::new(),
                    warnings: Vec::new(),
                    errors: vec![format!("Failed to open file: {}", e)],
                    duration_ms: start.elapsed().as_millis() as u64,
                    data: None,
                };
            }
        };

        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();
        let mut take_reader = reader.take(self.max_scan_bytes as u64);
        if let Err(e) = take_reader.read_to_end(&mut buffer) {
            return AnalyzerResult {
                analyzer: self.name().to_string(),
                status: AnalyzerStatus::Failed,
                evidence: Vec::new(),
                warnings: Vec::new(),
                errors: vec![format!("Failed to read file buffer: {}", e)],
                duration_ms: start.elapsed().as_millis() as u64,
                data: None,
            };
        }

        let ascii_strings = Self::extract_ascii_strings(&buffer, self.min_length);
        let utf16_strings = Self::extract_utf16_strings(&buffer, self.min_length);

        let mut all_strings = ascii_strings;
        all_strings.extend(utf16_strings);

        // Regex categories
        let re_url = Regex::new(r"(?i)\bhttps?://[a-zA-Z0-9_\-.]+(?::[0-9]+)?(?:/[^\s<>\x22\x27]*)?").unwrap();
        let re_domain = Regex::new(r"(?i)\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|edu|gov|io|ai|dev|co|xyz|info|app|me)\b").unwrap();
        let re_win_path = Regex::new(r"(?i)[a-zA-Z]:\\[a-zA-Z0-9_\-\.\\]+").unwrap();
        let re_registry = Regex::new(r"(?i)\b(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKEY_CLASSES_ROOT|HKEY_USERS)\\[a-zA-Z0-9_\\\-]+").unwrap();
        let re_email = Regex::new(r"(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap();

        let mut urls = Vec::new();
        let mut domains = Vec::new();
        let mut file_paths = Vec::new();
        let mut reg_paths = Vec::new();
        let mut emails = Vec::new();
        let mut sample_general = Vec::new();

        let mut evidence = Vec::new();
        let now = Utc::now();

        for (offset, raw_str) in &all_strings {
            let safe_str = Self::mask_potential_secrets(raw_str);
            let loc = format!("Offset 0x{:X}", offset);

            if let Some(mat) = re_url.find(&safe_str) {
                let url_val = mat.as_str().to_string();
                urls.push(StringCategoryItem {
                    category: "URL".to_string(),
                    value: url_val.clone(),
                    location: loc.clone(),
                });
                if evidence.len() < 100 {
                    evidence.push(EvidenceItem {
                        id: format!("EV-STR-URL-{}", evidence.len() + 1),
                        r#type: "url".to_string(),
                        value: url_val,
                        source: "string_scan".to_string(),
                        location: loc.clone(),
                        confidence: EvidenceConfidence::High,
                        category: EvidenceCategory::Observed,
                        analyzer: self.name().to_string(),
                        timestamp: now,
                        details: None,
                    });
                }
            } else if let Some(mat) = re_registry.find(&safe_str) {
                let reg_val = mat.as_str().to_string();
                reg_paths.push(StringCategoryItem {
                    category: "Registry".to_string(),
                    value: reg_val.clone(),
                    location: loc.clone(),
                });
                if evidence.len() < 100 {
                    evidence.push(EvidenceItem {
                        id: format!("EV-STR-REG-{}", evidence.len() + 1),
                        r#type: "registry_key".to_string(),
                        value: reg_val,
                        source: "string_scan".to_string(),
                        location: loc.clone(),
                        confidence: EvidenceConfidence::High,
                        category: EvidenceCategory::Observed,
                        analyzer: self.name().to_string(),
                        timestamp: now,
                        details: None,
                    });
                }
            } else if let Some(mat) = re_win_path.find(&safe_str) {
                file_paths.push(StringCategoryItem {
                    category: "FilePath".to_string(),
                    value: mat.as_str().to_string(),
                    location: loc.clone(),
                });
            } else if let Some(mat) = re_email.find(&safe_str) {
                emails.push(StringCategoryItem {
                    category: "Email".to_string(),
                    value: mat.as_str().to_string(),
                    location: loc.clone(),
                });
            } else if let Some(mat) = re_domain.find(&safe_str) {
                domains.push(StringCategoryItem {
                    category: "Domain".to_string(),
                    value: mat.as_str().to_string(),
                    location: loc.clone(),
                });
            } else if sample_general.len() < 50 {
                sample_general.push(safe_str);
            }
        }

        let summary = StringsSummary {
            total_extracted: all_strings.len(),
            urls,
            domains,
            file_paths,
            registry_paths,
            emails,
            sample_general,
        };

        AnalyzerResult {
            analyzer: self.name().to_string(),
            status: AnalyzerStatus::Success,
            evidence,
            warnings: Vec::new(),
            errors: Vec::new(),
            duration_ms: start.elapsed().as_millis() as u64,
            data: Some(serde_json::to_value(&summary).unwrap_or_default()),
        }
    }
}
