use as_inspect_core::{
    Analyzer, AnalyzerResult, AnalyzerStatus, EvidenceCategory, EvidenceConfidence, EvidenceItem,
    TargetKind, TargetMetadata,
};
use chrono::Utc;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use std::time::Instant;

pub struct HashAnalyzer;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct HashData {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

impl HashAnalyzer {
    pub fn compute_hashes<P: AsRef<Path>>(path: P) -> std::io::Result<HashData> {
        let file = File::open(path)?;
        let mut reader = BufReader::with_capacity(128 * 1024, file);

        let mut md5 = Md5::new();
        let mut sha1 = Sha1::new();
        let mut sha256 = Sha256::new();

        let mut buffer = [0u8; 64 * 1024];
        loop {
            let bytes_read = reader.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            md5.update(&buffer[..bytes_read]);
            sha1.update(&buffer[..bytes_read]);
            sha256.update(&buffer[..bytes_read]);
        }

        Ok(HashData {
            md5: hex::encode(md5.finalize()),
            sha1: hex::encode(sha1.finalize()),
            sha256: hex::encode(sha256.finalize()),
        })
    }
}

impl Analyzer for HashAnalyzer {
    fn name(&self) -> &'static str {
        "hash_analyzer"
    }

    fn description(&self) -> &'static str {
        "Computes cryptographic hashes (MD5, SHA-1, SHA-256) of target files"
    }

    fn can_analyze(&self, target: &TargetMetadata) -> bool {
        target.kind == TargetKind::File
    }

    fn analyze(&self, target: &TargetMetadata) -> AnalyzerResult {
        let start = Instant::now();
        match Self::compute_hashes(&target.path) {
            Ok(hashes) => {
                let now = Utc::now();
                let evidence = vec![
                    EvidenceItem {
                        id: "EV-HASH-MD5".to_string(),
                        r#type: "hash_md5".to_string(),
                        value: hashes.md5.clone(),
                        source: "file_body".to_string(),
                        location: "0..EOF".to_string(),
                        confidence: EvidenceConfidence::Certain,
                        category: EvidenceCategory::Observed,
                        analyzer: "hash_analyzer".to_string(),
                        timestamp: now,
                        details: None,
                    },
                    EvidenceItem {
                        id: "EV-HASH-SHA1".to_string(),
                        r#type: "hash_sha1".to_string(),
                        value: hashes.sha1.clone(),
                        source: "file_body".to_string(),
                        location: "0..EOF".to_string(),
                        confidence: EvidenceConfidence::Certain,
                        category: EvidenceCategory::Observed,
                        analyzer: "hash_analyzer".to_string(),
                        timestamp: now,
                        details: None,
                    },
                    EvidenceItem {
                        id: "EV-HASH-SHA256".to_string(),
                        r#type: "hash_sha256".to_string(),
                        value: hashes.sha256.clone(),
                        source: "file_body".to_string(),
                        location: "0..EOF".to_string(),
                        confidence: EvidenceConfidence::Certain,
                        category: EvidenceCategory::Observed,
                        analyzer: "hash_analyzer".to_string(),
                        timestamp: now,
                        details: None,
                    },
                ];

                AnalyzerResult {
                    analyzer: self.name().to_string(),
                    status: AnalyzerStatus::Success,
                    evidence,
                    warnings: Vec::new(),
                    errors: Vec::new(),
                    duration_ms: start.elapsed().as_millis() as u64,
                    data: Some(serde_json::to_value(&hashes).unwrap_or_default()),
                }
            }
            Err(e) => AnalyzerResult {
                analyzer: self.name().to_string(),
                status: AnalyzerStatus::Failed,
                evidence: Vec::new(),
                warnings: Vec::new(),
                errors: vec![format!("Failed to calculate hashes: {}", e)],
                duration_ms: start.elapsed().as_millis() as u64,
                data: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_hash_calculation() {
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(b"AS Inspect verification test").unwrap();
        tmp.flush().unwrap();

        let hashes = HashAnalyzer::compute_hashes(tmp.path()).unwrap();
        assert!(!hashes.md5.is_empty());
        assert_eq!(hashes.md5.len(), 32);
        assert_eq!(hashes.sha1.len(), 40);
        assert_eq!(hashes.sha256.len(), 64);
    }
}
