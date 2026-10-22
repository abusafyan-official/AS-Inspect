use as_inspect_core::{
    Analyzer, AnalyzerResult, AnalyzerStatus, EvidenceCategory, EvidenceConfidence, EvidenceItem,
    TargetMetadata,
};
use chrono::Utc;
use goblin::pe::PE;
use serde::{Deserialize, Serialize};
use std::fs;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSectionInfo {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_data_size: u32,
    pub entropy: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeImportInfo {
    pub dll: String,
    pub functions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeAnalysisData {
    pub is_64_bit: bool,
    pub architecture: String,
    pub machine: u16,
    pub entry_point: u64,
    pub image_base: u64,
    pub subsystem: u16,
    pub compile_timestamp: u32,
    pub sections: Vec<PeSectionInfo>,
    pub imports: Vec<PeImportInfo>,
    pub exports: Vec<String>,
    pub is_dotnet: bool,
}

pub struct PeAnalyzer;

impl PeAnalyzer {
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        let mut occurrences = [0usize; 256];
        for &byte in data {
            occurrences[byte as usize] += 1;
        }
        let len = data.len() as f64;
        let mut entropy = 0.0;
        for &count in &occurrences {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        entropy
    }
}

impl Analyzer for PeAnalyzer {
    fn name(&self) -> &'static str {
        "pe_analyzer"
    }

    fn description(&self) -> &'static str {
        "Parses Windows Portable Executable (EXE/DLL) headers, sections, imports, and exports"
    }

    fn can_analyze(&self, target: &TargetMetadata) -> bool {
        let ext = std::path::Path::new(&target.path)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        ext == "exe" || ext == "dll" || ext == "sys" || ext == "ocx"
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
                    errors: vec![format!("Failed to read file: {}", e)],
                    duration_ms: start.elapsed().as_millis() as u64,
                    data: None,
                };
            }
        };

        match PE::parse(&bytes) {
            Ok(pe) => {
                let mut evidence = Vec::new();
                let now = Utc::now();

                let arch = if pe.is_64 {
                    "x64".to_string()
                } else if pe.header.coff_header.machine == 0x014c {
                    "x86".to_string()
                } else if pe.header.coff_header.machine == 0xaa64 {
                    "ARM64".to_string()
                } else if pe.header.coff_header.machine == 0x01c0 || pe.header.coff_header.machine == 0x01c4 {
                    "ARM".to_string()
                } else {
                    format!("Machine: 0x{:04x}", pe.header.coff_header.machine)
                };

                evidence.push(EvidenceItem {
                    id: "EV-PE-ARCH".to_string(),
                    r#type: "architecture".to_string(),
                    value: arch.clone(),
                    source: "pe_header".to_string(),
                    location: "COFF Header -> Machine".to_string(),
                    confidence: EvidenceConfidence::Certain,
                    category: EvidenceCategory::Observed,
                    analyzer: self.name().to_string(),
                    timestamp: now,
                    details: None,
                });

                evidence.push(EvidenceItem {
                    id: "EV-PE-ENTRY".to_string(),
                    r#type: "entry_point".to_string(),
                    value: format!("0x{:X}", pe.entry),
                    source: "pe_header".to_string(),
                    location: "Optional Header -> AddressOfEntryPoint".to_string(),
                    confidence: EvidenceConfidence::Certain,
                    category: EvidenceCategory::Observed,
                    analyzer: self.name().to_string(),
                    timestamp: now,
                    details: None,
                });

                let mut sections = Vec::new();
                for sec in &pe.sections {
                    let sec_name = sec.name().unwrap_or("").to_string();
                    let start_offset = sec.pointer_to_raw_data as usize;
                    let end_offset = start_offset + sec.size_of_raw_data as usize;
                    let entropy = if start_offset < bytes.len() && end_offset <= bytes.len() {
                        Self::calculate_entropy(&bytes[start_offset..end_offset])
                    } else {
                        0.0
                    };

                    evidence.push(EvidenceItem {
                        id: format!("EV-PE-SEC-{}", sec_name.trim_matches('\0')),
                        r#type: "section".to_string(),
                        value: format!("{} (Entropy: {:.2}, Size: {} bytes)", sec_name, entropy, sec.size_of_raw_data),
                        source: "pe_section_table".to_string(),
                        location: format!("Offset 0x{:X}", sec.pointer_to_raw_data),
                        confidence: EvidenceConfidence::Certain,
                        category: EvidenceCategory::Observed,
                        analyzer: self.name().to_string(),
                        timestamp: now,
                        details: Some(serde_json::json!({
                            "virtual_address": sec.virtual_address,
                            "virtual_size": sec.virtual_size,
                            "raw_size": sec.size_of_raw_data,
                            "entropy": entropy
                        })),
                    });

                    sections.push(PeSectionInfo {
                        name: sec_name,
                        virtual_address: sec.virtual_address,
                        virtual_size: sec.virtual_size,
                        raw_data_size: sec.size_of_raw_data,
                        entropy,
                    });
                }

                // Check for .NET CLR runtime header
                let is_dotnet = pe.header.optional_header.map(|opt| {
                    if let Some(clr_dir) = opt.data_directories.get_clr_runtime_header() {
                        clr_dir.virtual_address > 0
                    } else {
                        false
                    }
                }).unwrap_or(false);

                if is_dotnet {
                    evidence.push(EvidenceItem {
                        id: "EV-PE-DOTNET".to_string(),
                        r#type: "framework_indicator".to_string(),
                        value: ".NET Framework / CLR Header Present".to_string(),
                        source: "pe_optional_header".to_string(),
                        location: "DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]".to_string(),
                        confidence: EvidenceConfidence::Certain,
                        category: EvidenceCategory::Observed,
                        analyzer: self.name().to_string(),
                        timestamp: now,
                        details: None,
                    });
                }

                let mut imports_data = Vec::new();
                for imp in &pe.imports {
                    let dll_name = imp.dll.to_string();
                    let func_name = imp.name.to_string();

                    if let Some(existing) = imports_data.iter_mut().find(|i: &&mut PeImportInfo| i.dll.eq_ignore_ascii_case(&dll_name)) {
                        existing.functions.push(func_name);
                    } else {
                        imports_data.push(PeImportInfo {
                            dll: dll_name,
                            functions: vec![func_name],
                        });
                    }
                }

                for imp in &imports_data {
                    evidence.push(EvidenceItem {
                        id: format!("EV-PE-IMP-{}", imp.dll),
                        r#type: "import_dll".to_string(),
                        value: format!("{} ({} functions)", imp.dll, imp.functions.len()),
                        source: "pe_import_table".to_string(),
                        location: "Import Directory".to_string(),
                        confidence: EvidenceConfidence::Certain,
                        category: EvidenceCategory::Observed,
                        analyzer: self.name().to_string(),
                        timestamp: now,
                        details: Some(serde_json::to_value(&imp.functions).unwrap_or_default()),
                    });
                }

                let mut exports_data = Vec::new();
                for exp in &pe.exports {
                    if let Some(exp_name) = exp.name {
                        exports_data.push(exp_name.to_string());
                        evidence.push(EvidenceItem {
                            id: format!("EV-PE-EXP-{}", exp_name),
                            r#type: "export_symbol".to_string(),
                            value: exp_name.to_string(),
                            source: "pe_export_table".to_string(),
                            location: format!("RVA: 0x{:X}", exp.rva),
                            confidence: EvidenceConfidence::Certain,
                            category: EvidenceCategory::Observed,
                            analyzer: self.name().to_string(),
                            timestamp: now,
                            details: None,
                        });
                    }
                }

                let opt = pe.header.optional_header;
                let data = PeAnalysisData {
                    is_64_bit: pe.is_64,
                    architecture: arch,
                    machine: pe.header.coff_header.machine,
                    entry_point: pe.entry as u64,
                    image_base: opt.map(|o| o.windows_fields.image_base).unwrap_or(0),
                    subsystem: opt.map(|o| o.windows_fields.subsystem).unwrap_or(0),
                    compile_timestamp: pe.header.coff_header.time_date_stamp,
                    sections,
                    imports: imports_data,
                    exports: exports_data,
                    is_dotnet,
                };

                AnalyzerResult {
                    analyzer: self.name().to_string(),
                    status: AnalyzerStatus::Success,
                    evidence,
                    warnings: Vec::new(),
                    errors: Vec::new(),
                    duration_ms: start.elapsed().as_millis() as u64,
                    data: Some(serde_json::to_value(&data).unwrap_or_default()),
                }
            }
            Err(e) => AnalyzerResult {
                analyzer: self.name().to_string(),
                status: AnalyzerStatus::Failed,
                evidence: Vec::new(),
                warnings: Vec::new(),
                errors: vec![format!("Invalid or unsupported PE structure: {}", e)],
                duration_ms: start.elapsed().as_millis() as u64,
                data: None,
            },
        }
    }
}
