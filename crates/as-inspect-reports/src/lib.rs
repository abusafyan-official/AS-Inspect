use as_inspect_core::AnalysisReport;

pub struct ReportGenerator;

impl ReportGenerator {
    pub fn to_json(report: &AnalysisReport) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(report)
    }

    pub fn to_markdown(report: &AnalysisReport) -> String {
        let mut md = String::new();

        md.push_str("# AS Inspect Technical Analysis Report\n\n");
        md.push_str("> Understand applications with evidence.\n\n");
        md.push_str("**Developer:** Developed by Abu Safyan\n\n");

        md.push_str("## 1. Executive Summary\n\n");
        md.push_str(&format!("- **Target:** `{}`\n", report.target.filename));
        md.push_str(&format!("- **Path:** `{}`\n", report.target.path));
        md.push_str(&format!("- **Size:** {} bytes\n", report.target.size_bytes));
        md.push_str(&format!("- **Analysis Started:** {}\n", report.target.created_at.map(|t| t.to_rfc3339()).unwrap_or_else(|| "N/A".to_string())));
        md.push_str(&format!("- **Total Evidence Collected:** {}\n\n", report.all_evidence.len()));

        md.push_str("## 2. File Information & Hashes\n\n");
        md.push_str("| Type | Value |\n|---|---|\n");
        for ev in &report.all_evidence {
            if ev.r#type.starts_with("hash_") {
                md.push_str(&format!("| {} | `{}` |\n", ev.r#type.replace("hash_", "").to_uppercase(), ev.value));
            }
        }
        md.push_str("\n");

        md.push_str("## 3. Architecture & Binary Characteristics\n\n");
        for ev in &report.all_evidence {
            if ev.r#type == "architecture" || ev.r#type == "entry_point" {
                md.push_str(&format!("- **{}:** {}\n", ev.r#type, ev.value));
            }
        }
        md.push_str("\n");

        md.push_str("## 4. Framework Detection\n\n");
        let mut fw_found = false;
        for ev in &report.all_evidence {
            if ev.r#type == "framework_detection" || ev.r#type == "framework_indicator" {
                md.push_str(&format!("- **[{}]** {} *(Source: {})*\n", ev.id, ev.value, ev.location));
                fw_found = true;
            }
        }
        if !fw_found {
            md.push_str("No specific application framework indicators were detected.\n");
        }
        md.push_str("\n");

        md.push_str("## 5. Imports & External Dependencies\n\n");
        for ev in &report.all_evidence {
            if ev.r#type == "import_dll" {
                md.push_str(&format!("- **DLL:** `{}`\n", ev.value));
            }
        }
        md.push_str("\n");

        md.push_str("## 6. Discovered URLs & Endpoints\n\n");
        let mut urls_found = false;
        for ev in &report.all_evidence {
            if ev.r#type == "url" {
                md.push_str(&format!("- [{}] `{}` (at `{}`)\n", ev.id, ev.value, ev.location));
                urls_found = true;
            }
        }
        if !urls_found {
            md.push_str("No clear external URLs observed in string analysis.\n");
        }
        md.push_str("\n");

        md.push_str("## 7. Evidence Ledger\n\n");
        md.push_str("| ID | Category | Type | Location | Confidence |\n|---|---|---|---|---|\n");
        for ev in &report.all_evidence {
            let cat = format!("{:?}", ev.category);
            let conf = format!("{:?}", ev.confidence);
            md.push_str(&format!("| {} | {} | {} | {} | {} |\n", ev.id, cat, ev.r#type, ev.location, conf));
        }
        md.push_str("\n");

        if let Some(ai) = &report.ai_analysis {
            md.push_str("## 8. AI-Generated Explanation\n\n");
            md.push_str(&format!("*Provider: {} (Model: {})*\n\n", ai.provider, ai.model));
            md.push_str(&ai.summary);
            md.push_str("\n\n");
            for item in &ai.answers {
                md.push_str(&format!("### {}\n\n{}\n\n*Citations: {:?}*\n\n", item.question, item.answer, item.evidence_ids));
            }
        }

        md.push_str("## 9. Limitations & Warnings\n\n");
        if report.limitations.is_empty() && report.warnings.is_empty() {
            md.push_str("- None noted during this analysis.\n");
        } else {
            for lim in &report.limitations {
                md.push_str(&format!("- [Limitation] {}\n", lim));
            }
            for w in &report.warnings {
                md.push_str(&format!("- [Warning] {}\n", w));
            }
        }

        md
    }

    pub fn to_html(report: &AnalysisReport) -> String {
        let md = Self::to_markdown(report);
        format!(
            r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AS Inspect Report - {}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; padding: 30px; max-width: 900px; margin: 0 auto; color: #1e293b; background: #f8fafc; }}
        h1, h2, h3 {{ color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; }}
        code {{ background: #e2e8f0; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 0.9em; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ border: 1px solid #cbd5e1; padding: 8px 12px; text-align: left; }}
        th {{ background: #f1f5f9; }}
        blockquote {{ border-left: 4px solid #3b82f6; margin: 0; padding-left: 12px; color: #64748b; }}
    </style>
</head>
<body>
    <pre style="white-space: pre-wrap; font-family: inherit;">{}</pre>
</body>
</html>"#,
            report.target.filename, md
        )
    }
}
