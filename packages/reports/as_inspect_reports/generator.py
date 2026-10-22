import json
from dataclasses import asdict
from as_inspect_core import AnalysisReport

class ReportGenerator:
    @staticmethod
    def to_json(report: AnalysisReport) -> str:
        data = asdict(report)
        return json.dumps(data, indent=2, default=str)

    @staticmethod
    def to_markdown(report: AnalysisReport) -> str:
        lines = [
            "# AS Inspect Technical Analysis Report",
            "",
            "> Understand applications with evidence.",
            "",
            "**Developer:** Developed by Abu Safyan",
            "",
            "## 1. Executive Summary",
            f"- **Target:** `{report.target.filename}`",
            f"- **Path:** `{report.target.path}`",
            f"- **Size:** {report.target.size_bytes} bytes",
            f"- **Target Kind:** {report.target.kind.value}",
            f"- **Detected Format:** {report.target.detected_type.value}",
            f"- **Analysis Started:** {report.started_at}",
            f"- **Total Evidence Gathered:** {len(report.all_evidence)}",
            "",
            "## 2. Cryptographic Hashes",
            "| Algorithm | Value |",
            "|---|---|",
        ]

        for ev in report.all_evidence:
            if ev.type.startswith("hash_"):
                algo = ev.type.replace("hash_", "").upper()
                lines.append(f"| {algo} | `{ev.value}` |")

        lines.extend([
            "",
            "## 3. Architecture & Binary Attributes",
        ])
        for ev in report.all_evidence:
            if ev.type in ["architecture", "entry_point", "section"]:
                lines.append(f"- **[{ev.id}]** {ev.type.replace('_', ' ').capitalize()}: {ev.value} *(at {ev.location})*")

        lines.extend([
            "",
            "## 4. Framework Detection",
        ])
        fw_found = False
        for ev in report.all_evidence:
            if ev.type in ["framework_detection", "framework_indicator"]:
                lines.append(f"- **[{ev.id}]** {ev.value} *(Source: {ev.source})*")
                fw_found = True
        if not fw_found:
            lines.append("No specific application framework indicators were detected.")

        lines.extend([
            "",
            "## 5. Imports & Dependencies",
        ])
        for ev in report.all_evidence:
            if ev.type in ["import_dll", "javascript_dependencies"]:
                lines.append(f"- **[{ev.id}]** `{ev.value}`")

        lines.extend([
            "",
            "## 6. URLs & Discovered Endpoints",
        ])
        urls_found = False
        for ev in report.all_evidence:
            if ev.type == "url":
                lines.append(f"- **[{ev.id}]** `{ev.value}` *(Location: {ev.location})*")
                urls_found = True
        if not urls_found:
            lines.append("No network URLs observed in analyzed sections.")

        lines.extend([
            "",
            "## 7. Structured Evidence Ledger",
            "| ID | Category | Type | Value | Confidence |",
            "|---|---|---|---|---|",
        ])
        for ev in report.all_evidence:
            lines.append(f"| {ev.id} | {ev.category.value} | {ev.type} | `{ev.value[:60]}` | {ev.confidence.value} |")

        if report.ai_analysis:
            lines.extend([
                "",
                "## 8. AI-Generated Explanation",
                f"*Provider: {report.ai_analysis.provider} ({report.ai_analysis.model})*",
                "",
                report.ai_analysis.summary,
                "",
            ])
            for ans in report.ai_analysis.answers:
                lines.append(f"### {ans.question}\n\n{ans.answer}\n\n*Cited Evidence: {', '.join(ans.evidence_ids)}*\n")

        lines.extend([
            "",
            "## 9. Limitations & Warnings",
        ])
        if not report.limitations and not report.warnings:
            lines.append("- None noted.")
        else:
            for lim in report.limitations:
                lines.append(f"- [Limitation] {lim}")
            for w in report.warnings:
                lines.append(f"- [Warning] {w}")

        return "\n".join(lines)

    @staticmethod
    def to_html(report: AnalysisReport) -> str:
        md = ReportGenerator.to_markdown(report)
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AS Inspect Report - {report.target.filename}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; line-height: 1.6; padding: 30px; max-width: 900px; margin: 0 auto; color: #1e293b; background: #f8fafc; }}
        h1, h2, h3 {{ color: #0f172a; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; }}
        code {{ background: #e2e8f0; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 0.9em; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ border: 1px solid #cbd5e1; padding: 8px 12px; text-align: left; }}
        th {{ background: #f1f5f9; }}
        blockquote {{ border-left: 4px solid #3b82f6; margin: 0; padding-left: 12px; color: #64748b; }}
    </style>
</head>
<body>
    <pre style="white-space: pre-wrap; font-family: inherit;">{md}</pre>
</body>
</html>"""
