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

        # Authenticode and Packer status
        lines.extend([
            "",
            "## 4. Digital Signatures & Packing Status",
        ])
        sig_or_packer_found = False
        for ev in report.all_evidence:
            if ev.type in ["authenticode_signature", "packer_signature"]:
                lines.append(f"- **[{ev.id}]** {ev.value} *(Source: {ev.source})*")
                sig_or_packer_found = True
        if not sig_or_packer_found:
            lines.append("No Authenticode directory or known packer signatures detected.")

        # Behavioral & Security Capabilities
        lines.extend([
            "",
            "## 5. Security Capabilities & Behavior Matrix",
        ])
        caps_found = False
        for ev in report.all_evidence:
            if ev.type == "security_capability":
                lines.append(f"- **[{ev.id}]** {ev.value}")
                caps_found = True
        if not caps_found:
            lines.append("No specific high-level security capabilities mapped.")

        lines.extend([
            "",
            "## 6. Framework Detection",
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
            "## 7. Imports & Dependencies",
        ])
        for ev in report.all_evidence:
            if ev.type in ["import_dll", "javascript_dependencies"]:
                lines.append(f"- **[{ev.id}]** `{ev.value}`")

        lines.extend([
            "",
            "## 8. URLs & Discovered Endpoints",
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
            "## 9. Structured Evidence Ledger",
            "| ID | Category | Type | Value | Confidence |",
            "|---|---|---|---|---|",
        ])
        for ev in report.all_evidence:
            lines.append(f"| {ev.id} | {ev.category.value} | {ev.type} | `{ev.value[:60]}` | {ev.confidence.value} |")

        if report.ai_analysis:
            lines.extend([
                "",
                "## 10. AI-Generated Explanation",
                f"*Provider: {report.ai_analysis.provider} ({report.ai_analysis.model})*",
                "",
                report.ai_analysis.summary,
                "",
            ])
            for ans in report.ai_analysis.answers:
                lines.append(f"### {ans.question}\n\n{ans.answer}\n\n*Cited Evidence: {', '.join(ans.evidence_ids)}*\n")

        lines.extend([
            "",
            "## 11. Limitations & Warnings",
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
        report_json = ReportGenerator.to_json(report)
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AS Inspect - {report.target.filename}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{
            --bg: #090d16;
            --surface: #111827;
            --surface-card: #1f2937;
            --border: #374151;
            --text-main: #f3f4f6;
            --text-muted: #9ca3af;
            --primary: #3b82f6;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --purple: #8b5cf6;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg);
            color: var(--text-main);
            font-family: 'Inter', sans-serif;
            line-height: 1.5;
            padding: 32px 16px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 24px;
            margin-bottom: 32px;
        }}
        .brand h1 {{
            font-size: 28px;
            font-weight: 700;
            background: linear-gradient(135deg, #60a5fa, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }}
        .brand p {{
            color: var(--text-muted);
            font-size: 14px;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }}
        .badge-blue {{ background: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.4); }}
        .badge-green {{ background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.4); }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
            margin-bottom: 32px;
        }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
        }}
        .card h3 {{
            font-size: 13px;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 8px;
        }}
        .card .value {{
            font-size: 20px;
            font-weight: 700;
            color: #fff;
            word-break: break-all;
        }}
        .search-box {{
            margin-bottom: 20px;
            display: flex;
            gap: 12px;
        }}
        .search-box input {{
            flex: 1;
            background: var(--surface);
            border: 1px solid var(--border);
            padding: 12px 16px;
            border-radius: 8px;
            color: #fff;
            font-family: inherit;
            font-size: 14px;
        }}
        .search-box input:focus {{
            outline: none;
            border-color: var(--primary);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--surface);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid var(--border);
            margin-bottom: 32px;
        }}
        th, td {{
            padding: 14px 18px;
            text-align: left;
            border-bottom: 1px solid var(--border);
            font-size: 14px;
        }}
        th {{
            background: var(--surface-card);
            color: var(--text-muted);
            font-weight: 600;
            text-transform: uppercase;
            font-size: 12px;
            letter-spacing: 0.05em;
        }}
        tr:hover td {{
            background: rgba(255, 255, 255, 0.02);
        }}
        code {{
            font-family: 'JetBrains Mono', monospace;
            background: rgba(0, 0, 0, 0.4);
            padding: 3px 6px;
            border-radius: 4px;
            color: #93c5fd;
            font-size: 13px;
        }}
        .section-title {{
            font-size: 20px;
            font-weight: 700;
            margin: 32px 0 16px 0;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .copy-btn {{
            background: transparent;
            border: 1px solid var(--border);
            color: var(--text-muted);
            padding: 3px 8px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;
            margin-left: 8px;
        }}
        .copy-btn:hover {{
            background: var(--surface-card);
            color: #fff;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <h1>AS Inspect</h1>
                <p>Understand applications with evidence. • Developed by Abu Safyan</p>
            </div>
            <div>
                <span class="badge badge-blue">{report.target.detected_type.value}</span>
                <span class="badge badge-green">Verified Evidence</span>
            </div>
        </header>

        <div class="grid">
            <div class="card">
                <h3>Target Name</h3>
                <div class="value">{report.target.filename}</div>
            </div>
            <div class="card">
                <h3>File Size</h3>
                <div class="value">{report.target.size_bytes:,} bytes</div>
            </div>
            <div class="card">
                <h3>Total Evidence Collected</h3>
                <div class="value">{len(report.all_evidence)} Items</div>
            </div>
        </div>

        <div class="section-title">Cryptographic Hashes</div>
        <table>
            <thead>
                <tr>
                    <th style="width: 150px;">Algorithm</th>
                    <th>Hash Digest</th>
                    <th style="width: 100px;">Action</th>
                </tr>
            </thead>
            <tbody>
                {''.join(f'<tr><td><b>{ev.type.replace("hash_", "").upper()}</b></td><td><code>{ev.value}</code></td><td><button class="copy-btn" onclick="navigator.clipboard.writeText(\'{ev.value}\')">Copy</button></td></tr>' for ev in report.all_evidence if ev.type.startswith("hash_"))}
            </tbody>
        </table>

        <div class="section-title">Evidence Ledger (Filter & Search)</div>
        <div class="search-box">
            <input type="text" id="filterInput" placeholder="Search evidence by ID, type, value, or location..." onkeyup="filterEvidence()">
        </div>

        <table id="evidenceTable">
            <thead>
                <tr>
                    <th style="width: 140px;">Evidence ID</th>
                    <th style="width: 120px;">Category</th>
                    <th style="width: 180px;">Type</th>
                    <th>Observed Value</th>
                    <th>Location / Source</th>
                    <th style="width: 100px;">Confidence</th>
                </tr>
            </thead>
            <tbody>
                {''.join(f'<tr><td><code>{ev.id}</code></td><td><span class="badge badge-blue">{ev.category.value}</span></td><td>{ev.type}</td><td><code>{ev.value}</code></td><td>{ev.location}</td><td>{ev.confidence.value}</td></tr>' for ev in report.all_evidence)}
            </tbody>
        </table>

        <footer style="margin-top: 60px; text-align: center; color: var(--text-muted); font-size: 13px; border-top: 1px solid var(--border); padding-top: 24px;">
            Generated with AS Inspect v0.1.0 • Evidence-Based Windows Engineering & Security Toolkit
        </footer>
    </div>

    <script>
        function filterEvidence() {{
            const input = document.getElementById('filterInput').value.toLowerCase();
            const rows = document.querySelectorAll('#evidenceTable tbody tr');
            rows.forEach(row => {{
                const text = row.innerText.toLowerCase();
                row.style.display = text.includes(input) ? '' : 'none';
            }});
        }}
    </script>
</body>
</html>"""
