import argparse
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE_DIR, "packages", "core"))
sys.path.insert(0, os.path.join(BASE_DIR, "packages", "analyzers"))
sys.path.insert(0, os.path.join(BASE_DIR, "packages", "evidence"))
sys.path.insert(0, os.path.join(BASE_DIR, "packages", "reports"))

from as_inspect_analyzers import AnalysisPipeline
from as_inspect_reports import ReportGenerator

def main():
    parser = argparse.ArgumentParser(
        prog="as-inspect",
        description="AS Inspect: Understand applications with evidence. Developed by Abu Safyan.",
    )
    parser.add_argument("--version", action="version", version="AS Inspect 0.1.0")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # analyze
    p_analyze = subparsers.add_parser("analyze", help="Perform full technical analysis on a target")
    p_analyze.add_argument("target", help="Path to file or folder")
    p_analyze.add_argument("--json", help="Path to export JSON report")
    p_analyze.add_argument("--markdown", help="Path to export Markdown report")

    # hash
    p_hash = subparsers.add_parser("hash", help="Calculate cryptographic hashes")
    p_hash.add_argument("target", help="Path to file")

    # strings
    p_str = subparsers.add_parser("strings", help="Extract printable strings safely")
    p_str.add_argument("target", help="Path to file")

    # imports
    p_imp = subparsers.add_parser("imports", help="Extract PE imports")
    p_imp.add_argument("target", help="Path to file")

    # detect
    p_det = subparsers.add_parser("detect", help="Detect frameworks")
    p_det.add_argument("target", help="Path to file")

    # report
    p_rep = subparsers.add_parser("report", help="Generate inspection report")
    p_rep.add_argument("target", help="Path to file or directory")
    p_rep.add_argument("--format", choices=["markdown", "json", "html"], default="markdown")

    args = parser.parse_args()
    pipeline = AnalysisPipeline()

    if args.command == "analyze":
        print(f"Inspecting target: {args.target}")
        report = pipeline.inspect_target(args.target)
        print("\nAnalysis Complete!")
        print(f"Evidence collected: {len(report.all_evidence)}")
        for ev in report.all_evidence:
            print(f"[{ev.id}] {ev.type} -> {ev.value}")

        if args.json:
            with open(args.json, "w", encoding="utf-8") as f:
                f.write(ReportGenerator.to_json(report))
            print(f"Wrote JSON report to {args.json}")

        if args.markdown:
            with open(args.markdown, "w", encoding="utf-8") as f:
                f.write(ReportGenerator.to_markdown(report))
            print(f"Wrote Markdown report to {args.markdown}")

    elif args.command == "hash":
        report = pipeline.inspect_target(args.target)
        for ev in report.all_evidence:
            if ev.type.startswith("hash_"):
                print(f"{ev.type.replace('hash_', '').upper()}: {ev.value}")

    elif args.command == "strings":
        report = pipeline.inspect_target(args.target)
        for ev in report.all_evidence:
            if ev.source == "string_scan":
                print(f"[{ev.id}] {ev.type}: {ev.value}")

    elif args.command == "imports":
        report = pipeline.inspect_target(args.target)
        for ev in report.all_evidence:
            if ev.type == "import_dll":
                print(f"{ev.value}")

    elif args.command == "detect":
        report = pipeline.inspect_target(args.target)
        for ev in report.all_evidence:
            if ev.type in ["framework_detection", "framework_indicator"]:
                print(f"[{ev.id}] {ev.value}")

    elif args.command == "report":
        report = pipeline.inspect_target(args.target)
        if args.format == "json":
            print(ReportGenerator.to_json(report))
        elif args.format == "html":
            print(ReportGenerator.to_html(report))
        else:
            print(ReportGenerator.to_markdown(report))

if __name__ == "__main__":
    main()
