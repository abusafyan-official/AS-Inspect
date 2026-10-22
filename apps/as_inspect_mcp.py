import json
import os
import sys

# Ensure local packages are on path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "packages", "core"))
sys.path.insert(0, os.path.join(BASE_DIR, "packages", "analyzers"))
sys.path.insert(0, os.path.join(BASE_DIR, "packages", "reports"))

from as_inspect_analyzers import AnalysisPipeline
from as_inspect_reports import ReportGenerator

def main():
    pipeline = AnalysisPipeline()

    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue

            req = json.loads(line)
            method = req.get("method")
            req_id = req.get("id")

            if method == "tools/list":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": [
                            {
                                "name": "inspect_file",
                                "description": "Inspect executable, DLL, ASAR, or folder and extract structured technical evidence",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "path": {"type": "string", "description": "Absolute path to target file"}
                                    },
                                    "required": ["path"]
                                }
                            },
                            {
                                "name": "get_hashes",
                                "description": "Calculate MD5, SHA-1, SHA-256 for target",
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "path": {"type": "string"}
                                    },
                                    "required": ["path"]
                                }
                            }
                        ]
                    }
                }
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()

            elif method == "tools/call":
                params = req.get("params", {})
                name = params.get("name")
                args = params.get("arguments", {})
                target_path = args.get("path")

                if not target_path or not os.path.exists(target_path):
                    resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32602, "message": f"Target path not found: {target_path}"}
                    }
                else:
                    report = pipeline.inspect_target(target_path)
                    if name == "get_hashes":
                        hashes = [ev for ev in report.all_evidence if ev.type.startswith("hash_")]
                        content_text = json.dumps([{"algorithm": h.type, "value": h.value} for h in hashes])
                    else:
                        content_text = ReportGenerator.to_markdown(report)

                    resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": content_text}]
                        }
                    }

                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()

            elif method == "initialize":
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "as-inspect", "version": "0.1.0"}
                    }
                }
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()

        except Exception as e:
            err_resp = {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32000, "message": str(e)}
            }
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()

if __name__ == "__main__":
    main()
