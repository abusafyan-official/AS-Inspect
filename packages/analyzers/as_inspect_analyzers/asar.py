import json
import os
import struct
import time
from datetime import datetime, timezone
from typing import Any, Dict, List
from as_inspect_core import (
    AnalyzerResult,
    AnalyzerStatus,
    EvidenceCategory,
    EvidenceConfidence,
    EvidenceItem,
    TargetMetadata,
)

class AsarAnalyzer:
    @staticmethod
    def parse_asar_header(file_path: str) -> Dict[str, Any]:
        with open(file_path, "rb") as f:
            header_bytes = f.read(16)
            if len(header_bytes) < 16:
                raise ValueError("File too small to be a valid ASAR archive.")

            magic = struct.unpack("<I", header_bytes[0:4])[0]
            if magic != 4:
                raise ValueError("Invalid ASAR magic (expected 4).")

            header_json_size = struct.unpack("<I", header_bytes[12:16])[0]
            json_bytes = f.read(header_json_size)
            header_json = json.loads(json_bytes.decode("utf-8"))

        files_list: List[Dict[str, Any]] = []
        ext_counts: Dict[str, int] = {}

        def walk(node: Dict[str, Any], current_path: str):
            if "files" in node:
                for name, item in node["files"].items():
                    p = f"{current_path}/{name}" if current_path else name
                    if "files" in item:
                        walk(item, p)
                    else:
                        size = item.get("size", 0)
                        ext = os.path.splitext(name)[1].lower() or "no_ext"
                        ext_counts[ext] = ext_counts.get(ext, 0) + 1
                        files_list.append({
                            "path": p,
                            "size": size,
                            "offset": item.get("offset"),
                        })

        walk(header_json, "")
        total_size = sum(f["size"] for f in files_list)

        return {
            "total_files": len(files_list),
            "total_size": total_size,
            "extension_counts": ext_counts,
            "files": files_list,
        }

    def analyze(self, target: TargetMetadata) -> AnalyzerResult:
        start_time = time.time()
        if not target.path.lower().endswith(".asar"):
            return AnalyzerResult(
                analyzer="asar_analyzer",
                status=AnalyzerStatus.SKIPPED,
                evidence=[],
                warnings=["Target is not an .asar archive."],
                errors=[],
                duration_ms=0,
                data=None,
            )

        try:
            report = self.parse_asar_header(target.path)
            now = datetime.now(timezone.utc).isoformat()
            evidence = [
                EvidenceItem(
                    id="EV-ASAR-DETECT",
                    type="asar_archive",
                    value=f"Electron ASAR Package: {report['total_files']} files, {report['total_size']} bytes",
                    source="asar_header",
                    location="Header -> files",
                    confidence=EvidenceConfidence.CERTAIN,
                    category=EvidenceCategory.OBSERVED,
                    analyzer="asar_analyzer",
                    timestamp=now,
                    details=report["extension_counts"],
                )
            ]

            return AnalyzerResult(
                analyzer="asar_analyzer",
                status=AnalyzerStatus.SUCCESS,
                evidence=evidence,
                warnings=[],
                errors=[],
                duration_ms=int((time.time() - start_time) * 1000),
                data=report,
            )
        except Exception as e:
            return AnalyzerResult(
                analyzer="asar_analyzer",
                status=AnalyzerStatus.FAILED,
                evidence=[],
                warnings=[],
                errors=[f"Failed to inspect ASAR: {str(e)}"],
                duration_ms=int((time.time() - start_time) * 1000),
                data=None,
            )
