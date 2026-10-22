import os
import time
from datetime import datetime, timezone
from typing import Dict, List
from as_inspect_core import (
    AnalyzerResult,
    AnalyzerStatus,
    EvidenceCategory,
    EvidenceConfidence,
    EvidenceItem,
    TargetKind,
    TargetMetadata,
)

class FolderAnalyzer:
    def analyze(self, target: TargetMetadata) -> AnalyzerResult:
        start_time = time.time()
        if target.kind != TargetKind.FOLDER or not os.path.isdir(target.path):
            return AnalyzerResult(
                analyzer="folder_analyzer",
                status=AnalyzerStatus.SKIPPED,
                evidence=[],
                warnings=["Target is not a directory."],
                errors=[],
                duration_ms=0,
                data=None,
            )

        try:
            total_files = 0
            total_dirs = 0
            total_size = 0
            ext_counts: Dict[str, int] = {}
            key_artifacts: List[str] = []

            for root, dirs, files in os.walk(target.path):
                total_dirs += len(dirs)
                for f in files:
                    total_files += 1
                    fp = os.path.join(root, f)
                    try:
                        sz = os.path.getsize(fp)
                        total_size += sz
                    except OSError:
                        pass

                    ext = os.path.splitext(f)[1].lower() or "no_ext"
                    ext_counts[ext] = ext_counts.get(ext, 0) + 1

                    if f.lower() in ["package.json", "app.asar", "electron.exe"] or ext in [".exe", ".dll", ".config"]:
                        key_artifacts.append(os.path.relpath(fp, target.path))

            now = datetime.now(timezone.utc).isoformat()
            evidence = [
                EvidenceItem(
                    id="EV-DIR-SCAN",
                    type="directory_structure",
                    value=f"Directory structure: {total_files} files across {total_dirs} folders ({total_size} bytes)",
                    source="filesystem_walk",
                    location=target.path,
                    confidence=EvidenceConfidence.CERTAIN,
                    category=EvidenceCategory.OBSERVED,
                    analyzer="folder_analyzer",
                    timestamp=now,
                    details={"key_artifacts": key_artifacts[:100]},
                )
            ]

            data = {
                "total_files": total_files,
                "total_dirs": total_dirs,
                "total_size": total_size,
                "extension_distribution": ext_counts,
                "key_artifacts": key_artifacts,
            }

            return AnalyzerResult(
                analyzer="folder_analyzer",
                status=AnalyzerStatus.SUCCESS,
                evidence=evidence,
                warnings=[],
                errors=[],
                duration_ms=int((time.time() - start_time) * 1000),
                data=data,
            )
        except Exception as e:
            return AnalyzerResult(
                analyzer="folder_analyzer",
                status=AnalyzerStatus.FAILED,
                evidence=[],
                warnings=[],
                errors=[f"Directory scan error: {str(e)}"],
                duration_ms=int((time.time() - start_time) * 1000),
                data=None,
            )
