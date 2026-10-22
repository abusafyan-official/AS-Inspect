import hashlib
import os
import time
from datetime import datetime, timezone
from typing import Dict
from as_inspect_core import (
    AnalyzerResult,
    AnalyzerStatus,
    EvidenceCategory,
    EvidenceConfidence,
    EvidenceItem,
    TargetKind,
    TargetMetadata,
)

class HashAnalyzer:
    @staticmethod
    def compute_hashes(file_path: str) -> Dict[str, str]:
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as f:
            while chunk := f.read(64 * 1024):
                md5.update(chunk)
                sha1.update(chunk)
                sha256.update(chunk)

        return {
            "md5": md5.hexdigest(),
            "sha1": sha1.hexdigest(),
            "sha256": sha256.hexdigest(),
        }

    def analyze(self, target: TargetMetadata) -> AnalyzerResult:
        start_time = time.time()
        if target.kind != TargetKind.FILE or not os.path.exists(target.path):
            return AnalyzerResult(
                analyzer="hash_analyzer",
                status=AnalyzerStatus.SKIPPED,
                evidence=[],
                warnings=["Target is not a valid file for hashing."],
                errors=[],
                duration_ms=0,
                data=None,
            )

        try:
            hashes = self.compute_hashes(target.path)
            now = datetime.now(timezone.utc).isoformat()
            evidence = [
                EvidenceItem(
                    id="EV-HASH-MD5",
                    type="hash_md5",
                    value=hashes["md5"],
                    source="file_body",
                    location="0..EOF",
                    confidence=EvidenceConfidence.CERTAIN,
                    category=EvidenceCategory.OBSERVED,
                    analyzer="hash_analyzer",
                    timestamp=now,
                ),
                EvidenceItem(
                    id="EV-HASH-SHA1",
                    type="hash_sha1",
                    value=hashes["sha1"],
                    source="file_body",
                    location="0..EOF",
                    confidence=EvidenceConfidence.CERTAIN,
                    category=EvidenceCategory.OBSERVED,
                    analyzer="hash_analyzer",
                    timestamp=now,
                ),
                EvidenceItem(
                    id="EV-HASH-SHA256",
                    type="hash_sha256",
                    value=hashes["sha256"],
                    source="file_body",
                    location="0..EOF",
                    confidence=EvidenceConfidence.CERTAIN,
                    category=EvidenceCategory.OBSERVED,
                    analyzer="hash_analyzer",
                    timestamp=now,
                ),
            ]

            duration = int((time.time() - start_time) * 1000)
            return AnalyzerResult(
                analyzer="hash_analyzer",
                status=AnalyzerStatus.SUCCESS,
                evidence=evidence,
                warnings=[],
                errors=[],
                duration_ms=duration,
                data=hashes,
            )
        except Exception as e:
            return AnalyzerResult(
                analyzer="hash_analyzer",
                status=AnalyzerStatus.FAILED,
                evidence=[],
                warnings=[],
                errors=[f"Failed to calculate hashes: {str(e)}"],
                duration_ms=int((time.time() - start_time) * 1000),
                data=None,
            )
