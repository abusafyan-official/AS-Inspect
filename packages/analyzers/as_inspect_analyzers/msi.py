import os
import time
from datetime import datetime, timezone
from as_inspect_core import (
    AnalyzerResult,
    AnalyzerStatus,
    EvidenceCategory,
    EvidenceConfidence,
    EvidenceItem,
    TargetMetadata,
)

class MsiAnalyzer:
    def analyze(self, target: TargetMetadata) -> AnalyzerResult:
        start_time = time.time()
        if not target.path.lower().endswith(".msi"):
            return AnalyzerResult(
                analyzer="msi_analyzer",
                status=AnalyzerStatus.SKIPPED,
                evidence=[],
                warnings=["Target is not an MSI file."],
                errors=[],
                duration_ms=0,
                data=None,
            )

        try:
            with open(target.path, "rb") as f:
                header = f.read(8)

            # OLE Compound File signature: D0 CF 11 E0 A1 B1 1A E1
            is_ole = header == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

            evidence = []
            now = datetime.now(timezone.utc).isoformat()
            if is_ole:
                evidence.append(
                    EvidenceItem(
                        id="EV-MSI-OLE-MAGIC",
                        type="installer_package",
                        value="Valid Microsoft Windows Installer Compound Binary File (MSI)",
                        source="file_header",
                        location="0x00000000",
                        confidence=EvidenceConfidence.CERTAIN,
                        category=EvidenceCategory.OBSERVED,
                        analyzer="msi_analyzer",
                        timestamp=now,
                    )
                )

            return AnalyzerResult(
                analyzer="msi_analyzer",
                status=AnalyzerStatus.SUCCESS,
                evidence=evidence,
                warnings=[],
                errors=[],
                duration_ms=int((time.time() - start_time) * 1000),
                data={"is_valid_ole": is_ole},
            )
        except Exception as e:
            return AnalyzerResult(
                analyzer="msi_analyzer",
                status=AnalyzerStatus.FAILED,
                evidence=[],
                warnings=[],
                errors=[f"MSI inspection error: {str(e)}"],
                duration_ms=int((time.time() - start_time) * 1000),
                data=None,
            )
