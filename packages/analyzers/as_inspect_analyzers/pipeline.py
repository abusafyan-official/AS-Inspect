import os
from datetime import datetime, timezone
from typing import List, Optional
from as_inspect_core import (
    AnalysisReport,
    EvidenceItem,
    SupportedFileType,
    TargetKind,
    TargetMetadata,
)
from .asar import AsarAnalyzer
from .folder import FolderAnalyzer
from .framework import FrameworkDetector
from .hashing import HashAnalyzer
from .javascript import JavaScriptAnalyzer
from .msi import MsiAnalyzer
from .pe import PeAnalyzer
from .strings import StringAnalyzer
from .security_caps import SecurityCapabilitiesAnalyzer

class AnalysisPipeline:
    def __init__(self):
        self.analyzers = [
            HashAnalyzer(),
            PeAnalyzer(),
            SecurityCapabilitiesAnalyzer(),
            FrameworkDetector(),
            StringAnalyzer(),
            AsarAnalyzer(),
            JavaScriptAnalyzer(),
            MsiAnalyzer(),
            FolderAnalyzer(),
        ]

    def inspect_target(self, target_path: str) -> AnalysisReport:
        abs_path = os.path.abspath(target_path)
        if not os.path.exists(abs_path):
            raise FileNotFoundError(f"Target not found: {abs_path}")

        started_at = datetime.now(timezone.utc).isoformat()
        is_dir = os.path.isdir(abs_path)
        filename = os.path.basename(abs_path)
        size_bytes = 0

        if is_dir:
            detected_type = SupportedFileType.FOLDER
            kind = TargetKind.FOLDER
        else:
            kind = TargetKind.FILE
            size_bytes = os.path.getsize(abs_path)
            ext = os.path.splitext(filename)[1].lower()
            type_map = {
                ".exe": SupportedFileType.PE_EXE,
                ".dll": SupportedFileType.PE_DLL,
                ".msi": SupportedFileType.MSI,
                ".asar": SupportedFileType.ASAR,
                ".js": SupportedFileType.JAVASCRIPT,
                ".mjs": SupportedFileType.JAVASCRIPT,
                ".cjs": SupportedFileType.JAVASCRIPT,
                ".ts": SupportedFileType.JAVASCRIPT,
                ".json": SupportedFileType.JSON,
            }
            detected_type = type_map.get(ext, SupportedFileType.UNKNOWN)

        target_meta = TargetMetadata(
            path=abs_path,
            filename=filename,
            size_bytes=size_bytes,
            kind=kind,
            detected_type=detected_type,
        )

        results = []
        all_evidence: List[EvidenceItem] = []
        warnings: List[str] = []
        limitations: List[str] = []

        for analyzer in self.analyzers:
            res = analyzer.analyze(target_meta)
            if res.status.value != "skipped":
                results.append(res)
                all_evidence.extend(res.evidence)
                warnings.extend(res.warnings)

        if not all_evidence:
            limitations.append("No structured evidence could be gathered for this target type.")

        finished_at = datetime.now(timezone.utc).isoformat()

        return AnalysisReport(
            target=target_meta,
            started_at=started_at,
            finished_at=finished_at,
            results=results,
            all_evidence=all_evidence,
            warnings=warnings,
            limitations=limitations,
            ai_analysis=None,
        )
