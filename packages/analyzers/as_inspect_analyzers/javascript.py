import os
import re
import time
from datetime import datetime, timezone
from typing import List
from as_inspect_core import (
    AnalyzerResult,
    AnalyzerStatus,
    EvidenceCategory,
    EvidenceConfidence,
    EvidenceItem,
    TargetMetadata,
)

class JavaScriptAnalyzer:
    def analyze(self, target: TargetMetadata) -> AnalyzerResult:
        start_time = time.time()
        ext = os.path.splitext(target.path)[1].lower()
        if ext not in [".js", ".mjs", ".cjs", ".ts"]:
            return AnalyzerResult(
                analyzer="javascript_analyzer",
                status=AnalyzerStatus.SKIPPED,
                evidence=[],
                warnings=["Target is not a JavaScript/TypeScript source file."],
                errors=[],
                duration_ms=0,
                data=None,
            )

        try:
            with open(target.path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            lines = content.splitlines()
            imports: List[str] = []
            exports: List[str] = []
            functions: List[str] = []
            urls: List[str] = []

            for match in re.finditer(r"require\(\s*['\"]([^'\"]+)['\"]\s*\)", content):
                imports.append(match.group(1))
            for match in re.finditer(r"import\s+(?:[^'\"]+\s+from\s+)?['\"]([^'\"]+)['\"]", content):
                imports.append(match.group(1))

            for match in re.finditer(r"export\s+(?:default\s+)?(?:class|function|const|let|var)\s+([a-zA-Z0-9_$]+)", content):
                exports.append(match.group(1))

            for match in re.finditer(r"function\s+([a-zA-Z0-9_$]+)\s*\(", content):
                functions.append(match.group(1))

            for match in re.finditer(r"(?i)\bhttps?://[a-zA-Z0-9_\-.]+(?::[0-9]+)?(?:/[^\s<>\x22\x27]*)?", content):
                urls.append(match.group(0))

            evidence: List[EvidenceItem] = []
            now = datetime.now(timezone.utc).isoformat()

            if imports:
                evidence.append(
                    EvidenceItem(
                        id="EV-JS-DEPS",
                        type="javascript_dependencies",
                        value=f"Found {len(imports)} module dependencies",
                        source="static_js_ast",
                        location="File Imports",
                        confidence=EvidenceConfidence.CERTAIN,
                        category=EvidenceCategory.OBSERVED,
                        analyzer="javascript_analyzer",
                        timestamp=now,
                        details={"imports": imports[:50]},
                    )
                )

            data = {
                "total_lines": len(lines),
                "imports": imports,
                "exports": exports,
                "functions": functions,
                "urls": urls,
            }

            return AnalyzerResult(
                analyzer="javascript_analyzer",
                status=AnalyzerStatus.SUCCESS,
                evidence=evidence,
                warnings=[],
                errors=[],
                duration_ms=int((time.time() - start_time) * 1000),
                data=data,
            )
        except Exception as e:
            return AnalyzerResult(
                analyzer="javascript_analyzer",
                status=AnalyzerStatus.FAILED,
                evidence=[],
                warnings=[],
                errors=[f"JavaScript analysis failed: {str(e)}"],
                duration_ms=int((time.time() - start_time) * 1000),
                data=None,
            )
