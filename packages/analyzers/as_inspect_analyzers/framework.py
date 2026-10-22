import os
import re
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

class FrameworkDetector:
    def analyze(self, target: TargetMetadata) -> AnalyzerResult:
        start_time = time.time()
        if not os.path.exists(target.path) or target.kind.value != "file":
            return AnalyzerResult(
                analyzer="framework_detector",
                status=AnalyzerStatus.SKIPPED,
                evidence=[],
                warnings=["Target is not a readable file."],
                errors=[],
                duration_ms=0,
                data=None,
            )

        try:
            with open(target.path, "rb") as f:
                content_bytes = f.read(25 * 1024 * 1024) # Scan first 25MB

            content = content_bytes.decode("latin1", errors="ignore")
            indicators: List[Dict[str, Any]] = []

            # Electron check
            electron_signals = []
            if "resources.pak" in content:
                electron_signals.append("resources.pak reference")
            if "app.asar" in content:
                electron_signals.append("app.asar reference")
            if "ELECTRON_RUN_AS_NODE" in content:
                electron_signals.append("ELECTRON_RUN_AS_NODE environment flag")
            if "Chrome/" in content or "Chromium" in content:
                electron_signals.append("Chromium rendering engine markers")

            if electron_signals:
                conf = "High" if len(electron_signals) >= 2 else "Medium"
                indicators.append({
                    "framework": "Electron",
                    "confidence": conf,
                    "reasons": electron_signals,
                })

            # .NET check
            dotnet_signals = []
            if "mscorlib.dll" in content:
                dotnet_signals.append("mscorlib.dll reference")
            if "System.Runtime" in content:
                dotnet_signals.append("System.Runtime (.NET Core / .NET 5+) reference")
            if "_CorExeMain" in content or "_CorDllMain" in content:
                dotnet_signals.append("CLR Entrypoint invocation")

            if dotnet_signals:
                conf = "High" if len(dotnet_signals) >= 2 else "Medium"
                indicators.append({
                    "framework": ".NET",
                    "confidence": conf,
                    "reasons": dotnet_signals,
                })

            # Python check
            python_signals = []
            if any(p in content for p in ["python3.dll", "python310.dll", "python311.dll", "python312.dll", "python313.dll", "python314.dll"]):
                python_signals.append("Bundled Python runtime DLL")
            if "PyInstaller" in content or "_MEI" in content:
                python_signals.append("PyInstaller bootloader metadata")

            if python_signals:
                indicators.append({
                    "framework": "Python (Bundled/Frozen)",
                    "confidence": "High",
                    "reasons": python_signals,
                })

            # Qt check
            if any(q in content for q in ["Qt5Core.dll", "Qt6Core.dll", "QApplication"]):
                indicators.append({
                    "framework": "Qt",
                    "confidence": "High",
                    "reasons": ["Qt runtime libraries and widgets detected"],
                })

            evidence: List[EvidenceItem] = []
            now = datetime.now(timezone.utc).isoformat()

            for ind in indicators:
                evidence.append(
                    EvidenceItem(
                        id=f"EV-FW-{ind['framework'].replace(' ', '_')}",
                        type="framework_detection",
                        value=f"{ind['framework']} (Confidence: {ind['confidence']})",
                        source="binary_analysis",
                        location="content_strings_and_imports",
                        confidence=EvidenceConfidence.HIGH if ind["confidence"] == "High" else EvidenceConfidence.MEDIUM,
                        category=EvidenceCategory.INFERRED,
                        analyzer="framework_detector",
                        timestamp=now,
                        details={"reasons": ind["reasons"]},
                    )
                )

            return AnalyzerResult(
                analyzer="framework_detector",
                status=AnalyzerStatus.SUCCESS,
                evidence=evidence,
                warnings=[],
                errors=[],
                duration_ms=int((time.time() - start_time) * 1000),
                data={"indicators": indicators},
            )

        except Exception as e:
            return AnalyzerResult(
                analyzer="framework_detector",
                status=AnalyzerStatus.FAILED,
                evidence=[],
                warnings=[],
                errors=[f"Framework detection error: {str(e)}"],
                duration_ms=int((time.time() - start_time) * 1000),
                data=None,
            )
