import os
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Tuple
from as_inspect_core import (
    AnalyzerResult,
    AnalyzerStatus,
    EvidenceCategory,
    EvidenceConfidence,
    EvidenceItem,
    TargetKind,
    TargetMetadata,
)

class StringAnalyzer:
    def __init__(self, min_length: int = 5, max_scan_bytes: int = 50 * 1024 * 1024):
        self.min_length = min_length
        self.max_scan_bytes = max_scan_bytes

    @staticmethod
    def mask_potential_secrets(s: str) -> str:
        s = re.sub(r"sk-[a-zA-Z0-9]{12,}", "sk-**************", s)
        s = re.sub(r"AIza[0-9A-Za-z-_]{30,}", "AIza**************", s)
        s = re.sub(r"(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{30,}", r"\1_**************", s)
        return s

    @staticmethod
    def extract_ascii(data: bytes, min_len: int) -> List[Tuple[int, str]]:
        pattern = re.compile(rb"[\x20-\x7E\t]{" + str(min_len).encode() + rb",}")
        results = []
        for match in pattern.finditer(data):
            try:
                results.append((match.start(), match.group().decode("ascii")))
            except Exception:
                pass
        return results

    @staticmethod
    def extract_utf16(data: bytes, min_len: int) -> List[Tuple[int, str]]:
        pattern = re.compile(rb"(?:[\x20-\x7E\t]\x00){" + str(min_len).encode() + rb",}")
        results = []
        for match in pattern.finditer(data):
            try:
                results.append((match.start(), match.group().decode("utf-16le")))
            except Exception:
                pass
        return results

    def analyze(self, target: TargetMetadata) -> AnalyzerResult:
        start_time = time.time()
        if target.kind != TargetKind.FILE or not os.path.exists(target.path):
            return AnalyzerResult(
                analyzer="string_analyzer",
                status=AnalyzerStatus.SKIPPED,
                evidence=[],
                warnings=["Target is not a valid file."],
                errors=[],
                duration_ms=0,
                data=None,
            )

        try:
            with open(target.path, "rb") as f:
                data = f.read(self.max_scan_bytes)

            all_strings = self.extract_ascii(data, self.min_length) + self.extract_utf16(data, self.min_length)

            re_url = re.compile(r"(?i)\bhttps?://[a-zA-Z0-9_\-.]+(?::[0-9]+)?(?:/[^\s<>\x22\x27]*)?")
            re_domain = re.compile(r"(?i)\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|edu|gov|io|ai|dev|co|xyz|info|app|me)\b")
            re_win_path = re.compile(r"(?i)[a-zA-Z]:\\[a-zA-Z0-9_\-\.\\]+")
            re_registry = re.compile(r"(?i)\b(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKEY_CLASSES_ROOT|HKEY_USERS)\\[a-zA-Z0-9_\\\-]+")
            re_email = re.compile(r"(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")

            urls: List[Dict[str, str]] = []
            domains: List[Dict[str, str]] = []
            file_paths: List[Dict[str, str]] = []
            reg_paths: List[Dict[str, str]] = []
            emails: List[Dict[str, str]] = []
            sample_general: List[str] = []

            evidence: List[EvidenceItem] = []
            now = datetime.now(timezone.utc).isoformat()

            for offset, raw_str in all_strings:
                safe_str = self.mask_potential_secrets(raw_str)
                loc = f"Offset 0x{offset:X}"

                m_url = re_url.search(safe_str)
                m_reg = re_registry.search(safe_str)
                m_path = re_win_path.search(safe_str)
                m_email = re_email.search(safe_str)
                m_domain = re_domain.search(safe_str)

                if m_url:
                    val = m_url.group(0)
                    urls.append({"value": val, "location": loc})
                    if len(evidence) < 150:
                        evidence.append(
                            EvidenceItem(
                                id=f"EV-STR-URL-{len(evidence)+1}",
                                type="url",
                                value=val,
                                source="string_scan",
                                location=loc,
                                confidence=EvidenceConfidence.HIGH,
                                category=EvidenceCategory.OBSERVED,
                                analyzer="string_analyzer",
                                timestamp=now,
                            )
                        )
                elif m_reg:
                    val = m_reg.group(0)
                    reg_paths.append({"value": val, "location": loc})
                    if len(evidence) < 150:
                        evidence.append(
                            EvidenceItem(
                                id=f"EV-STR-REG-{len(evidence)+1}",
                                type="registry_key",
                                value=val,
                                source="string_scan",
                                location=loc,
                                confidence=EvidenceConfidence.HIGH,
                                category=EvidenceCategory.OBSERVED,
                                analyzer="string_analyzer",
                                timestamp=now,
                            )
                        )
                elif m_path:
                    file_paths.append({"value": m_path.group(0), "location": loc})
                elif m_email:
                    emails.append({"value": m_email.group(0), "location": loc})
                elif m_domain:
                    domains.append({"value": m_domain.group(0), "location": loc})
                elif len(sample_general) < 100:
                    sample_general.append(safe_str)

            summary = {
                "total_strings_extracted": len(all_strings),
                "urls": urls,
                "domains": domains,
                "file_paths": file_paths,
                "registry_paths": reg_paths,
                "emails": emails,
                "sample_general": sample_general,
            }

            return AnalyzerResult(
                analyzer="string_analyzer",
                status=AnalyzerStatus.SUCCESS,
                evidence=evidence,
                warnings=[],
                errors=[],
                duration_ms=int((time.time() - start_time) * 1000),
                data=summary,
            )

        except Exception as e:
            return AnalyzerResult(
                analyzer="string_analyzer",
                status=AnalyzerStatus.FAILED,
                evidence=[],
                warnings=[],
                errors=[f"String analysis error: {str(e)}"],
                duration_ms=int((time.time() - start_time) * 1000),
                data=None,
            )
