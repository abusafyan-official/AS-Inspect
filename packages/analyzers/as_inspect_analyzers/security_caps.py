import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List
import pefile
from as_inspect_core import (
    AnalyzerResult,
    AnalyzerStatus,
    EvidenceCategory,
    EvidenceConfidence,
    EvidenceItem,
    TargetMetadata,
)

class SecurityCapabilitiesAnalyzer:
    # Common Windows Win32 API capabilities mapping
    CAPABILITY_MAP = {
        "Network & Telemetry": {
            "apis": [
                "InternetOpenA", "InternetOpenW", "HttpOpenRequestA", "HttpOpenRequestW",
                "HttpSendRequestA", "HttpSendRequestW", "WSAStartup", "socket", "connect",
                "send", "recv", "URLDownloadToFileW", "URLDownloadToFileA", "WinHttpOpen",
            ],
            "description": "Performs external internet or raw socket network communication.",
        },
        "Process & Thread Control": {
            "apis": [
                "CreateProcessA", "CreateProcessW", "OpenProcess", "CreateRemoteThread",
                "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory",
                "ReadProcessMemory", "QueueUserAPC", "SetThreadContext",
            ],
            "description": "Allocates virtual memory, alters page protection, or manages remote process memory.",
        },
        "Registry Persistence & Config": {
            "apis": [
                "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW",
                "RegCreateKeyExA", "RegCreateKeyExW", "RegDeleteValueA", "RegDeleteValueW",
            ],
            "description": "Reads or writes system/user configuration keys in Windows Registry.",
        },
        "File System Operations": {
            "apis": [
                "CreateFileA", "CreateFileW", "WriteFile", "DeleteFileA", "DeleteFileW",
                "MoveFileExW", "CopyFileW", "FindFirstFileW", "FindNextFileW",
            ],
            "description": "Creates, modifies, enumerates, or deletes files on local disks.",
        },
        "Crypto & Credential Safety": {
            "apis": [
                "CryptAcquireContextA", "CryptAcquireContextW", "CryptEncrypt", "CryptDecrypt",
                "CryptGenRandom", "BCryptOpenAlgorithmProvider", "BCryptEncrypt", "BCryptDecrypt",
            ],
            "description": "Uses Windows Cryptography APIs / BCrypt for hashing, encryption, or PRNG.",
        },
        "Anti-Analysis & Debug Detection": {
            "apis": [
                "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA",
                "OutputDebugStringW", "QueryPerformanceCounter", "GetTickCount",
            ],
            "description": "Checks system debugging flags or monitors execution performance ticks.",
        },
    }

    KNOWN_PACKERS = [
        (".upx0", "UPX Executable Packer"),
        (".upx1", "UPX Executable Packer"),
        (".upx2", "UPX Executable Packer"),
        (".aspack", "Aspack Compressor"),
        (".adata", "Aspack Compressor"),
        (".mpress1", "MPRESS Compressor"),
        (".mpress2", "MPRESS Compressor"),
        ("vmp0", "VMProtect Virtualizer"),
        ("vmp1", "VMProtect Virtualizer"),
        (".themida", "Themida / WinLicense Protector"),
    ]

    def analyze(self, target: TargetMetadata) -> AnalyzerResult:
        start_time = time.time()
        ext = os.path.splitext(target.path)[1].lower()
        if ext not in [".exe", ".dll", ".sys"]:
            return AnalyzerResult(
                analyzer="security_capabilities_analyzer",
                status=AnalyzerStatus.SKIPPED,
                evidence=[],
                warnings=["Target is not a native PE binary."],
                errors=[],
                duration_ms=0,
                data=None,
            )

        try:
            pe = pefile.PE(target.path, fast_load=False)
            evidence: List[EvidenceItem] = []
            now = datetime.now(timezone.utc).isoformat()

            # 1. Digital Signature Check (IMAGE_DIRECTORY_ENTRY_SECURITY)
            has_signature = False
            sig_size = 0
            sig_va = 0
            try:
                sec_dir_idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
                if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > sec_dir_idx:
                    sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_dir_idx]
                    if sec_dir.VirtualAddress > 0 and sec_dir.Size > 0:
                        has_signature = True
                        sig_va = sec_dir.VirtualAddress
                        sig_size = sec_dir.Size
            except Exception:
                pass

            sig_status_str = f"Digitally Signed (Certificate Table Size: {sig_size} bytes)" if has_signature else "Unsigned (No Authenticode certificate table)"
            evidence.append(
                EvidenceItem(
                    id="EV-SEC-AUTHENTICODE",
                    type="authenticode_signature",
                    value=sig_status_str,
                    source="pe_security_directory",
                    location=f"DataDirectory[SECURITY] (Offset 0x{sig_va:X})",
                    confidence=EvidenceConfidence.CERTAIN,
                    category=EvidenceCategory.OBSERVED,
                    analyzer="security_capabilities_analyzer",
                    timestamp=now,
                    details={"is_signed": has_signature, "cert_table_size": sig_size},
                )
            )

            # 2. Packer / Obfuscator & High-Entropy Detection
            detected_packers = []
            for sec in pe.sections:
                sec_name = sec.Name.decode("latin1", errors="ignore").lower().strip("\x00")
                for p_sig, p_name in self.KNOWN_PACKERS:
                    if p_sig in sec_name:
                        detected_packers.append((sec_name, p_name))

            for s_name, p_name in detected_packers:
                evidence.append(
                    EvidenceItem(
                        id=f"EV-PACKER-{s_name}",
                        type="packer_signature",
                        value=f"Identified packer/protector signature: {p_name} in section '{s_name}'",
                        source="pe_section_headers",
                        location=f"Section {s_name}",
                        confidence=EvidenceConfidence.HIGH,
                        category=EvidenceCategory.INFERRED,
                        analyzer="security_capabilities_analyzer",
                        timestamp=now,
                    )
                )

            # 3. Security Capabilities Extraction via Win32 Imports
            all_imported_apis = set()
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            all_imported_apis.add(imp.name.decode("utf-8", errors="ignore"))

            capabilities_detected: Dict[str, Dict[str, Any]] = {}
            for cap_name, cap_info in self.CAPABILITY_MAP.items():
                matched_apis = [api for api in cap_info["apis"] if api in all_imported_apis]
                if matched_apis:
                    capabilities_detected[cap_name] = {
                        "matched_apis": matched_apis,
                        "description": cap_info["description"],
                    }
                    evidence.append(
                        EvidenceItem(
                            id=f"EV-CAP-{cap_name.replace(' ', '_')}",
                            type="security_capability",
                            value=f"{cap_name}: {len(matched_apis)} APIs matched ({', '.join(matched_apis[:4])}{'...' if len(matched_apis) > 4 else ''})",
                            source="pe_import_table",
                            location="Import Directory",
                            confidence=EvidenceConfidence.CERTAIN,
                            category=EvidenceCategory.OBSERVED,
                            analyzer="security_capabilities_analyzer",
                            timestamp=now,
                            details={"matched_apis": matched_apis, "description": cap_info["description"]},
                        )
                    )

            pe.close()

            data = {
                "is_signed": has_signature,
                "cert_size": sig_size,
                "detected_packers": [p[1] for p in detected_packers],
                "capabilities": capabilities_detected,
            }

            return AnalyzerResult(
                analyzer="security_capabilities_analyzer",
                status=AnalyzerStatus.SUCCESS,
                evidence=evidence,
                warnings=[],
                errors=[],
                duration_ms=int((time.time() - start_time) * 1000),
                data=data,
            )

        except Exception as e:
            return AnalyzerResult(
                analyzer="security_capabilities_analyzer",
                status=AnalyzerStatus.FAILED,
                evidence=[],
                warnings=[],
                errors=[f"Security capabilities analysis error: {str(e)}"],
                duration_ms=int((time.time() - start_time) * 1000),
                data=None,
            )
