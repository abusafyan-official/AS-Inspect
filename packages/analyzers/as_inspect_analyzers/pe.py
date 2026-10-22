import math
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

class PeAnalyzer:
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        occurrences = [0] * 256
        for byte in data:
            occurrences[byte] += 1
        for count in occurrences:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 3)

    def analyze(self, target: TargetMetadata) -> AnalyzerResult:
        start_time = time.time()
        ext = os.path.splitext(target.path)[1].lower()
        if ext not in [".exe", ".dll", ".sys", ".ocx"]:
            return AnalyzerResult(
                analyzer="pe_analyzer",
                status=AnalyzerStatus.SKIPPED,
                evidence=[],
                warnings=["File extension is not recognized as PE."],
                errors=[],
                duration_ms=0,
                data=None,
            )

        try:
            pe = pefile.PE(target.path, fast_load=False)
            evidence: List[EvidenceItem] = []
            now = datetime.now(timezone.utc).isoformat()

            # Machine / Architecture
            machine = pe.FILE_HEADER.Machine
            arch_map = {
                0x014c: "x86 (32-bit)",
                0x8664: "x64 (64-bit AMD64)",
                0xaa64: "ARM64",
                0x01c0: "ARM",
                0x01c4: "ARM Thumb-2",
            }
            arch = arch_map.get(machine, f"Machine: 0x{machine:04X}")

            evidence.append(
                EvidenceItem(
                    id="EV-PE-ARCH",
                    type="architecture",
                    value=arch,
                    source="pe_header",
                    location="FILE_HEADER.Machine",
                    confidence=EvidenceConfidence.CERTAIN,
                    category=EvidenceCategory.OBSERVED,
                    analyzer="pe_analyzer",
                    timestamp=now,
                )
            )

            # Entry Point
            entry_point = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            evidence.append(
                EvidenceItem(
                    id="EV-PE-ENTRY",
                    type="entry_point",
                    value=entry_point,
                    source="pe_header",
                    location="OPTIONAL_HEADER.AddressOfEntryPoint",
                    confidence=EvidenceConfidence.CERTAIN,
                    category=EvidenceCategory.OBSERVED,
                    analyzer="pe_analyzer",
                    timestamp=now,
                )
            )

            # Sections
            sections_data = []
            for sec in pe.sections:
                sec_name = sec.Name.decode("utf-8", errors="ignore").strip("\x00")
                sec_data = sec.get_data()
                entropy = self.calculate_entropy(sec_data)

                sections_data.append({
                    "name": sec_name,
                    "virtual_address": hex(sec.VirtualAddress),
                    "virtual_size": sec.Misc_VirtualSize,
                    "raw_size": sec.SizeOfRawData,
                    "entropy": entropy,
                })

                evidence.append(
                    EvidenceItem(
                        id=f"EV-PE-SEC-{sec_name}",
                        type="section",
                        value=f"{sec_name} (Entropy: {entropy}, Size: {sec.SizeOfRawData} bytes)",
                        source="pe_section_table",
                        location=f"Offset 0x{sec.PointerToRawData:X}",
                        confidence=EvidenceConfidence.CERTAIN,
                        category=EvidenceCategory.OBSERVED,
                        analyzer="pe_analyzer",
                        timestamp=now,
                        details={"entropy": entropy, "raw_size": sec.SizeOfRawData},
                    )
                )

            # .NET CLR Header detection
            is_dotnet = False
            try:
                clr_idx = pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
                if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > clr_idx:
                    clr_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[clr_idx]
                    if clr_dir.VirtualAddress > 0 and clr_dir.Size > 0:
                        is_dotnet = True
            except Exception:
                pass

            if is_dotnet:
                evidence.append(
                    EvidenceItem(
                        id="EV-PE-DOTNET",
                        type="framework_indicator",
                        value=".NET Framework / CLR COM descriptor present",
                        source="pe_optional_header",
                        location="DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR]",
                        confidence=EvidenceConfidence.CERTAIN,
                        category=EvidenceCategory.OBSERVED,
                        analyzer="pe_analyzer",
                        timestamp=now,
                    )
                )

            # Imports
            imports_data: Dict[str, List[str]] = {}
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="ignore")
                    imports_data[dll_name] = []
                    for imp in entry.imports:
                        func_name = imp.name.decode("utf-8", errors="ignore") if imp.name else f"Ordinal({imp.ordinal})"
                        imports_data[dll_name].append(func_name)

                    evidence.append(
                        EvidenceItem(
                            id=f"EV-PE-IMP-{dll_name}",
                            type="import_dll",
                            value=f"{dll_name} ({len(imports_data[dll_name])} functions)",
                            source="pe_import_table",
                            location="Import Directory Table",
                            confidence=EvidenceConfidence.CERTAIN,
                            category=EvidenceCategory.OBSERVED,
                            analyzer="pe_analyzer",
                            timestamp=now,
                        )
                    )

            # Exports
            exports_data = []
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    exp_name = exp.name.decode("utf-8", errors="ignore") if exp.name else f"Ordinal({exp.ordinal})"
                    exports_data.append(exp_name)
                    evidence.append(
                        EvidenceItem(
                            id=f"EV-PE-EXP-{exp_name}",
                            type="export_symbol",
                            value=exp_name,
                            source="pe_export_table",
                            location=f"RVA: 0x{exp.address:X}",
                            confidence=EvidenceConfidence.CERTAIN,
                            category=EvidenceCategory.OBSERVED,
                            analyzer="pe_analyzer",
                            timestamp=now,
                        )
                    )

            # Version Info
            version_info = {}
            if hasattr(pe, "FileInfo"):
                for fi in pe.FileInfo:
                    for sub in fi:
                        if hasattr(sub, "StringTable"):
                            for st in sub.StringTable:
                                for k, v in st.entries.items():
                                    key_s = k.decode("utf-8", errors="ignore")
                                    val_s = v.decode("utf-8", errors="ignore")
                                    version_info[key_s] = val_s

            data: Dict[str, Any] = {
                "architecture": arch,
                "machine": machine,
                "entry_point": entry_point,
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                "subsystem": pe.OPTIONAL_HEADER.Subsystem,
                "compile_timestamp": pe.FILE_HEADER.TimeDateStamp,
                "sections": sections_data,
                "imports": imports_data,
                "exports": exports_data,
                "is_dotnet": is_dotnet,
                "version_info": version_info,
            }

            pe.close()
            return AnalyzerResult(
                analyzer="pe_analyzer",
                status=AnalyzerStatus.SUCCESS,
                evidence=evidence,
                warnings=[],
                errors=[],
                duration_ms=int((time.time() - start_time) * 1000),
                data=data,
            )

        except pefile.PEFormatError as e:
            return AnalyzerResult(
                analyzer="pe_analyzer",
                status=AnalyzerStatus.FAILED,
                evidence=[],
                warnings=[],
                errors=[f"Invalid or unsupported PE structure: {str(e)}"],
                duration_ms=int((time.time() - start_time) * 1000),
                data=None,
            )
        except Exception as e:
            return AnalyzerResult(
                analyzer="pe_analyzer",
                status=AnalyzerStatus.FAILED,
                evidence=[],
                warnings=[],
                errors=[f"PE analysis error: {str(e)}"],
                duration_ms=int((time.time() - start_time) * 1000),
                data=None,
            )
