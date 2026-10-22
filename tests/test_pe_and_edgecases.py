import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "packages", "core"))
sys.path.insert(0, os.path.join(BASE_DIR, "packages", "analyzers"))

import pytest
from as_inspect_core import TargetMetadata, TargetKind, SupportedFileType
from as_inspect_analyzers import PeAnalyzer, AnalysisPipeline

def test_real_windows_binary_pe():
    # Test against python.exe itself as a real Windows x64 binary
    python_exe = sys.executable
    assert os.path.exists(python_exe)

    target = TargetMetadata(
        path=python_exe,
        filename="python.exe",
        size_bytes=os.path.getsize(python_exe),
        kind=TargetKind.FILE,
        detected_type=SupportedFileType.PE_EXE,
    )

    analyzer = PeAnalyzer()
    res = analyzer.analyze(target)
    assert res.status.value == "success"
    assert "x64" in res.data["architecture"]
    assert len(res.data["sections"]) > 0
    assert any("EV-PE-ARCH" == e.id for e in res.evidence)
    assert any("EV-PE-ENTRY" == e.id for e in res.evidence)

def test_malformed_pe_handling(tmp_path):
    # Malformed PE header (starts with MZ but truncated/corrupt)
    corrupt_pe = tmp_path / "corrupt.exe"
    corrupt_pe.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF")

    target = TargetMetadata(
        path=str(corrupt_pe),
        filename="corrupt.exe",
        size_bytes=corrupt_pe.stat().st_size,
        kind=TargetKind.FILE,
        detected_type=SupportedFileType.PE_EXE,
    )

    analyzer = PeAnalyzer()
    res = analyzer.analyze(target)
    # Must report failed analyzer status safely without unhandled exception or crash
    assert res.status.value == "failed"
    assert len(res.errors) > 0

def test_empty_file_handling(tmp_path):
    empty = tmp_path / "empty.exe"
    empty.write_bytes(b"")

    target = TargetMetadata(
        path=str(empty),
        filename="empty.exe",
        size_bytes=0,
        kind=TargetKind.FILE,
        detected_type=SupportedFileType.PE_EXE,
    )

    pipeline = AnalysisPipeline()
    report = pipeline.inspect_target(str(empty))
    assert report.target.size_bytes == 0
    # Hashes should still be computed for 0-byte file (standard empty hashes)
    assert any(e.type == "hash_sha256" for e in report.all_evidence)
