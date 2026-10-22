import os
import sys

# Ensure local packages are on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "packages", "core"))
sys.path.insert(0, os.path.join(BASE_DIR, "packages", "analyzers"))
sys.path.insert(0, os.path.join(BASE_DIR, "packages", "evidence"))
sys.path.insert(0, os.path.join(BASE_DIR, "packages", "reports"))

import pytest
from as_inspect_core import TargetMetadata, TargetKind, SupportedFileType
from as_inspect_analyzers import (
    HashAnalyzer,
    PeAnalyzer,
    StringAnalyzer,
    FrameworkDetector,
    AsarAnalyzer,
    JavaScriptAnalyzer,
    AnalysisPipeline,
)
from as_inspect_evidence import EvidenceDatabase
from as_inspect_reports import ReportGenerator

def test_hash_analyzer(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"AS Inspect cryptographic test verification")
    target = TargetMetadata(
        path=str(f),
        filename="sample.bin",
        size_bytes=f.stat().st_size,
        kind=TargetKind.FILE,
        detected_type=SupportedFileType.UNKNOWN,
    )
    analyzer = HashAnalyzer()
    res = analyzer.analyze(target)
    assert res.status.value == "success"
    assert len(res.evidence) == 3
    assert any(e.type == "hash_sha256" for e in res.evidence)

def test_string_secret_masking():
    raw = "Here is my secret sk-1234567890abcdef and token AIzaSyB1234567890abcdefghijklmnopqr"
    masked = StringAnalyzer.mask_potential_secrets(raw)
    assert "sk-**************" in masked
    assert "AIza**************" in masked
    assert "sk-1234567890abcdef" not in masked

def test_evidence_database():
    db = EvidenceDatabase(":memory:")
    pipeline = AnalysisPipeline()
    # Test on a temporary file
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(b"console.log('hello'); require('fs');")
        tf_path = tf.name

    report = pipeline.inspect_target(tf_path)
    raw_json = ReportGenerator.to_json(report)
    aid = db.save_report(report, raw_json)
    assert aid is not None
    assert db.get_total_analyses() == 1
    os.remove(tf_path)

def test_javascript_analyzer(tmp_path):
    f = tmp_path / "app.js"
    f.write_text("import fs from 'fs';\nconst x = require('path');\nfunction start() { return 'https://api.github.com'; }", encoding="utf-8")
    target = TargetMetadata(
        path=str(f),
        filename="app.js",
        size_bytes=f.stat().st_size,
        kind=TargetKind.FILE,
        detected_type=SupportedFileType.JAVASCRIPT,
    )
    res = JavaScriptAnalyzer().analyze(target)
    assert res.status.value == "success"
    assert "fs" in res.data["imports"]
    assert "path" in res.data["imports"]
    assert "start" in res.data["functions"]
    assert "https://api.github.com" in res.data["urls"]
