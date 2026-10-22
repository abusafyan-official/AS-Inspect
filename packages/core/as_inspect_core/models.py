from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid

class TargetKind(str, Enum):
    FILE = "file"
    FOLDER = "folder"

class SupportedFileType(str, Enum):
    PE_EXE = "pe_exe"
    PE_DLL = "pe_dll"
    MSI = "msi"
    ASAR = "asar"
    JAVASCRIPT = "javascript"
    JSON = "json"
    FOLDER = "folder"
    UNKNOWN = "unknown"

class EvidenceConfidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CERTAIN = "certain"

class EvidenceCategory(str, Enum):
    OBSERVED = "observed"
    INFERRED = "inferred"
    AI_GENERATED_EXPLANATION = "ai_generated_explanation"

class AnalyzerStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    FAILED = "failed"

@dataclass
class TargetMetadata:
    path: str
    filename: str
    size_bytes: int
    kind: TargetKind
    detected_type: SupportedFileType
    created_at: Optional[str] = None
    modified_at: Optional[str] = None

@dataclass
class EvidenceItem:
    id: str
    type: str
    value: str
    source: str
    location: str
    confidence: EvidenceConfidence
    category: EvidenceCategory
    analyzer: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Optional[Dict[str, Any]] = None

@dataclass
class AnalyzerResult:
    analyzer: str
    status: AnalyzerStatus
    evidence: List[EvidenceItem]
    warnings: List[str]
    errors: List[str]
    duration_ms: int
    data: Optional[Dict[str, Any]] = None

@dataclass
class AiAnswerItem:
    question: str
    answer: str
    evidence_ids: List[str]

@dataclass
class AiAnalysisOutput:
    provider: str
    model: str
    summary: str
    answers: List[AiAnswerItem]
    cited_evidence_ids: List[str]

@dataclass
class AnalysisReport:
    target: TargetMetadata
    started_at: str
    finished_at: str
    results: List[AnalyzerResult]
    all_evidence: List[EvidenceItem]
    warnings: List[str]
    limitations: List[str]
    ai_analysis: Optional[AiAnalysisOutput] = None
