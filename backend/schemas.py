"""
AEGIS 2.0 Backend — Pydantic Data Contract

This module defines the canonical response schema specified in PRD Section 8.
Every analysis endpoint returns an AnalysisResponse that uses these models.
The types mirror the frontend TypeScript definitions exactly.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class InputType(str, enum.Enum):
    EMAIL = "email"
    SMS = "sms"
    URL = "url"
    MESSAGE = "message"
    TEXT = "text"


class RiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(str, enum.Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Confidence(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingCategory(str, enum.Enum):
    SOCIAL_ENGINEERING = "social_engineering"
    URL = "url"
    IMPERSONATION = "impersonation"
    EMAIL_AUTH = "email_auth"
    CONTENT = "content"
    ANOMALY = "anomaly"


class FindingSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class UrlReputation(str, enum.Enum):
    UNKNOWN = "unknown"
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class BlockchainStatus(str, enum.Enum):
    NOT_ENABLED = "not_enabled"
    PENDING = "pending"
    ANCHORED = "anchored"
    FAILED = "failed"


# ---------------------------------------------------------------------------
# Nested Models
# ---------------------------------------------------------------------------

class SignalScores(BaseModel):
    """Per-signal contribution scores (0–100)."""
    nlp: int = 0
    url: int = 0
    sender: int = 0
    email_auth: int = 0
    context: int = 0


class ModelScores(BaseModel):
    """Raw classifier output scores (0.0–1.0)."""
    url_classifier: float = 0.0
    text_classifier: float = 0.0
    anomaly: float = 0.0


class Finding(BaseModel):
    """A single explainable detection finding."""
    category: FindingCategory
    severity: FindingSeverity
    evidence: str
    explanation: str
    recommended_action: str
    source_module: str


class ExtractedUrl(BaseModel):
    """A URL extracted from the submitted content."""
    url: str
    domain: str
    reputation: UrlReputation = UrlReputation.UNKNOWN
    flags: list[str] = Field(default_factory=list)


class LinkHop(BaseModel):
    """One hop in a server-side redirect chain."""
    hop: int
    url: str
    status: int
    final: bool
    page_title: Optional[str] = None
    flags: list[str] = Field(default_factory=list)


class TextHighlight(BaseModel):
    """A substring range tagged with a threat indicator."""
    start: int
    end: int
    severity: str
    label: str


# ---------------------------------------------------------------------------
# Request Models
# ---------------------------------------------------------------------------

class AnalyzeRequest(BaseModel):
    """Incoming analysis request from the frontend."""
    type: InputType
    content: str
    sender: Optional[str] = None
    subject: Optional[str] = None


class UrlAnalyzeRequest(BaseModel):
    """
    Request body for the URL analysis endpoint.
    Accepts both {"url": "https://..."} and {"content": "https://..."}.
    """
    url: Optional[str] = None
    content: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def resolve_url_or_content(cls, data):
        if isinstance(data, dict):
            url_val = data.get("url") or data.get("content")
            if not url_val or not str(url_val).strip():
                raise ValueError("Either 'url' or 'content' must be provided.")
            data["url"] = str(url_val).strip()
            data["content"] = str(url_val).strip()
        elif isinstance(data, str):
            clean = data.strip()
            data = {"url": clean, "content": clean}
        return data

    @property
    def target_url(self) -> str:
        return self.url or self.content or ""


class TextAnalyzeRequest(BaseModel):
    """Request body for free-text / SMS analysis endpoint."""
    content: str
    input_type: InputType = InputType.TEXT
    sender: Optional[str] = None
    subject: Optional[str] = None


class EmailAnalyzeRequest(BaseModel):
    """Request body for email analysis endpoint."""
    content: str
    sender: Optional[str] = None
    subject: Optional[str] = None
    raw_headers: Optional[str] = None


# ---------------------------------------------------------------------------
# Response Model (PRD Section 8 — canonical AnalysisResult)
# ---------------------------------------------------------------------------

class AnalysisResponse(BaseModel):
    """
    The canonical analysis response contract (PRD Section 8).

    Every analysis endpoint returns this identical structure,
    regardless of input channel. Fields that are not applicable
    to a given channel are left at their defaults (empty lists,
    zero scores, etc.).
    """
    model_config = {
        "protected_namespaces": (),
    }

    case_id: str
    input_type: InputType
    created_at: str  # ISO-8601 datetime string
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    verdict: Verdict
    confidence: Confidence
    signal_scores: SignalScores = Field(default_factory=SignalScores)
    model_scores: ModelScores = Field(default_factory=ModelScores)
    findings: list[Finding] = Field(default_factory=list)
    extracted_urls: list[ExtractedUrl] = Field(default_factory=list)
    link_trail: list[LinkHop] = Field(default_factory=list)
    highlights: list[TextHighlight] = Field(default_factory=list)
    unavailable_checks: list[str] = Field(default_factory=list)
    explanation: str = ""
    recommendations: list[str] = Field(default_factory=list)
    evidence_hash: Optional[str] = None
    blockchain_status: BlockchainStatus = BlockchainStatus.NOT_ENABLED
    transaction_hash: Optional[str] = None

