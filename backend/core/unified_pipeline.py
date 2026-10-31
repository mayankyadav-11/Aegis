"""
AEGIS 2.0 — Unified Analysis Pipeline

Central orchestrator that connects every supported input channel through the
canonical evidence abstraction and evidence fusion engine.

Supported channels:
  text / message / sms / url / email / file / screenshot

Flow per request:
  1. extract_for_*()           → CanonicalEvidence
  2. Engine A (deterministic)  → URL inspector + brand/NLP detector
  3. Engine B (Gemini)         → single consolidated AI call (with graceful fallback)
  4. Intelligence cross-verify → lookup every extracted domain
  5. EvidenceFusionEngine      → FusionResult

Design rules:
  - Reuses ALL existing detector functions; no duplication.
  - Gemini is called at most ONCE per request.
  - SSRF protections are fully delegated to analyze_url_deterministic().
  - Never executes uploaded attachments.
  - Inconclusive extraction → FusionResult with risk_score=0, verdict=SAFE,
    completeness="inconclusive", disclosed in unavailable_checks.
"""

from __future__ import annotations

from typing import Optional

from schemas import Finding, FindingCategory, FindingSeverity

from core.canonical_evidence import (
    CanonicalEvidence,
    extract_for_email,
    extract_for_eml,
    extract_for_pdf,
    extract_for_screenshot,
    extract_for_text,
    extract_for_url,
)
from core.evidence_fusion import EvidenceFusionEngine, FusionResult, evidence_fusion_engine


# ---------------------------------------------------------------------------
# Lazy imports for detector functions to avoid circular imports at module load
# ---------------------------------------------------------------------------

def _analyze_url_deterministic(url: str, inspect_links: bool = False):
    from detectors.url_detector import analyze_url_deterministic
    return analyze_url_deterministic(url, inspect_links=inspect_links)


def _analyze_text_content(content: str, channel_type: str, sender=None, subject=None):
    from detectors.text_detector import analyze_text_content
    return analyze_text_content(
        content=content,
        channel_type=channel_type,
        sender=sender,
        subject=subject,
    )


def _analyze_with_gemini(content: str, channel_type: str, deterministic_findings=None):
    from core.gemini_analyzer import analyze_with_gemini
    return analyze_with_gemini(
        content=content,
        channel_type=channel_type,
        deterministic_findings=deterministic_findings or [],
    )


def _lookup_intelligence(domains: list[str]) -> dict:
    try:
        from intelligence.intelligence_service import intelligence_service
    except ImportError:
        try:
            from backend.intelligence.intelligence_service import intelligence_service
        except ImportError:
            return {}
    results = {}
    for d in domains:
        if d:
            results[d] = intelligence_service.lookup_domain_reputation(d)
    return results


def _parse_eml_findings(file_bytes: bytes):
    """Return (findings, email_risk_boost) from EML forensics for the fusion engine."""
    from detectors.file_forensics import parse_eml_bytes
    eml_res = parse_eml_bytes(file_bytes)
    boost = 0
    for f in eml_res.findings:
        if f.severity == FindingSeverity.CRITICAL:
            boost = max(boost, 85)
        elif f.severity == FindingSeverity.HIGH:
            boost = max(boost, 60)
        elif f.severity == FindingSeverity.MEDIUM:
            boost = max(boost, 35)
    return list(eml_res.findings), boost


def _parse_pdf_findings(file_bytes: bytes):
    """Return (findings, extra_score) from PDF forensics."""
    from detectors.file_forensics import parse_pdf_bytes
    pdf_res = parse_pdf_bytes(file_bytes)
    return list(pdf_res.findings), 0


# ---------------------------------------------------------------------------
# UnifiedAnalysisPipeline
# ---------------------------------------------------------------------------

class UnifiedAnalysisPipeline:
    """
    Unified orchestration engine.  All six analysis routes delegate here.
    """

    def __init__(self, fusion_engine: Optional[EvidenceFusionEngine] = None):
        self._fusion = fusion_engine or evidence_fusion_engine

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def process_input(
        self,
        input_type: str,
        *,
        content: Optional[str] = None,
        file_bytes: Optional[bytes] = None,
        filename: Optional[str] = None,
        sender: Optional[str] = None,
        subject: Optional[str] = None,
        context: Optional[str] = None,
        raw_headers: Optional[str] = None,
        inspect_links: bool = False,
    ) -> FusionResult:
        """
        Analyse any supported input and return a FusionResult.

        Parameters
        ----------
        input_type    : "text" | "sms" | "url" | "email" | "file" | "screenshot"
        content       : raw text/URL for text-based inputs
        file_bytes    : raw file bytes for file/screenshot inputs
        filename      : original filename (used to determine format for file inputs)
        sender        : declared sender (email / SMS)
        subject       : declared subject (email)
        context       : optional user-provided description (file / screenshot)
        raw_headers   : raw email header string (email channel)
        inspect_links : whether to follow redirect chains (URL channel only)
        """
        it = (input_type or "text").lower().strip()

        if it in ("text", "message", "sms"):
            return self._process_text(
                content=content or "",
                channel_type=it,
                sender=sender,
                subject=subject,
            )
        elif it == "url":
            return self._process_url(
                url=content or "",
                inspect_links=inspect_links,
            )
        elif it == "email":
            return self._process_email(
                content=content or "",
                sender=sender,
                subject=subject,
                raw_headers=raw_headers,
            )
        elif it == "file":
            if file_bytes is None:
                raise ValueError("file_bytes required for file input_type")
            return self._process_file(
                file_bytes=file_bytes,
                filename=filename or "upload",
                sender=sender,
                subject=subject,
                context=context,
            )
        elif it == "screenshot":
            if file_bytes is None:
                raise ValueError("file_bytes required for screenshot input_type")
            return self._process_screenshot(
                file_bytes=file_bytes,
                filename=filename or "screenshot.png",
                context=context,
            )
        else:
            raise ValueError(f"Unsupported input_type: {input_type!r}")

    # ------------------------------------------------------------------
    # Channel-specific processors
    # ------------------------------------------------------------------

    def _process_text(
        self,
        content: str,
        channel_type: str = "text",
        sender: Optional[str] = None,
        subject: Optional[str] = None,
    ) -> FusionResult:
        # 1. Canonical evidence
        evidence = extract_for_text(content, sender=sender, subject=subject, channel_type=channel_type)

        # 2. Deterministic text + URL analysis
        text_res = _analyze_text_content(
            content=evidence.extracted_text,
            channel_type=channel_type,
            sender=sender,
            subject=subject,
        )
        det_findings: list[Finding] = list(text_res.findings)
        det_url_scores: dict[str, int] = {}

        url_findings: list[Finding] = []
        for url in evidence.extracted_urls[:15]:
            u_res = _analyze_url_deterministic(url, inspect_links=False)
            det_url_scores[url] = u_res.risk_score
            url_findings.extend(u_res.findings)
        det_findings.extend(url_findings)

        # 3. Gemini (single call using normalised text)
        gemini_res = _analyze_with_gemini(
            content=evidence.extracted_text,
            channel_type=channel_type,
            deterministic_findings=det_findings,
        )

        # 4. Intelligence cross-verification
        intel = _lookup_intelligence(evidence.extracted_domains)

        # SMS-specific unavailables
        if channel_type == "sms":
            evidence.unavailable_checks.extend([
                "Email authentication: not applicable for SMS channel",
                "Carrier DLT telemetry: carrier gateway API unavailable",
            ])

        # 5. Fuse
        return self._fusion.fuse(
            evidence=evidence,
            deterministic_findings=det_findings,
            deterministic_url_scores=det_url_scores,
            deterministic_text_score=text_res.combined_risk_score,
            gemini_result=gemini_res,
            intelligence_results=intel,
            highlights=list(text_res.highlights),
        )

    def _process_url(
        self,
        url: str,
        inspect_links: bool = False,
    ) -> FusionResult:
        # 1. Canonical evidence
        evidence = extract_for_url(url)

        # 2. Deterministic URL analysis
        u_res = _analyze_url_deterministic(url, inspect_links=inspect_links)
        det_url_scores = {url: u_res.risk_score}

        # 3. Gemini
        gemini_res = _analyze_with_gemini(
            content=(
                f"URL under inspection: {url}\n"
                f"Domain: {u_res.domain}\n"
                f"Flags: {', '.join(u_res.flags)}"
            ),
            channel_type="url",
            deterministic_findings=list(u_res.findings),
        )

        # 4. Intelligence
        intel = _lookup_intelligence(evidence.extracted_domains)

        # 5. Fuse
        return self._fusion.fuse(
            evidence=evidence,
            deterministic_findings=list(u_res.findings),
            deterministic_url_scores=det_url_scores,
            deterministic_text_score=0,
            gemini_result=gemini_res,
            intelligence_results=intel,
            highlights=[],
        )

    def _process_email(
        self,
        content: str,
        sender: Optional[str] = None,
        subject: Optional[str] = None,
        raw_headers: Optional[str] = None,
    ) -> FusionResult:
        from detectors.email_detector import parse_and_inspect_email

        # 1. Email forensics
        email_res = parse_and_inspect_email(
            raw_content=content,
            explicit_sender=sender,
            explicit_subject=subject,
            raw_headers=raw_headers,
        )

        # 2. Canonical evidence from email body
        evidence = extract_for_email(
            content=content,
            sender=sender,
            subject=subject,
            raw_headers=raw_headers,
        )

        # 3. Deterministic text + URL
        text_res = _analyze_text_content(
            content=evidence.extracted_text,
            channel_type="email",
            sender=email_res.sender_email or sender,
            subject=email_res.subject or subject,
        )
        det_findings: list[Finding] = list(email_res.findings) + list(text_res.findings)
        det_url_scores: dict[str, int] = {}

        for url in evidence.extracted_urls[:15]:
            u_res = _analyze_url_deterministic(url, inspect_links=False)
            det_url_scores[url] = u_res.risk_score
            det_findings.extend(u_res.findings)

        email_boost = email_res.risk_boost

        # 4. Gemini
        gemini_res = _analyze_with_gemini(
            content=evidence.extracted_text,
            channel_type="email",
            deterministic_findings=det_findings,
        )

        # 5. Intelligence
        intel = _lookup_intelligence(evidence.extracted_domains)

        # 6. Fuse
        return self._fusion.fuse(
            evidence=evidence,
            deterministic_findings=det_findings,
            deterministic_url_scores=det_url_scores,
            deterministic_text_score=text_res.combined_risk_score,
            gemini_result=gemini_res,
            intelligence_results=intel,
            email_risk_boost=email_boost,
            highlights=list(text_res.highlights),
        )

    def _process_file(
        self,
        file_bytes: bytes,
        filename: str,
        sender: Optional[str] = None,
        subject: Optional[str] = None,
        context: Optional[str] = None,
    ) -> FusionResult:
        from pathlib import Path
        ext = Path(filename).suffix.lower()

        if ext == ".eml":
            return self._process_eml(
                file_bytes=file_bytes,
                filename=filename,
                sender=sender,
                subject=subject,
                context=context,
            )
        elif ext == ".pdf":
            return self._process_pdf(
                file_bytes=file_bytes,
                filename=filename,
                sender=sender,
                subject=subject,
                context=context,
            )
        elif ext in (".png", ".jpg", ".jpeg", ".webp"):
            return self._process_screenshot(
                file_bytes=file_bytes,
                filename=filename,
                context=context,
            )
        else:
            raise ValueError(f"Unsupported file extension: {ext!r}")

    def _process_eml(
        self,
        file_bytes: bytes,
        filename: str,
        sender: Optional[str] = None,
        subject: Optional[str] = None,
        context: Optional[str] = None,
    ) -> FusionResult:
        # 1. Canonical evidence
        evidence = extract_for_eml(
            file_bytes=file_bytes,
            sender=sender,
            subject=subject,
            context=context,
        )

        # 2. EML forensics findings and email_risk_boost
        eml_forensic_findings, email_boost = _parse_eml_findings(file_bytes)

        # 3. Deterministic text
        text_res = _analyze_text_content(
            content=evidence.extracted_text or f"Subject: {evidence.subject_declared}",
            channel_type="email",
            sender=evidence.sender_declared,
            subject=evidence.subject_declared,
        )
        det_findings: list[Finding] = eml_forensic_findings + list(text_res.findings)
        det_url_scores: dict[str, int] = {}

        for url in evidence.extracted_urls[:15]:
            u_res = _analyze_url_deterministic(url, inspect_links=False)
            det_url_scores[url] = u_res.risk_score
            det_findings.extend(u_res.findings)

        # Critical EML finding forces score
        if any(f.severity == FindingSeverity.CRITICAL for f in eml_forensic_findings):
            email_boost = max(email_boost, 85)

        # 4. Gemini
        gemini_content = evidence.extracted_text or f"Subject: {evidence.subject_declared}"
        gemini_res = _analyze_with_gemini(
            content=gemini_content,
            channel_type="email",
            deterministic_findings=det_findings,
        )

        # 5. Intelligence
        intel = _lookup_intelligence(evidence.extracted_domains)

        # 6. Fuse
        return self._fusion.fuse(
            evidence=evidence,
            deterministic_findings=det_findings,
            deterministic_url_scores=det_url_scores,
            deterministic_text_score=text_res.combined_risk_score,
            gemini_result=gemini_res,
            intelligence_results=intel,
            email_risk_boost=email_boost,
            highlights=list(text_res.highlights),
        )

    def _process_pdf(
        self,
        file_bytes: bytes,
        filename: str,
        sender: Optional[str] = None,
        subject: Optional[str] = None,
        context: Optional[str] = None,
    ) -> FusionResult:
        # 1. Canonical evidence (may return inconclusive for scanned PDFs)
        evidence = extract_for_pdf(
            file_bytes=file_bytes,
            filename=filename,
            sender=sender,
            subject=subject,
            context=context,
        )

        # Inconclusive path handled by fusion engine
        pdf_forensic_findings, _ = _parse_pdf_findings(file_bytes)

        # 2. Deterministic text + URL
        text_res = _analyze_text_content(
            content=evidence.extracted_text or f"PDF File: {filename}",
            channel_type="file",
            sender=sender,
            subject=subject or evidence.subject_declared,
        )
        det_findings: list[Finding] = pdf_forensic_findings + list(text_res.findings)
        det_url_scores: dict[str, int] = {}

        for url in evidence.extracted_urls[:15]:
            u_res = _analyze_url_deterministic(url, inspect_links=False)
            det_url_scores[url] = u_res.risk_score
            det_findings.extend(u_res.findings)

        # 3. Gemini
        gemini_res = _analyze_with_gemini(
            content=evidence.extracted_text or f"PDF File: {filename}",
            channel_type="file",
            deterministic_findings=det_findings,
        )

        # 4. Intelligence
        intel = _lookup_intelligence(evidence.extracted_domains)

        # 5. Fuse
        return self._fusion.fuse(
            evidence=evidence,
            deterministic_findings=det_findings,
            deterministic_url_scores=det_url_scores,
            deterministic_text_score=text_res.combined_risk_score,
            gemini_result=gemini_res,
            intelligence_results=intel,
            highlights=list(text_res.highlights),
        )

    def _process_screenshot(
        self,
        file_bytes: bytes,
        filename: str = "screenshot.png",
        context: Optional[str] = None,
    ) -> FusionResult:
        # 1. Canonical evidence (Gemini called inside; result cached in metadata)
        evidence = extract_for_screenshot(
            file_bytes=file_bytes,
            context=context,
            filename=filename,
        )

        # 2. If Gemini was available, reconstruct its result for the fusion engine
        #    from the cached metadata; otherwise pass None.
        gemini_res = self._build_gemini_result_from_screenshot_metadata(evidence)

        # 3. Deterministic URL analysis on any extracted URLs
        det_findings: list[Finding] = []
        det_url_scores: dict[str, int] = {}

        for url in evidence.extracted_urls[:15]:
            u_res = _analyze_url_deterministic(url, inspect_links=False)
            det_url_scores[url] = u_res.risk_score
            det_findings.extend(u_res.findings)

        # 4. Intelligence
        intel = _lookup_intelligence(evidence.extracted_domains)

        # 5. Fuse
        return self._fusion.fuse(
            evidence=evidence,
            deterministic_findings=det_findings,
            deterministic_url_scores=det_url_scores,
            deterministic_text_score=0,
            gemini_result=gemini_res,
            intelligence_results=intel,
            highlights=[],
        )

    @staticmethod
    def _build_gemini_result_from_screenshot_metadata(evidence: CanonicalEvidence):
        """
        Re-construct a lightweight GeminiAnalysisResult-compatible object from
        the cached screenshot metadata so the fusion engine can treat it uniformly.
        Returns None when Gemini was not available.
        """
        meta = evidence.metadata
        if not meta.get("gemini_available"):
            return None

        from schemas import Confidence, Finding, FindingCategory, FindingSeverity
        from dataclasses import dataclass, field as dc_field

        @dataclass
        class _FakGeminiResult:
            available: bool = True
            risk_score: int = 0
            explanation: str = ""
            recommendations: list = dc_field(default_factory=list)
            findings: list = dc_field(default_factory=list)
            confidence: Confidence = Confidence.MEDIUM
            error: str = ""

        raw_findings = meta.get("gemini_findings", [])
        findings = []
        for rf in raw_findings:
            try:
                findings.append(Finding(
                    category=FindingCategory(rf.get("category", "content")),
                    severity=FindingSeverity(rf.get("severity", "medium")),
                    evidence=rf.get("evidence", ""),
                    explanation=rf.get("explanation", ""),
                    recommended_action="Review this finding.",
                    source_module="gemini:screenshot",
                ))
            except (ValueError, KeyError):
                pass

        confidence_str = meta.get("gemini_confidence", "medium")
        try:
            confidence = Confidence(confidence_str)
        except ValueError:
            confidence = Confidence.MEDIUM

        return _FakGeminiResult(
            available=True,
            risk_score=meta.get("gemini_risk_score", 0) or 0,
            explanation=meta.get("gemini_explanation", ""),
            recommendations=list(meta.get("gemini_recommendations", [])),
            findings=findings,
            confidence=confidence,
        )


# Module-level singleton
unified_pipeline = UnifiedAnalysisPipeline()

