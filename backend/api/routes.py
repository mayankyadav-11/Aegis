"""
AEGIS 2.0 — FastAPI Endpoints

Implements:
- GET /health
- POST /api/analyze/url
- POST /api/analyze/text
- POST /api/analyze/sms
- POST /api/analyze/email

Every analysis endpoint strictly returns the PRD Section 8 canonical AnalysisResponse schema.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter

from config import settings
from core.gemini_analyzer import analyze_with_gemini
from detectors.brand_detector import analyze_brand_and_social_engineering
from detectors.email_detector import parse_and_inspect_email
from detectors.text_detector import analyze_text_content
from detectors.url_detector import analyze_url_deterministic
from schemas import (
    AnalysisResponse,
    BlockchainStatus,
    Confidence,
    EmailAnalyzeRequest,
    ExtractedUrl,
    Finding,
    FindingCategory,
    FindingSeverity,
    InputType,
    LinkHop,
    ModelScores,
    RiskLevel,
    SignalScores,
    TextAnalyzeRequest,
    TextHighlight,
    UrlAnalyzeRequest,
    UrlReputation,
    Verdict,
)

router = APIRouter()


def _generate_case_id() -> str:
    """Generate unique case ID in the format AEG-YYYY-XXXX."""
    random_hex = uuid.uuid4().hex[:6].upper()
    return f"AEG-{datetime.now(timezone.utc).year}-{random_hex}"


def _score_to_risk_level(score: int) -> RiskLevel:
    if score >= 80:
        return RiskLevel.CRITICAL
    elif score >= 55:
        return RiskLevel.HIGH
    elif score >= 25:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _score_to_verdict(score: int) -> Verdict:
    if score >= 55:
        return Verdict.MALICIOUS
    elif score >= 25:
        return Verdict.SUSPICIOUS
    return Verdict.SAFE


def _compute_evidence_hash(case_id: str, input_type: str, content: str, risk_score: int) -> str:
    """Compute SHA-256 digest of the canonical evidence."""
    payload = f"{case_id}|{input_type}|{risk_score}|{content}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Health Endpoint
# ---------------------------------------------------------------------------

@router.get("/health")
def health():
    """System health status and AI module availability."""
    has_api_key = bool(settings.gemini_api_key.strip())
    return {
        "status": "ok",
        "service": "AEGIS 2.0 Security Core",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ai_engine": {
            "provider": "Google Gemini",
            "model": settings.gemini_model,
            "configured": has_api_key,
            "status": "ready" if has_api_key else "fallback_deterministic_mode",
        },
        "detectors": {
            "url_inspector": "active",
            "brand_impersonation_engine": "active",
            "email_forensics_engine": "active",
            "normalizer": "active",
        },
    }


# ---------------------------------------------------------------------------
# 1. URL Analysis Endpoint
# ---------------------------------------------------------------------------

@router.post("/api/analyze/url", response_model=AnalysisResponse)
def analyze_url(request: UrlAnalyzeRequest):
    """
    Analyse a standalone URL for phishing, brand impersonation, and SSRF threats.
    """
    case_id = _generate_case_id()
    created_at = datetime.now(timezone.utc).isoformat()
    raw_url = (request.url or request.content or "").strip()

    # Deterministic URL and SSRF inspection
    url_res = analyze_url_deterministic(raw_url, inspect_links=True)

    findings: list[Finding] = list(url_res.findings)
    unavailable: list[str] = []

    # Contextual Gemini check if available
    gemini_res = analyze_with_gemini(
        content=f"URL: {raw_url}\nDomain: {url_res.domain}\nFlags: {', '.join(url_res.flags)}",
        channel_type="url",
        deterministic_findings=findings,
    )

    if gemini_res.available:
        findings.extend(gemini_res.findings)
        risk_score = max(url_res.risk_score, gemini_res.risk_score)
        explanation = gemini_res.explanation
        recommendations = gemini_res.recommendations
        confidence = gemini_res.confidence
    else:
        risk_score = url_res.risk_score
        confidence = Confidence.HIGH if url_res.flags else Confidence.MEDIUM
        explanation = (
            f"Deterministic URL evaluation for '{url_res.domain}'. "
            + (f"Threat flags identified: {', '.join(url_res.flags)}." if url_res.flags else "No immediate URL anomalies detected.")
        )
        recommendations = [
            "Never submit sensitive passwords or banking credentials on unverified domains.",
            "Verify the destination domain against official institutional records.",
        ]
        if gemini_res.error:
            unavailable.append(f"AI Contextual Engine: {gemini_res.error}")

    risk_level = _score_to_risk_level(risk_score)
    verdict = _score_to_verdict(risk_score)

    extracted_urls = [
        ExtractedUrl(
            url=raw_url,
            domain=url_res.domain,
            reputation=url_res.reputation,
            flags=url_res.flags,
        )
    ]

    evidence_hash = _compute_evidence_hash(case_id, "url", raw_url, risk_score)

    return AnalysisResponse(
        case_id=case_id,
        input_type=InputType.URL,
        created_at=created_at,
        risk_score=risk_score,
        risk_level=risk_level,
        verdict=verdict,
        confidence=confidence,
        signal_scores=SignalScores(
            url=risk_score,
            nlp=0,
            sender=0,
            email_auth=0,
            context=min(100, len(url_res.flags) * 20),
        ),
        model_scores=ModelScores(
            url_classifier=round(risk_score / 100.0, 2),
            text_classifier=0.0,
            anomaly=0.0,
        ),
        findings=findings,
        extracted_urls=extracted_urls,
        link_trail=url_res.link_trail,
        highlights=[],
        unavailable_checks=unavailable,
        explanation=explanation,
        recommendations=recommendations,
        evidence_hash=evidence_hash,
        blockchain_status=BlockchainStatus.NOT_ENABLED,
        transaction_hash=None,
    )


# ---------------------------------------------------------------------------
# 2. Text / Message Analysis Endpoint
# ---------------------------------------------------------------------------

@router.post("/api/analyze/text", response_model=AnalysisResponse)
def analyze_text(request: TextAnalyzeRequest):
    """
    Analyse freeform message text from WhatsApp, Telegram, or other chat platforms.
    """
    case_id = _generate_case_id()
    created_at = datetime.now(timezone.utc).isoformat()

    # Core text threat analysis (Normaliser + Brand Engine + Gemini)
    text_analysis = analyze_text_content(
        content=request.content,
        channel_type="text",
        sender=request.sender,
        subject=request.subject,
    )

    findings: list[Finding] = list(text_analysis.findings)
    highlights: list[TextHighlight] = list(text_analysis.highlights)
    unavailable: list[str] = list(text_analysis.unavailable_checks)

    # Inspect all embedded URLs
    extracted_urls: list[ExtractedUrl] = []
    link_trail: list[LinkHop] = []
    max_url_score = 0

    for extracted_url in text_analysis.normalisation.extracted_urls:
        url_res = analyze_url_deterministic(extracted_url, inspect_links=False)
        extracted_urls.append(ExtractedUrl(
            url=extracted_url,
            domain=url_res.domain,
            reputation=url_res.reputation,
            flags=url_res.flags,
        ))
        findings.extend(url_res.findings)
        max_url_score = max(max_url_score, url_res.risk_score)
        if url_res.link_trail:
            link_trail.extend(url_res.link_trail)

    # Fuse scores
    risk_score = max(text_analysis.combined_risk_score, max_url_score)
    risk_level = _score_to_risk_level(risk_score)
    verdict = _score_to_verdict(risk_score)

    if text_analysis.gemini_analysis.available:
        explanation = text_analysis.gemini_analysis.explanation
        recommendations = text_analysis.gemini_analysis.recommendations
        confidence = text_analysis.gemini_analysis.confidence
    else:
        confidence = Confidence.HIGH if findings else Confidence.MEDIUM
        explanation = (
            f"Deterministic security evaluation identified {len(findings)} indicator(s). "
            + ("High-risk social engineering or brand impersonation patterns detected." if risk_score >= 50 else "No overt phishing patterns detected.")
        )
        recommendations = [
            "Never click on unsolicited links received in messaging apps.",
            "Report suspicious messages to the Indian Cybercrime Helpline at 1930.",
        ]

    evidence_hash = _compute_evidence_hash(case_id, "text", request.content, risk_score)

    return AnalysisResponse(
        case_id=case_id,
        input_type=InputType.MESSAGE if request.input_type == InputType.MESSAGE else InputType.TEXT,
        created_at=created_at,
        risk_score=risk_score,
        risk_level=risk_level,
        verdict=verdict,
        confidence=confidence,
        signal_scores=SignalScores(
            nlp=text_analysis.combined_risk_score,
            url=max_url_score,
            sender=text_analysis.brand_analysis.risk_boost,
            email_auth=0,
            context=min(100, len(findings) * 15),
        ),
        model_scores=ModelScores(
            url_classifier=round(max_url_score / 100.0, 2),
            text_classifier=round(text_analysis.combined_risk_score / 100.0, 2),
            anomaly=0.0,
        ),
        findings=findings,
        extracted_urls=extracted_urls,
        link_trail=link_trail,
        highlights=highlights,
        unavailable_checks=unavailable,
        explanation=explanation,
        recommendations=recommendations,
        evidence_hash=evidence_hash,
        blockchain_status=BlockchainStatus.NOT_ENABLED,
        transaction_hash=None,
    )


# ---------------------------------------------------------------------------
# 3. SMS Analysis Endpoint
# ---------------------------------------------------------------------------

@router.post("/api/analyze/sms", response_model=AnalysisResponse)
def analyze_sms(request: TextAnalyzeRequest):
    """
    Analyse SMS text for bank suspension, KYC, UPI refund, electricity, and TRAI DLT headers.
    """
    case_id = _generate_case_id()
    created_at = datetime.now(timezone.utc).isoformat()

    text_analysis = analyze_text_content(
        content=request.content,
        channel_type="sms",
        sender=request.sender,
        subject=None,
    )

    findings: list[Finding] = list(text_analysis.findings)
    highlights: list[TextHighlight] = list(text_analysis.highlights)
    unavailable: list[str] = list(text_analysis.unavailable_checks)
    unavailable.append("Carrier DLT Gateway Verification: Telecom operator API not connected")

    extracted_urls: list[ExtractedUrl] = []
    link_trail: list[LinkHop] = []
    max_url_score = 0

    for extracted_url in text_analysis.normalisation.extracted_urls:
        url_res = analyze_url_deterministic(extracted_url, inspect_links=False)
        extracted_urls.append(ExtractedUrl(
            url=extracted_url,
            domain=url_res.domain,
            reputation=url_res.reputation,
            flags=url_res.flags,
        ))
        findings.extend(url_res.findings)
        max_url_score = max(max_url_score, url_res.risk_score)
        if url_res.link_trail:
            link_trail.extend(url_res.link_trail)

    risk_score = max(text_analysis.combined_risk_score, max_url_score)
    risk_level = _score_to_risk_level(risk_score)
    verdict = _score_to_verdict(risk_score)

    if text_analysis.gemini_analysis.available:
        explanation = text_analysis.gemini_analysis.explanation
        recommendations = text_analysis.gemini_analysis.recommendations
        confidence = text_analysis.gemini_analysis.confidence
    else:
        confidence = Confidence.HIGH if findings else Confidence.MEDIUM
        explanation = (
            f"SMS analysis completed. Identified {len(findings)} threat signal(s). "
            + ("High-risk financial urgency and brand spoofing patterns present." if risk_score >= 50 else "Message shows standard transactional/promotional characteristics.")
        )
        recommendations = [
            "Never tap links in unsolicited SMS messages.",
            "Forward fraudulent SMS to 1909 (TRAI DND) or dial 1930.",
        ]

    evidence_hash = _compute_evidence_hash(case_id, "sms", request.content, risk_score)

    return AnalysisResponse(
        case_id=case_id,
        input_type=InputType.SMS,
        created_at=created_at,
        risk_score=risk_score,
        risk_level=risk_level,
        verdict=verdict,
        confidence=confidence,
        signal_scores=SignalScores(
            nlp=text_analysis.combined_risk_score,
            url=max_url_score,
            sender=text_analysis.brand_analysis.risk_boost,
            email_auth=0,
            context=min(100, len(findings) * 20),
        ),
        model_scores=ModelScores(
            url_classifier=round(max_url_score / 100.0, 2),
            text_classifier=round(text_analysis.combined_risk_score / 100.0, 2),
            anomaly=0.0,
        ),
        findings=findings,
        extracted_urls=extracted_urls,
        link_trail=link_trail,
        highlights=highlights,
        unavailable_checks=unavailable,
        explanation=explanation,
        recommendations=recommendations,
        evidence_hash=evidence_hash,
        blockchain_status=BlockchainStatus.NOT_ENABLED,
        transaction_hash=None,
    )


# ---------------------------------------------------------------------------
# 4. Email Analysis Endpoint
# ---------------------------------------------------------------------------

@router.post("/api/analyze/email", response_model=AnalysisResponse)
def analyze_email(request: EmailAnalyzeRequest):
    """
    Analyse raw email or .eml payload for display name spoofing, reply-to mismatch,
    header forensics (SPF/DKIM/DMARC status), and body content phishing.
    """
    case_id = _generate_case_id()
    created_at = datetime.now(timezone.utc).isoformat()

    # 1. Deterministic Email Forensics (Headers, Sender, Display Name)
    email_res = parse_and_inspect_email(
        raw_content=request.content,
        explicit_sender=request.sender,
        explicit_subject=request.subject,
        raw_headers=request.raw_headers,
    )

    # 2. Text Analysis on Email Body
    text_analysis = analyze_text_content(
        content=email_res.extracted_body,
        channel_type="email",
        sender=email_res.sender_email,
        subject=email_res.subject,
    )

    findings: list[Finding] = list(email_res.findings) + list(text_analysis.findings)
    highlights: list[TextHighlight] = list(text_analysis.highlights)
    unavailable: list[str] = list(email_res.unavailable_checks) + list(text_analysis.unavailable_checks)

    # 3. Inspect Embedded URLs
    extracted_urls: list[ExtractedUrl] = []
    link_trail: list[LinkHop] = []
    max_url_score = 0

    for extracted_url in text_analysis.normalisation.extracted_urls:
        url_res = analyze_url_deterministic(extracted_url, inspect_links=False)
        extracted_urls.append(ExtractedUrl(
            url=extracted_url,
            domain=url_res.domain,
            reputation=url_res.reputation,
            flags=url_res.flags,
        ))
        findings.extend(url_res.findings)
        max_url_score = max(max_url_score, url_res.risk_score)
        if url_res.link_trail:
            link_trail.extend(url_res.link_trail)

    # Combine scores
    risk_score = max(email_res.risk_boost, text_analysis.combined_risk_score, max_url_score)
    risk_level = _score_to_risk_level(risk_score)
    verdict = _score_to_verdict(risk_score)

    if text_analysis.gemini_analysis.available:
        explanation = text_analysis.gemini_analysis.explanation
        recommendations = text_analysis.gemini_analysis.recommendations
        confidence = text_analysis.gemini_analysis.confidence
    else:
        confidence = Confidence.HIGH if findings else Confidence.MEDIUM
        explanation = (
            f"Email forensics and body inspection completed ({len(findings)} findings). "
            + ("Direct sender impersonation, authentication anomaly, or phishing payload identified." if risk_score >= 50 else "No critical email authentication or phishing indicators detected.")
        )
        recommendations = [
            "Check the full email headers and verify sender domain carefully.",
            "Do not open attachments or click links from unverified senders.",
        ]

    evidence_hash = _compute_evidence_hash(case_id, "email", request.content, risk_score)

    return AnalysisResponse(
        case_id=case_id,
        input_type=InputType.EMAIL,
        created_at=created_at,
        risk_score=risk_score,
        risk_level=risk_level,
        verdict=verdict,
        confidence=confidence,
        signal_scores=SignalScores(
            nlp=text_analysis.combined_risk_score,
            url=max_url_score,
            sender=email_res.risk_boost,
            email_auth=email_res.risk_boost if (email_res.spf_result == "fail" or email_res.dkim_result == "fail") else 0,
            context=min(100, len(findings) * 15),
        ),
        model_scores=ModelScores(
            url_classifier=round(max_url_score / 100.0, 2),
            text_classifier=round(text_analysis.combined_risk_score / 100.0, 2),
            anomaly=0.0,
        ),
        findings=findings,
        extracted_urls=extracted_urls,
        link_trail=link_trail,
        highlights=highlights,
        unavailable_checks=unavailable,
        explanation=explanation,
        recommendations=recommendations,
        evidence_hash=evidence_hash,
        blockchain_status=BlockchainStatus.NOT_ENABLED,
        transaction_hash=None,
    )
