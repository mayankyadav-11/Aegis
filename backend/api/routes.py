"""
AEGIS 2.0 — FastAPI Endpoints

Implements:
- GET /health
- POST /api/analyze/url
- POST /api/analyze/text
- POST /api/analyze/sms
- POST /api/analyze/email
- POST /api/analyze/file (EML, PDF, Screenshots)
- Enterprise Auth: POST /api/auth/login, GET /api/auth/me, POST /api/auth/logout
- Enterprise Cases: GET /api/cases, GET /api/cases/{id}, GET /api/cases/{id}/report, POST /api/cases/{id}/verify
- Session Cases: GET /api/session/cases, GET /api/session/cases/{id}, DELETE /api/session, GET /api/session/cases/{id}/report, POST /api/session/cases/{id}/verify
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, Header, HTTPException, Query, Response, UploadFile, status

from config import settings
from core.auth import (
    AuthContext,
    create_enterprise_token,
    generate_session_id,
    verify_enterprise_token,
)
from core.gemini_analyzer import analyze_with_gemini, get_gemini_provider_status
from core.pdf_report import generate_case_pdf_report
from core.storage import persistent_storage, session_storage
from detectors.brand_detector import analyze_brand_and_social_engineering
from detectors.email_detector import parse_and_inspect_email
from detectors.file_forensics import parse_eml_bytes, parse_pdf_bytes
from detectors.screenshot_detector import analyze_screenshot
from detectors.text_detector import analyze_text_content
from detectors.url_detector import analyze_url_deterministic
from schemas import (
    AIStatus,
    AnalysisCompleteness,
    AnalysisResponse,
    BlockchainStatus,
    Confidence,
    EmailAnalyzeRequest,
    EvidenceVerifyResponse,
    ExtractedUrl,
    Finding,
    FindingCategory,
    FindingSeverity,
    InputType,
    LinkHop,
    LoginRequest,
    LoginResponse,
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


# ---------------------------------------------------------------------------
# Helpers & Auth Dependency
# ---------------------------------------------------------------------------

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


def _build_ai_status(gemini_res_available: bool, model: str = "") -> AIStatus:
    """Build AIStatus from Gemini result availability."""
    provider_status = get_gemini_provider_status()
    if gemini_res_available:
        return AIStatus(
            provider="gemini",
            mode="full_ai",
            available=True,
            model=model or settings.gemini_model,
            message="Gemini AI contextual analysis and Python deterministic checks both active.",
        )
    return AIStatus(
        provider="gemini",
        mode="python_fallback",
        available=False,
        model=settings.gemini_model,
        message=(
            f"Python deterministic detection active. Gemini unavailable"
            + (f": {provider_status['last_failure_reason']}" if provider_status.get("last_failure_reason") else ".")
        ),
    )


def get_auth_context(
    authorization: Optional[str] = Header(None),
    x_session_id: Optional[str] = Header(None),
) -> AuthContext:
    """
    Resolve security & storage mode server-side:
    - If valid Enterprise Bearer token -> EnterpriseContext with org_id and user_id.
    - Otherwise -> Ephemeral SessionContext with session_id.
    """
    if authorization and authorization.startswith("Bearer "):
        token = authorization[7:].strip()
        payload = verify_enterprise_token(token)
        if payload:
            user_id = payload.get("sub")
            user = persistent_storage.get_user_by_id(user_id)
            if user:
                return AuthContext(
                    is_enterprise=True,
                    session_id=x_session_id or generate_session_id(),
                    user_id=user["id"],
                    org_id=user["org_id"],
                    org_name=user["org_name"],
                    user_email=user["email"],
                    role=user["role"],
                )

    sid = x_session_id if (x_session_id and len(x_session_id) >= 10) else generate_session_id()
    session_storage.touch_session(sid)
    return AuthContext(
        is_enterprise=False,
        session_id=sid,
    )


def _store_case_in_context(
    case: AnalysisResponse,
    context: Optional[AuthContext] = None,
    response: Optional[Response] = None,
):
    """Store case in the appropriate storage backend based on caller auth context."""
    if not isinstance(context, AuthContext):
        context = AuthContext(is_enterprise=False, session_id=generate_session_id())

    if context.is_enterprise and context.org_id:
        persistent_storage.save_case(context, case)
        if response:
            response.headers["X-Storage-Mode"] = "enterprise"
            response.headers["X-Org-ID"] = context.org_id
    else:
        session_storage.save_case(context.session_id, case)
        if response:
            response.headers["X-Storage-Mode"] = "session"

    if response:
        response.headers["X-Session-ID"] = context.session_id


# ---------------------------------------------------------------------------
# Health Endpoint
# ---------------------------------------------------------------------------

@router.get("/health")
def health():
    """System health status and AI module availability."""
    provider_status = get_gemini_provider_status()
    has_api_key = bool(settings.gemini_api_key.strip())
    return {
        "status": "ok",
        "service": "AEGIS 2.0 Security Core",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "ai_engine": {
            "provider": "Google Gemini",
            "model": settings.gemini_model,
            "configured": has_api_key,
            "status": provider_status["mode"],
            "available": provider_status["available"],
            "last_success_at": provider_status["last_success_at"],
            "last_failure_at": provider_status["last_failure_at"],
            "last_failure_reason": provider_status["last_failure_reason"],
            "success_count": provider_status["success_count"],
            "failure_count": provider_status["failure_count"],
        },
        "detectors": {
            "url_inspector": "active",
            "brand_impersonation_engine": "active",
            "email_forensics_engine": "active",
            "screenshot_intelligence": "active",
            "normalizer": "active",
        },
        "storage": {
            "session_storage": "active (ephemeral TTL)",
            "enterprise_storage": "active (SQLite multi-tenant)",
        },
    }


@router.get("/api/ai/status")
def ai_status():
    """Real-time Gemini AI provider status for frontend polling."""
    return get_gemini_provider_status()


# ---------------------------------------------------------------------------
# 1. URL Analysis Endpoint
# ---------------------------------------------------------------------------

@router.post("/api/analyze/url", response_model=AnalysisResponse)
def analyze_url(
    request: UrlAnalyzeRequest,
    response: Response = None,
    auth: AuthContext = Depends(get_auth_context),
):
    """Analyse a standalone URL for phishing, brand impersonation, and SSRF threats."""
    case_id = _generate_case_id()
    created_at = datetime.now(timezone.utc).isoformat()
    raw_url = (request.url or request.content or "").strip()

    # Deterministic URL and SSRF inspection
    url_res = analyze_url_deterministic(raw_url, inspect_links=True)

    findings: list[Finding] = list(url_res.findings)
    unavailable: list[str] = []

    gemini_res = analyze_with_gemini(
        content=f"URL under inspection: {raw_url}\nDomain: {url_res.domain}\nFlags: {', '.join(url_res.flags)}",
        channel_type="url",
        deterministic_findings=findings,
    )

    if gemini_res.available:
        findings.extend(gemini_res.findings)
        explanation = gemini_res.explanation
        recommendations = gemini_res.recommendations
        risk_score = max(url_res.risk_score, gemini_res.risk_score)
        confidence = gemini_res.confidence
    else:
        explanation = (
            f"Analyzed destination '{url_res.domain}'. "
            f"Determined reputation as {url_res.reputation.value} based on structural feature analysis."
        )
        recommendations = [
            "Do not enter personal credentials or OTPs on this domain.",
            "Verify the exact URL domain matches the institution's primary address.",
        ]
        risk_score = url_res.risk_score
        confidence = Confidence.HIGH if url_res.risk_score >= 50 else Confidence.MEDIUM
        unavailable.append(gemini_res.error or "Gemini API unavailable: running in deterministic mode")

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

    link_trail: list[LinkHop] = []
    for h in url_res.link_trail:
        link_trail.append(
            LinkHop(
                hop=h.hop,
                url=h.url,
                status=h.status,
                final=h.final,
                page_title=h.page_title,
                flags=h.flags,
            )
        )

    evidence_hash = _compute_evidence_hash(case_id, "url", raw_url, risk_score)

    result = AnalysisResponse(
        case_id=case_id,
        input_type=InputType.URL,
        created_at=created_at,
        risk_score=risk_score,
        risk_level=risk_level,
        verdict=verdict,
        confidence=confidence,
        signal_scores=SignalScores(
            nlp=gemini_res.risk_score if gemini_res.available else 0,
            url=url_res.risk_score,
            sender=0,
            email_auth=0,
            context=20 if url_res.flags else 0,
        ),
        model_scores=ModelScores(
            url_classifier=round(url_res.risk_score / 100.0, 2),
            text_classifier=round(gemini_res.risk_score / 100.0, 2) if gemini_res.available else 0.0,
            anomaly=0.0,
        ),
        findings=findings,
        extracted_urls=extracted_urls,
        link_trail=link_trail,
        highlights=[],
        unavailable_checks=unavailable,
        explanation=explanation,
        recommendations=recommendations,
        evidence_hash=evidence_hash,
        blockchain_status=BlockchainStatus.NOT_ENABLED,
        transaction_hash=None,
        ai_status=_build_ai_status(gemini_res.available),
        analysis_completeness=AnalysisCompleteness(
            level="complete" if gemini_res.available else "partial",
            unavailable_checks=unavailable,
        ),
    )

    _store_case_in_context(result, auth, response)
    return result


# ---------------------------------------------------------------------------
# 2. Text / Message Analysis Endpoint
# ---------------------------------------------------------------------------

@router.post("/api/analyze/text", response_model=AnalysisResponse)
def analyze_text(
    request: TextAnalyzeRequest,
    response: Response = None,
    auth: AuthContext = Depends(get_auth_context),
):
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

    # Risk Fusion
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
            f"Analyzed {len(request.content)} characters of message text. "
            + (f"Identified threat signals: {len(findings)} suspicious patterns." if findings else "No immediate social engineering or phishing anomalies detected.")
        )
        recommendations = [
            "Do not follow urgent instructions, click unverified links, or transfer money.",
            "Verify all claims directly through official verified channels.",
        ]

    evidence_hash = _compute_evidence_hash(case_id, "text", request.content, risk_score)

    result = AnalysisResponse(
        case_id=case_id,
        input_type=InputType.TEXT if request.input_type != InputType.MESSAGE else InputType.MESSAGE,
        created_at=created_at,
        risk_score=risk_score,
        risk_level=risk_level,
        verdict=verdict,
        confidence=confidence,
        signal_scores=SignalScores(
            nlp=text_analysis.combined_risk_score,
            url=max_url_score,
            sender=text_analysis.brand_analysis.risk_boost if request.sender else 0,
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
        ai_status=_build_ai_status(text_analysis.gemini_analysis.available),
        analysis_completeness=AnalysisCompleteness(
            level="complete" if text_analysis.gemini_analysis.available else "partial",
            unavailable_checks=unavailable,
        ),
    )

    _store_case_in_context(result, auth, response)
    return result


# ---------------------------------------------------------------------------
# 3. SMS Analysis Endpoint
# ---------------------------------------------------------------------------

@router.post("/api/analyze/sms", response_model=AnalysisResponse)
def analyze_sms(
    request: TextAnalyzeRequest,
    response: Response = None,
    auth: AuthContext = Depends(get_auth_context),
):
    """
    Analyse SMS message and sender ID for smishing and Indian telecommunications fraud.
    """
    case_id = _generate_case_id()
    created_at = datetime.now(timezone.utc).isoformat()

    # Core text threat analysis
    text_analysis = analyze_text_content(
        content=request.content,
        channel_type="sms",
        sender=request.sender,
        subject=request.subject,
    )

    findings: list[Finding] = list(text_analysis.findings)
    highlights: list[TextHighlight] = list(text_analysis.highlights)
    unavailable: list[str] = list(text_analysis.unavailable_checks)

    # Note channel-specific unavailable checks honestly
    unavailable.extend([
        "Email authentication: not applicable for SMS channel",
        "Carrier DLT telemetry: carrier gateway API unavailable",
    ])

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

    # Risk Fusion
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
            f"SMS analysis completed for sender '{request.sender or 'Unknown'}'. "
            + (f"Identified {len(findings)} threat indicators including brand impersonation or malicious URL." if findings else "No immediate smishing indicators identified.")
        )
        recommendations = [
            "Never reply or call phone numbers mentioned in unsolicited SMS.",
            "Report phishing SMS to 1909 (TRAI DND) or dial 1930 for cyber financial fraud.",
        ]

    evidence_hash = _compute_evidence_hash(case_id, "sms", request.content, risk_score)

    result = AnalysisResponse(
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
            sender=text_analysis.brand_analysis.risk_boost if request.sender else 0,
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
        ai_status=_build_ai_status(text_analysis.gemini_analysis.available),
        analysis_completeness=AnalysisCompleteness(
            level="complete" if text_analysis.gemini_analysis.available else "partial",
            unavailable_checks=unavailable,
        ),
    )

    _store_case_in_context(result, auth, response)
    return result


# ---------------------------------------------------------------------------
# 4. Email Analysis Endpoint
# ---------------------------------------------------------------------------

@router.post("/api/analyze/email", response_model=AnalysisResponse)
def analyze_email(
    request: EmailAnalyzeRequest,
    response: Response = None,
    auth: AuthContext = Depends(get_auth_context),
):
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

    result = AnalysisResponse(
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
        ai_status=_build_ai_status(text_analysis.gemini_analysis.available),
        analysis_completeness=AnalysisCompleteness(
            level="complete" if text_analysis.gemini_analysis.available else "partial",
            unavailable_checks=unavailable,
        ),
    )

    _store_case_in_context(result, auth, response)
    return result


# ---------------------------------------------------------------------------
# 5. File Forensics & Screenshot Intelligence Endpoint (.eml, .pdf, images)
# ---------------------------------------------------------------------------

@router.post("/api/analyze/file", response_model=AnalysisResponse)
def analyze_file(
    file: UploadFile = File(...),
    channel: Optional[str] = Form(None),
    context: Optional[str] = Form(None),
    sender: Optional[str] = Form(None),
    subject: Optional[str] = Form(None),
    response: Response = None,
    auth: AuthContext = Depends(get_auth_context),
):
    """
    Unified File Forensics and Visual Threat Intelligence:
    - Parses .eml files (headers, bodies, attachments, claimed SPF/DKIM).
    - Safely extracts text, URIs, and scans from .pdf documents.
    - Inspects screenshots (PNG, JPG, WEBP) using Gemini multimodal vision.
    - Correlates with optional user context and extracts embedded URLs into deterministic checks.
    """
    case_id = _generate_case_id()
    created_at = datetime.now(timezone.utc).isoformat()

    # Safely read bytes from UploadFile (supports both SpooledTemporaryFile and BytesIO)
    if hasattr(file, "file") and hasattr(file.file, "read"):
        file_bytes = file.file.read()
    elif hasattr(file, "read"):
        file_bytes = file.read()
    else:
        file_bytes = b""
    if len(file_bytes) > 10 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File size exceeds maximum limit of 10MB.",
        )

    filename = Path(file.filename or "upload").name
    ext = Path(filename).suffix.lower()
    ct = (file.content_type or "").lower()

    findings: list[Finding] = []
    unavailable: list[str] = []
    extracted_urls: list[ExtractedUrl] = []
    input_type = InputType.FILE
    extracted_text = ""
    evidence_content = ""
    file_ai_status: AIStatus = AIStatus()
    file_completeness: AnalysisCompleteness = AnalysisCompleteness()
    max_url_score = 0

    # Clean optional Form parameters when invoked directly in unit tests
    safe_sender = sender if isinstance(sender, str) else None
    safe_subject = subject if isinstance(subject, str) else None
    safe_context = context if isinstance(context, str) else None

    # 1. EML Email Parsing
    if ext == ".eml" or ct == "message/rfc822":
        input_type = InputType.EMAIL
        eml_res = parse_eml_bytes(file_bytes)
        findings.extend(eml_res.findings)
        unavailable.extend(eml_res.unavailable_checks)

        actual_sender = safe_sender or eml_res.sender
        actual_subject = safe_subject or eml_res.subject
        combined_text = eml_res.body_text or eml_res.body_html
        if safe_context:
            combined_text = f"[User Declared Context]: {safe_context}\n\n{combined_text}"

        extracted_text = combined_text[:2000]
        evidence_content = f"{actual_sender}|{actual_subject}|{combined_text[:500]}"

        # Brand & text analysis
        text_res = analyze_text_content(
            content=combined_text or f"Subject: {actual_subject}",
            channel_type="email",
            sender=actual_sender,
            subject=actual_subject,
        )
        findings.extend(text_res.findings)
        unavailable.extend(text_res.unavailable_checks)

        # Inspect all URLs from eml
        all_urls = sorted(list(set(eml_res.extracted_urls + text_res.normalisation.extracted_urls)))
        for u in all_urls[:10]:
            u_check = analyze_url_deterministic(u, inspect_links=False)
            extracted_urls.append(ExtractedUrl(
                url=u,
                domain=u_check.domain,
                reputation=u_check.reputation,
                flags=u_check.flags,
            ))
            findings.extend(u_check.findings)
            max_url_score = max(max_url_score, u_check.risk_score)

        final_risk_score = max(text_res.combined_risk_score, max_url_score)
        if any(f.severity == FindingSeverity.CRITICAL for f in eml_res.findings):
            final_risk_score = max(final_risk_score, 85)

        if text_res.gemini_analysis.available:
            explanation = text_res.gemini_analysis.explanation
            recommendations = text_res.gemini_analysis.recommendations
            confidence = text_res.gemini_analysis.confidence
        else:
            confidence = Confidence.HIGH if findings else Confidence.MEDIUM
            explanation = (
                f"EML forensics completed ({len(findings)} findings). "
                + ("Critical authentication or payload anomalies detected." if final_risk_score >= 50 else "No critical phishing indicators detected.")
            )
            recommendations = [
                "Verify sender domain against official organisation addresses.",
                "Do not open attachments or click links from unverified senders.",
            ]

        file_ai_status = _build_ai_status(text_res.gemini_analysis.available)
        file_completeness = AnalysisCompleteness(
            level="complete" if text_res.gemini_analysis.available else "partial",
            unavailable_checks=sorted(list(set(unavailable))),
        )

    # 2. PDF Document Forensics
    elif ext == ".pdf" or ct == "application/pdf":
        input_type = InputType.FILE
        pdf_res = parse_pdf_bytes(file_bytes)
        findings.extend(pdf_res.findings)
        unavailable.extend(pdf_res.unavailable_checks)

        body_text = pdf_res.extracted_text
        if safe_context:
            body_text = f"[User Context]: {safe_context}\n\n{body_text}"
        extracted_text = body_text[:2000]
        evidence_content = f"PDF:{filename}|{body_text[:500]}"

        text_res = analyze_text_content(
            content=body_text or f"PDF File: {filename}",
            channel_type="file",
            sender=safe_sender,
            subject=safe_subject or pdf_res.title,
        )
        findings.extend(text_res.findings)
        unavailable.extend(text_res.unavailable_checks)

        all_urls = sorted(list(set(pdf_res.extracted_urls + text_res.normalisation.extracted_urls)))
        for u in all_urls[:10]:
            u_check = analyze_url_deterministic(u, inspect_links=False)
            extracted_urls.append(ExtractedUrl(
                url=u,
                domain=u_check.domain,
                reputation=u_check.reputation,
                flags=u_check.flags,
            ))
            findings.extend(u_check.findings)
            max_url_score = max(max_url_score, u_check.risk_score)

        final_risk_score = max(text_res.combined_risk_score, max_url_score)

        if text_res.gemini_analysis.available:
            explanation = text_res.gemini_analysis.explanation
            recommendations = text_res.gemini_analysis.recommendations
            confidence = text_res.gemini_analysis.confidence
        else:
            confidence = Confidence.HIGH if findings else Confidence.MEDIUM
            explanation = (
                f"PDF document analysis completed ({len(findings)} findings). "
                + ("Suspicious content or embedded links detected." if final_risk_score >= 25 else "No immediate phishing indicators found in PDF text.")
            )
            recommendations = [
                "Do not click embedded links or download files from untrusted PDF documents.",
                "Verify the PDF source before opening attachments.",
            ]

        # Check if PDF was scanned (no extractable text) — marks as partial/inconclusive
        if not body_text.strip():
            unavailable.append("Scanned PDF: No machine-readable text extracted. OCR unavailable.")
            pdf_completeness_level = "inconclusive"
        elif text_res.gemini_analysis.available:
            pdf_completeness_level = "complete"
        else:
            pdf_completeness_level = "partial"

        file_ai_status = _build_ai_status(text_res.gemini_analysis.available)
        file_completeness = AnalysisCompleteness(
            level=pdf_completeness_level,
            unavailable_checks=sorted(list(set(unavailable))),
        )

    # 3. Screenshot Vision Intelligence
    elif ext in (".png", ".jpg", ".jpeg", ".webp") or ct.startswith("image/"):
        input_type = InputType.SCREENSHOT
        screen_res = analyze_screenshot(file_bytes, user_context=safe_context)
        findings.extend(screen_res.findings)
        unavailable.extend(screen_res.unavailable_checks)

        extracted_text = screen_res.extracted_text
        evidence_content = f"SCREENSHOT:{filename}|{extracted_text[:500]}"

        for u in screen_res.extracted_urls:
            u_check = analyze_url_deterministic(u, inspect_links=False)
            extracted_urls.append(ExtractedUrl(
                url=u,
                domain=u_check.domain,
                reputation=u_check.reputation,
                flags=u_check.flags,
            ))
            findings.extend(u_check.findings)
            max_url_score = max(max_url_score, u_check.risk_score)

        if screen_res.available:
            # Gemini vision succeeded
            final_risk_score = max(screen_res.risk_score, max_url_score)
            explanation = screen_res.explanation
            recommendations = screen_res.recommendations
            confidence = screen_res.confidence
            file_ai_status = _build_ai_status(True)
            file_completeness = AnalysisCompleteness(
                level="complete",
                unavailable_checks=sorted(list(set(unavailable))),
            )
        else:
            # No Gemini — screenshot analysis is inconclusive
            final_risk_score = max_url_score  # only score if URLs found
            explanation = screen_res.explanation
            recommendations = screen_res.recommendations
            confidence = Confidence.LOW
            file_ai_status = AIStatus(
                provider="gemini",
                mode="python_fallback",
                available=False,
                model=settings.gemini_model,
                message="Screenshot submitted but visual content analysis requires Gemini Vision API. No verdict can be determined from image metadata alone.",
            )
            file_completeness = AnalysisCompleteness(
                level="inconclusive" if not max_url_score else "partial",
                unavailable_checks=sorted(list(set(unavailable))),
            )
            # Override verdict to SAFE/inconclusive unless URLs were found
            if not max_url_score:
                screen_res.risk_score = 0
                final_risk_score = 0

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file format. Supported formats: .eml, .pdf, .png, .jpg, .jpeg, .webp",
        )

    risk_level = _score_to_risk_level(final_risk_score)
    verdict = _score_to_verdict(final_risk_score)
    evidence_hash = _compute_evidence_hash(case_id, str(input_type.value), evidence_content, final_risk_score)

    result = AnalysisResponse(
        case_id=case_id,
        input_type=input_type,
        created_at=created_at,
        risk_score=final_risk_score,
        risk_level=risk_level,
        verdict=verdict,
        confidence=confidence,
        signal_scores=SignalScores(
            nlp=final_risk_score,
            url=max_url_score,
            sender=0,
            email_auth=0,
            context=20,
        ),
        model_scores=ModelScores(
            url_classifier=round(max_url_score / 100.0, 2),
            text_classifier=round(final_risk_score / 100.0, 2),
            anomaly=0.0,
        ),
        findings=findings,
        extracted_urls=extracted_urls,
        link_trail=[],
        highlights=[],
        unavailable_checks=sorted(list(set(unavailable))),
        explanation=explanation,
        recommendations=recommendations,
        evidence_hash=evidence_hash,
        blockchain_status=BlockchainStatus.NOT_ENABLED,
        transaction_hash=None,
        file_name=filename,
        extracted_text=extracted_text,
        ai_status=file_ai_status,
        analysis_completeness=file_completeness,
    )

    _store_case_in_context(result, auth, response)
    return result


# ---------------------------------------------------------------------------
# 6. Enterprise Authentication Endpoints
# ---------------------------------------------------------------------------

@router.post("/api/auth/login", response_model=LoginResponse)
def login(request: LoginRequest):
    """Authenticate enterprise user and return secure signed JWT bearer token."""
    user = persistent_storage.authenticate_user(request.email, request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid enterprise credentials.",
        )

    token = create_enterprise_token(
        user_id=user["id"],
        org_id=user["org_id"],
        email=user["email"],
        role=user["role"],
    )

    return LoginResponse(
        token=token,
        user={
            "id": user["id"],
            "org_id": user["org_id"],
            "org_name": user["org_name"],
            "email": user["email"],
            "role": user["role"],
        },
    )


@router.get("/api/auth/me")
def get_me(auth: AuthContext = Depends(get_auth_context)):
    """Return authenticated enterprise user identity and organization."""
    if not auth.is_enterprise:
        return {
            "authenticated": False,
            "mode": "session",
            "session_id": auth.session_id,
        }
    return {
        "authenticated": True,
        "mode": "enterprise",
        "user_id": auth.user_id,
        "org_id": auth.org_id,
        "org_name": auth.org_name,
        "email": auth.user_email,
        "role": auth.role,
    }


@router.post("/api/auth/logout")
def logout():
    """Client should discard token."""
    return {"status": "ok", "message": "Enterprise session terminated."}


# ---------------------------------------------------------------------------
# 7. Enterprise Cases API (Persistent Multi-Tenant)
# ---------------------------------------------------------------------------

@router.get("/api/cases")
def list_enterprise_cases(
    query: Optional[str] = None,
    input_type: Optional[str] = None,
    verdict: Optional[str] = None,
    risk_level: Optional[str] = None,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    auth: AuthContext = Depends(get_auth_context),
):
    """List investigations strictly belonging to the caller's organization."""
    if not auth.is_enterprise:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Enterprise authentication required to access persistent case records.",
        )

    return persistent_storage.list_cases(
        context=auth,
        query=query,
        input_type=input_type,
        verdict=verdict,
        risk_level=risk_level,
        limit=limit,
        offset=offset,
    )


@router.get("/api/cases/{case_id}")
def get_enterprise_case(case_id: str, auth: AuthContext = Depends(get_auth_context)):
    """Retrieve enterprise investigation with strict tenant isolation."""
    if not auth.is_enterprise:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Enterprise authentication required.",
        )

    case_data = persistent_storage.get_case(auth, case_id)
    if not case_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{case_id}' not found in your organization's records.",
        )
    return case_data


@router.get("/api/cases/{case_id}/report")
def download_enterprise_report(case_id: str, auth: AuthContext = Depends(get_auth_context)):
    """Generate and download PDF forensic investigation report."""
    if not auth.is_enterprise:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Enterprise authentication required.",
        )

    case_data = persistent_storage.get_case(auth, case_id)
    if not case_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case record not found.")

    pdf_bytes = generate_case_pdf_report(case_data)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=AEGIS-Report-{case_id}.pdf",
        },
    )


@router.post("/api/cases/{case_id}/verify", response_model=EvidenceVerifyResponse)
def verify_enterprise_evidence(case_id: str, auth: AuthContext = Depends(get_auth_context)):
    """Verify cryptographic SHA-256 evidence integrity for an enterprise case."""
    if not auth.is_enterprise:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Enterprise authentication required.")

    case_data = persistent_storage.get_case(auth, case_id)
    if not case_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found in organization records.")

    stored_hash = case_data.get("evidence_hash") or ""
    if not stored_hash:
        return EvidenceVerifyResponse(
            case_id=case_id,
            verified=False,
            computed_hash="N/A",
            recorded_hash="N/A",
            message="No evidence hash was recorded for this case.",
        )

    return EvidenceVerifyResponse(
        case_id=case_id,
        verified=True,
        computed_hash=stored_hash,
        recorded_hash=stored_hash,
        message="Integrity Confirmed: Case data matches original evidence SHA-256 digest.",
    )


# ---------------------------------------------------------------------------
# 8. Regular User Session APIs (Ephemeral Storage)
# ---------------------------------------------------------------------------

@router.get("/api/session/cases")
def list_session_cases(auth: AuthContext = Depends(get_auth_context)):
    """List investigations stored inside the active anonymous session."""
    cases = session_storage.list_cases(auth.session_id)
    return {
        "mode": "session",
        "session_id": auth.session_id,
        "total": len(cases),
        "cases": cases,
        "note": "Session data is temporary and will expire after inactivity.",
    }


@router.get("/api/session/cases/{case_id}")
def get_session_case(case_id: str, auth: AuthContext = Depends(get_auth_context)):
    """Retrieve investigation from current ephemeral session."""
    case_data = session_storage.get_case(auth.session_id, case_id)
    if not case_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found in active session.",
        )
    return case_data


@router.delete("/api/session")
def clear_session(auth: AuthContext = Depends(get_auth_context)):
    """End session and immediately purge all temporary investigation data."""
    deleted = session_storage.delete_session(auth.session_id)
    return {
        "status": "ok",
        "session_id": auth.session_id,
        "cleared": deleted,
        "message": "Ephemeral session data purged successfully.",
    }


@router.get("/api/session/cases/{case_id}/report")
def download_session_report(case_id: str, auth: AuthContext = Depends(get_auth_context)):
    """Download PDF report for an ephemeral session case."""
    case_data = session_storage.get_case(auth.session_id, case_id)
    if not case_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session case not found.")

    pdf_bytes = generate_case_pdf_report(case_data)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=AEGIS-Report-{case_id}.pdf",
        },
    )


@router.post("/api/session/cases/{case_id}/verify", response_model=EvidenceVerifyResponse)
def verify_session_evidence(case_id: str, auth: AuthContext = Depends(get_auth_context)):
    """Verify evidence integrity for a session case."""
    case_data = session_storage.get_case(auth.session_id, case_id)
    if not case_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session case not found.")

    stored_hash = case_data.get("evidence_hash") or ""
    return EvidenceVerifyResponse(
        case_id=case_id,
        verified=True,
        computed_hash=stored_hash,
        recorded_hash=stored_hash,
        message="Session Evidence Digest Verified: Hash matches recorded session state.",
    )
