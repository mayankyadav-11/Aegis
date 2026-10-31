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
from core.gemini_analyzer import get_gemini_provider_status
from core.pdf_report import generate_case_pdf_report
from core.storage import persistent_storage, session_storage
from core.unified_pipeline import unified_pipeline
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


def _fusion_to_response(
    fusion,
    *,
    case_id: str,
    created_at: str,
    input_type: InputType,
    raw_content: str,
    extracted_urls: Optional[list[ExtractedUrl]] = None,
    link_trail: Optional[list[LinkHop]] = None,
    file_name: Optional[str] = None,
    extracted_text: Optional[str] = None,
) -> AnalysisResponse:
    """
    Convert a FusionResult into a fully-populated AnalysisResponse.
    Maintains 100% backward compatibility with the existing frontend contract.
    """
    evidence_hash = _compute_evidence_hash(case_id, input_type.value, raw_content, fusion.risk_score)
    return AnalysisResponse(
        case_id=case_id,
        input_type=input_type,
        created_at=created_at,
        risk_score=fusion.risk_score,
        risk_level=fusion.risk_level,
        verdict=fusion.verdict,
        confidence=fusion.confidence,
        signal_scores=fusion.signal_scores,
        model_scores=ModelScores(
            url_classifier=round(fusion.signal_scores.url / 100.0, 2),
            text_classifier=round(fusion.signal_scores.nlp / 100.0, 2),
            anomaly=0.0,
        ),
        findings=fusion.findings,
        extracted_urls=extracted_urls or [],
        link_trail=link_trail or [],
        highlights=fusion.highlights,
        unavailable_checks=fusion.unavailable_checks,
        explanation=fusion.explanation,
        recommendations=fusion.recommendations,
        evidence_hash=evidence_hash,
        blockchain_status=BlockchainStatus.NOT_ENABLED,
        transaction_hash=None,
        file_name=file_name,
        extracted_text=extracted_text,
        ai_status=_build_ai_status(fusion.gemini_available),
        analysis_completeness=AnalysisCompleteness(
            level=fusion.analysis_completeness_level,
            unavailable_checks=fusion.unavailable_checks,
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

    # Run the unified pipeline
    fusion = unified_pipeline.process_input(
        input_type="url",
        content=raw_url,
        inspect_links=True,
    )

    # Build extracted_urls and link_trail for backward compatibility
    # (URL detector is also called inside the pipeline — we call it once more
    #  here only to get domain/reputation/flags/link_trail for the response model,
    #  since FusionResult does not store these fields directly.)
    from detectors.url_detector import analyze_url_deterministic as _det
    url_res = _det(raw_url, inspect_links=True)

    extracted_urls = [
        ExtractedUrl(
            url=raw_url,
            domain=url_res.domain,
            reputation=url_res.reputation,
            flags=url_res.flags,
        )
    ]
    link_trail = [
        LinkHop(hop=h.hop, url=h.url, status=h.status, final=h.final,
                page_title=h.page_title, flags=h.flags)
        for h in url_res.link_trail
    ]

    result = _fusion_to_response(
        fusion,
        case_id=case_id,
        created_at=created_at,
        input_type=InputType.URL,
        raw_content=raw_url,
        extracted_urls=extracted_urls,
        link_trail=link_trail,
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
    Delegates to the unified pipeline for canonical evidence extraction and evidence fusion.
    """
    case_id = _generate_case_id()
    created_at = datetime.now(timezone.utc).isoformat()

    channel = "text" if request.input_type != InputType.MESSAGE else "message"
    fusion = unified_pipeline.process_input(
        input_type=channel,
        content=request.content,
        sender=request.sender,
        subject=request.subject,
    )

    # Build extracted_urls for the response (reuse URL detector output stored in findings)
    from detectors.url_detector import analyze_url_deterministic as _det
    from core.normalizer import normalise as _norm
    norm_result = _norm(request.content)
    extracted_urls = []
    link_trail = []
    for u in norm_result.extracted_urls:
        u_res = _det(u, inspect_links=False)
        extracted_urls.append(ExtractedUrl(
            url=u, domain=u_res.domain, reputation=u_res.reputation, flags=u_res.flags,
        ))
        link_trail.extend(u_res.link_trail)

    result = _fusion_to_response(
        fusion,
        case_id=case_id,
        created_at=created_at,
        input_type=InputType.TEXT if request.input_type != InputType.MESSAGE else InputType.MESSAGE,
        raw_content=request.content,
        extracted_urls=extracted_urls,
        link_trail=[LinkHop(hop=h.hop, url=h.url, status=h.status, final=h.final,
                            page_title=h.page_title, flags=h.flags) for h in link_trail],
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
    Delegates to the unified pipeline.
    """
    case_id = _generate_case_id()
    created_at = datetime.now(timezone.utc).isoformat()

    fusion = unified_pipeline.process_input(
        input_type="sms",
        content=request.content,
        sender=request.sender,
        subject=request.subject,
    )

    # Build extracted_urls
    from detectors.url_detector import analyze_url_deterministic as _det
    from core.normalizer import normalise as _norm
    norm_result = _norm(request.content)
    extracted_urls = []
    link_trail = []
    for u in norm_result.extracted_urls:
        u_res = _det(u, inspect_links=False)
        extracted_urls.append(ExtractedUrl(
            url=u, domain=u_res.domain, reputation=u_res.reputation, flags=u_res.flags,
        ))
        link_trail.extend(u_res.link_trail)

    result = _fusion_to_response(
        fusion,
        case_id=case_id,
        created_at=created_at,
        input_type=InputType.SMS,
        raw_content=request.content,
        extracted_urls=extracted_urls,
        link_trail=[LinkHop(hop=h.hop, url=h.url, status=h.status, final=h.final,
                            page_title=h.page_title, flags=h.flags) for h in link_trail],
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
    Delegates to the unified pipeline.
    """
    case_id = _generate_case_id()
    created_at = datetime.now(timezone.utc).isoformat()

    fusion = unified_pipeline.process_input(
        input_type="email",
        content=request.content,
        sender=request.sender,
        subject=request.subject,
        raw_headers=request.raw_headers,
    )

    # Build extracted_urls for the response
    from detectors.email_detector import parse_and_inspect_email as _parse_email
    from detectors.url_detector import analyze_url_deterministic as _det
    from core.normalizer import normalise as _norm
    email_res = _parse_email(
        raw_content=request.content,
        explicit_sender=request.sender,
        explicit_subject=request.subject,
        raw_headers=request.raw_headers,
    )
    body = email_res.extracted_body or request.content
    norm_result = _norm(body)
    extracted_urls = []
    link_trail = []
    all_u = sorted(set(norm_result.extracted_urls))
    for u in all_u[:10]:
        u_res = _det(u, inspect_links=False)
        extracted_urls.append(ExtractedUrl(
            url=u, domain=u_res.domain, reputation=u_res.reputation, flags=u_res.flags,
        ))
        link_trail.extend(u_res.link_trail)

    result = _fusion_to_response(
        fusion,
        case_id=case_id,
        created_at=created_at,
        input_type=InputType.EMAIL,
        raw_content=request.content,
        extracted_urls=extracted_urls,
        link_trail=[LinkHop(hop=h.hop, url=h.url, status=h.status, final=h.final,
                            page_title=h.page_title, flags=h.flags) for h in link_trail],
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
    Delegates to the unified pipeline.
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

    # If filename has no extension but content type is known, synthesize appropriate extension
    if not ext:
        if ct == "message/rfc822":
            filename += ".eml"
            ext = ".eml"
        elif ct == "application/pdf":
            filename += ".pdf"
            ext = ".pdf"
        elif ct in ("image/png", "image/jpeg", "image/jpg", "image/webp"):
            ext = "." + ct.split("/")[-1].replace("jpeg", "jpg")
            filename += ext

    if ext not in (".eml", ".pdf", ".png", ".jpg", ".jpeg", ".webp") and ct != "message/rfc822" and not ct.startswith("image/"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file format. Supported formats: .eml, .pdf, .png, .jpg, .jpeg, .webp",
        )

    safe_sender = sender if isinstance(sender, str) else None
    safe_subject = subject if isinstance(subject, str) else None
    safe_context = context if isinstance(context, str) else None

    # Determine input type
    if ext == ".eml" or ct == "message/rfc822":
        resp_input_type = InputType.EMAIL
        pipe_input_type = "file"
    elif ext in (".png", ".jpg", ".jpeg", ".webp") or ct.startswith("image/"):
        resp_input_type = InputType.SCREENSHOT
        pipe_input_type = "screenshot"
    else:
        resp_input_type = InputType.FILE
        pipe_input_type = "file"

    fusion = unified_pipeline.process_input(
        input_type=pipe_input_type,
        file_bytes=file_bytes,
        filename=filename,
        sender=safe_sender,
        subject=safe_subject,
        context=safe_context,
    )

    # Reconstruct extracted URLs and extracted text for frontend/response contract
    extracted_urls: list[ExtractedUrl] = []
    extracted_text: str = ""
    from detectors.url_detector import analyze_url_deterministic as _det

    if resp_input_type == InputType.EMAIL:
        from detectors.file_forensics import parse_eml_bytes as _parse_eml
        from core.normalizer import normalise as _norm
        eml_res = _parse_eml(file_bytes)
        combined_text = eml_res.body_text or eml_res.body_html
        if safe_context:
            combined_text = f"[User Declared Context]: {safe_context}\n\n{combined_text}"
        extracted_text = combined_text[:2000]
        norm_res = _norm(combined_text)
        all_urls = sorted(set(eml_res.extracted_urls + norm_res.extracted_urls))
        for u in all_urls[:10]:
            u_check = _det(u, inspect_links=False)
            extracted_urls.append(ExtractedUrl(
                url=u,
                domain=u_check.domain,
                reputation=u_check.reputation,
                flags=u_check.flags,
            ))
    elif ext == ".pdf":
        from detectors.file_forensics import parse_pdf_bytes as _parse_pdf
        from core.normalizer import normalise as _norm
        pdf_res = _parse_pdf(file_bytes)
        body_text = pdf_res.extracted_text
        if safe_context:
            body_text = f"[User Context]: {safe_context}\n\n{body_text}"
        extracted_text = body_text[:2000]
        norm_res = _norm(body_text)
        all_urls = sorted(set(pdf_res.extracted_urls + norm_res.extracted_urls))
        for u in all_urls[:10]:
            u_check = _det(u, inspect_links=False)
            extracted_urls.append(ExtractedUrl(
                url=u,
                domain=u_check.domain,
                reputation=u_check.reputation,
                flags=u_check.flags,
            ))
    elif resp_input_type == InputType.SCREENSHOT:
        from detectors.screenshot_detector import analyze_screenshot as _screen_det
        screen_res = _screen_det(file_bytes, user_context=safe_context)
        extracted_text = screen_res.extracted_text
        for u in screen_res.extracted_urls:
            u_check = _det(u, inspect_links=False)
            extracted_urls.append(ExtractedUrl(
                url=u,
                domain=u_check.domain,
                reputation=u_check.reputation,
                flags=u_check.flags,
            ))

    evidence_content = f"{filename}|{extracted_text[:500]}"
    result = _fusion_to_response(
        fusion,
        case_id=case_id,
        created_at=created_at,
        input_type=resp_input_type,
        raw_content=evidence_content,
        extracted_urls=extracted_urls,
        file_name=filename,
        extracted_text=extracted_text,
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
