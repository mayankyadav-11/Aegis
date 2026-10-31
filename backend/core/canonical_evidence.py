"""
AEGIS 2.0 — Canonical Evidence Extractor

Converts every supported input type into a standardised CanonicalEvidence object
that the unified pipeline and evidence fusion engine can process consistently.

Supported channels:
  - Text / Message
  - SMS
  - URL
  - Email (raw .eml content or API payload)
  - EML file (bytes)
  - PDF file (bytes)
  - Screenshot image (bytes) — extraction requires Gemini Vision; gracefully
    marks extraction_status as "inconclusive" when unavailable.

Design principles:
  - Reuses existing detectors: file_forensics, screenshot_detector, normalizer.
  - Never duplicates URL extraction, domain normalisation, or brand detection.
  - Never executes uploaded file contents.
  - URL normalisation through tldextract where available; urlparse fallback.
  - extraction_status: "complete" | "partial" | "inconclusive"
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

try:
    import tldextract
    _extractor = tldextract.TLDExtract(suffix_list_urls=None)
except ImportError:
    tldextract = None
    _extractor = None


# ---------------------------------------------------------------------------
# URL regex (shared with normalizer / file_forensics — keep in sync)
# ---------------------------------------------------------------------------

_URL_REGEX = re.compile(
    r"""(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»""'']))""",
    re.VERBOSE,
)


def _extract_domain(url: str) -> str:
    """Return the registered domain (or host) for a URL string."""
    try:
        if _extractor is not None:
            extracted = _extractor(url)
            if extracted.domain and extracted.suffix:
                return f"{extracted.domain}.{extracted.suffix}"
        parsed = urlparse(url if "://" in url else f"https://{url}")
        host = parsed.netloc or parsed.path.split("/")[0]
        return host.lower().split(":")[0]
    except Exception:
        return url[:100]


def _extract_urls_from_text(text: str) -> list[str]:
    """Extract URLs from arbitrary text using the shared regex."""
    if not text:
        return []
    matches = _URL_REGEX.findall(text)
    urls: list[str] = []
    for m in matches:
        url = m[0] if isinstance(m, tuple) else m
        url = url.strip().rstrip(".,;)")
        if url:
            urls.append(url)
    return list(dict.fromkeys(urls))  # deduplicate, preserve order


def _domains_from_urls(urls: list[str]) -> list[str]:
    """Return deduplicated domain list from a URL list."""
    seen: list[str] = []
    for u in urls:
        d = _extract_domain(u)
        if d and d not in seen:
            seen.append(d)
    return seen


# ---------------------------------------------------------------------------
# CanonicalEvidence dataclass
# ---------------------------------------------------------------------------

@dataclass
class CanonicalEvidence:
    """
    Standardised evidence container produced from any supported input type.

    Fields:
      input_type           : one of "text", "sms", "url", "email", "file", "screenshot"
      raw_content          : original submitted string / filename / URL (for hash/audit)
      extracted_text       : normalised body text to run NLP and brand detection on
      extracted_urls       : deduplicated, ordered list of URLs found in the content
      extracted_domains    : deduplicated domain strings derived from extracted_urls
      sender_declared      : sender string as declared by the submitter (may be spoofed)
      subject_declared     : subject line (email / file)
      email_headers        : raw header map from EML forensics (empty for non-email)
      attachments          : list of attachment metadata dicts (from EML forensics)
      extraction_status    : "complete" | "partial" | "inconclusive"
      unavailable_checks   : list of checks that could not be performed
      metadata             : channel-specific extras (e.g. PDF title, image dims)
    """

    input_type: str
    raw_content: str
    extracted_text: str
    extracted_urls: list[str] = field(default_factory=list)
    extracted_domains: list[str] = field(default_factory=list)
    sender_declared: Optional[str] = None
    subject_declared: Optional[str] = None
    email_headers: dict = field(default_factory=dict)
    attachments: list[dict] = field(default_factory=list)
    extraction_status: str = "complete"   # "complete" | "partial" | "inconclusive"
    unavailable_checks: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Extractor functions — one per input channel
# ---------------------------------------------------------------------------

def extract_for_text(
    content: str,
    sender: Optional[str] = None,
    subject: Optional[str] = None,
    channel_type: str = "text",
) -> CanonicalEvidence:
    """
    Build CanonicalEvidence from free-form text (Message / Text channel).
    URL extraction uses the shared regex.
    """
    from core.normalizer import normalise
    norm = normalise(content)

    urls = _extract_urls_from_text(norm.normalised or content)
    domains = _domains_from_urls(urls)

    return CanonicalEvidence(
        input_type=channel_type,
        raw_content=content,
        extracted_text=norm.normalised or content,
        extracted_urls=urls,
        extracted_domains=domains,
        sender_declared=sender,
        subject_declared=subject,
        extraction_status="complete",
        metadata={
            "zero_width_count": norm.zero_width_count,
            "homoglyph_count": norm.homoglyph_count,
        },
    )


def extract_for_url(url: str) -> CanonicalEvidence:
    """
    Build CanonicalEvidence from a standalone URL submission.
    """
    url = url.strip()
    domain = _extract_domain(url)

    return CanonicalEvidence(
        input_type="url",
        raw_content=url,
        extracted_text=url,
        extracted_urls=[url],
        extracted_domains=[domain] if domain else [],
        extraction_status="complete",
        metadata={"single_url": True},
    )


def extract_for_email(
    content: str,
    sender: Optional[str] = None,
    subject: Optional[str] = None,
    raw_headers: Optional[str] = None,
) -> CanonicalEvidence:
    """
    Build CanonicalEvidence from a raw email body / API text payload.
    Uses parse_and_inspect_email internally to harvest headers and body.
    """
    from detectors.email_detector import parse_and_inspect_email
    from core.normalizer import normalise

    email_res = parse_and_inspect_email(
        raw_content=content,
        explicit_sender=sender,
        explicit_subject=subject,
        raw_headers=raw_headers,
    )

    body = email_res.extracted_body or content
    norm = normalise(body)
    urls = _extract_urls_from_text(norm.normalised or body)
    domains = _domains_from_urls(urls)

    return CanonicalEvidence(
        input_type="email",
        raw_content=content,
        extracted_text=norm.normalised or body,
        extracted_urls=urls,
        extracted_domains=domains,
        sender_declared=email_res.sender_email or sender,
        subject_declared=email_res.subject or subject,
        email_headers={
            "spf": getattr(email_res, "spf_result", None),
            "dkim": getattr(email_res, "dkim_result", None),
            "dmarc": getattr(email_res, "dmarc_result", None),
            "reply_to": getattr(email_res, "reply_to", None),
            "return_path": getattr(email_res, "return_path", None),
        },
        extraction_status="complete",
        metadata={"risk_boost": email_res.risk_boost},
    )


def extract_for_eml(
    file_bytes: bytes,
    sender: Optional[str] = None,
    subject: Optional[str] = None,
    context: Optional[str] = None,
) -> CanonicalEvidence:
    """
    Build CanonicalEvidence from raw .eml bytes using the file_forensics parser.
    """
    from detectors.file_forensics import parse_eml_bytes
    from core.normalizer import normalise

    eml_res = parse_eml_bytes(file_bytes)

    actual_sender = sender or eml_res.sender
    actual_subject = subject or eml_res.subject
    body = eml_res.body_text or eml_res.body_html or ""
    if context:
        body = f"[User Context]: {context}\n\n{body}"

    norm = normalise(body)
    text_urls = _extract_urls_from_text(norm.normalised or body)
    all_urls = list(dict.fromkeys(eml_res.extracted_urls + text_urls))
    domains = _domains_from_urls(all_urls)

    unavailable = list(eml_res.unavailable_checks)

    return CanonicalEvidence(
        input_type="file",
        raw_content=f"EML:{actual_sender}|{actual_subject}",
        extracted_text=body[:4000],
        extracted_urls=all_urls[:20],
        extracted_domains=domains,
        sender_declared=actual_sender,
        subject_declared=actual_subject,
        email_headers={
            "received_headers": eml_res.received_headers,
            "auth_results": eml_res.auth_results_headers,
            "reply_to": eml_res.reply_to,
            "message_id": eml_res.message_id,
            "date": eml_res.date,
        },
        attachments=eml_res.attachments,
        extraction_status="complete",
        unavailable_checks=unavailable,
        metadata={"eml_findings_count": len(eml_res.findings)},
    )


def extract_for_pdf(
    file_bytes: bytes,
    filename: str = "document.pdf",
    sender: Optional[str] = None,
    subject: Optional[str] = None,
    context: Optional[str] = None,
) -> CanonicalEvidence:
    """
    Build CanonicalEvidence from PDF bytes using the file_forensics parser.
    Marks extraction_status as "inconclusive" when no machine-readable text is found (scanned PDF).
    """
    from detectors.file_forensics import parse_pdf_bytes
    from core.normalizer import normalise

    pdf_res = parse_pdf_bytes(file_bytes)

    body = pdf_res.extracted_text or ""
    if context:
        body = f"[User Context]: {context}\n\n{body}"

    norm = normalise(body)
    text_urls = _extract_urls_from_text(norm.normalised or body)
    all_urls = list(dict.fromkeys(pdf_res.extracted_urls + text_urls))
    domains = _domains_from_urls(all_urls)

    if not pdf_res.extracted_text.strip():
        status = "inconclusive"
        unavailable = list(pdf_res.unavailable_checks) + [
            "Scanned PDF: No machine-readable text extracted. OCR unavailable."
        ]
    else:
        status = "complete"
        unavailable = list(pdf_res.unavailable_checks)

    return CanonicalEvidence(
        input_type="file",
        raw_content=f"PDF:{filename}|{body[:200]}",
        extracted_text=body[:4000],
        extracted_urls=all_urls[:20],
        extracted_domains=domains,
        sender_declared=sender,
        subject_declared=subject or pdf_res.title,
        extraction_status=status,
        unavailable_checks=unavailable,
        metadata={
            "pdf_title": pdf_res.title,
            "pdf_author": pdf_res.author,
            "pdf_findings_count": len(pdf_res.findings),
        },
    )


def extract_for_screenshot(
    file_bytes: bytes,
    context: Optional[str] = None,
    filename: str = "screenshot.png",
) -> CanonicalEvidence:
    """
    Build CanonicalEvidence from screenshot bytes.

    When Gemini Vision is available: extracts text and URLs from the image.
    When Gemini Vision is unavailable: extraction_status is "inconclusive";
      extracted_text and extracted_urls remain empty — do NOT fabricate content.
    """
    from detectors.screenshot_detector import analyze_screenshot

    screen_res = analyze_screenshot(file_bytes, user_context=context)

    if screen_res.available:
        urls = list(dict.fromkeys(screen_res.extracted_urls))
        domains = _domains_from_urls(urls)
        status = "complete"
        unavailable: list[str] = []
    else:
        urls = []
        domains = []
        status = "inconclusive"
        unavailable = [
            "Screenshot visual content analysis requires Gemini Vision. "
            "No text or URL extraction possible without AI. Analysis is inconclusive."
        ] + list(screen_res.unavailable_checks)

    return CanonicalEvidence(
        input_type="screenshot",
        raw_content=f"SCREENSHOT:{filename}|{screen_res.extracted_text[:200]}",
        extracted_text=screen_res.extracted_text,
        extracted_urls=urls,
        extracted_domains=domains,
        extraction_status=status,
        unavailable_checks=unavailable,
        metadata={
            "gemini_available": screen_res.available,
            "gemini_risk_score": screen_res.risk_score if screen_res.available else None,
            "gemini_findings": [
                {
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "evidence": f.evidence,
                    "explanation": f.explanation,
                }
                for f in screen_res.findings
            ],
            "gemini_explanation": screen_res.explanation if screen_res.available else "",
            "gemini_recommendations": screen_res.recommendations if screen_res.available else [],
            "gemini_confidence": screen_res.confidence.value if screen_res.available else "low",
        },
    )

