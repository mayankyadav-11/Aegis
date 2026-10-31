"""
AEGIS 2.0 — File Forensics (.eml and .pdf)

Safely parses email (.eml) and document (.pdf) files in-memory:
- Extracts headers, bodies, embedded links, and attachment metadata.
- Distinguishes received authentication headers from independent DNS verification.
- Detects display-name spoofing, Reply-To mismatches, and dangerous attachment formats.
- Extracts text and links from PDFs without executing embedded code.
- Detects scanned / image-only PDFs with honest disclosure.
"""

from __future__ import annotations

import email
import email.policy
import io
import re
from dataclasses import dataclass, field
from typing import Optional

from pypdf import PdfReader

from schemas import ExtractedUrl, Finding, FindingCategory, FindingSeverity, UrlReputation


URL_REGEX = re.compile(
    r"""(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))"""
)
HREF_REGEX = re.compile(r'href=["\'](https?://[^"\'>\s]+)["\']', re.IGNORECASE)

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".iso", ".img", ".hta", ".cpl", ".msc",
    ".jar", ".com", ".pif",
}


@dataclass
class EmlForensicResult:
    subject: str = ""
    sender: str = ""
    reply_to: Optional[str] = None
    to: str = ""
    date: str = ""
    message_id: str = ""
    received_headers: list[str] = field(default_factory=list)
    auth_results_headers: list[str] = field(default_factory=list)
    body_text: str = ""
    body_html: str = ""
    extracted_urls: list[str] = field(default_factory=list)
    attachments: list[dict] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    unavailable_checks: list[str] = field(default_factory=list)


@dataclass
class PdfForensicResult:
    title: Optional[str] = None
    author: Optional[str] = None
    creator: Optional[str] = None
    page_count: int = 0
    extracted_text: str = ""
    extracted_urls: list[str] = field(default_factory=list)
    is_scanned_or_empty: bool = False
    findings: list[Finding] = field(default_factory=list)
    unavailable_checks: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 1. Safe .eml Parsing
# ---------------------------------------------------------------------------

def parse_eml_bytes(file_bytes: bytes) -> EmlForensicResult:
    """Parse raw .eml file bytes into forensic email components safely in-memory."""
    result = EmlForensicResult()

    try:
        msg = email.message_from_bytes(file_bytes, policy=email.policy.default)
    except Exception as e:
        result.findings.append(
            Finding(
                category=FindingCategory.EMAIL_AUTH,
                severity=FindingSeverity.HIGH,
                evidence=f"Corrupt or malformed email RFC format",
                explanation=f"Email message failed standard RFC parser: {str(e)[:80]}",
                recommended_action="Treat email with extreme suspicion. Malformed headers often indicate evasion attempts.",
                source_module="eml_forensic_parser",
            )
        )
        return result

    # Extract primary headers
    result.subject = str(msg.get("subject", "") or "")
    result.sender = str(msg.get("from", "") or "")
    result.reply_to = str(msg.get("reply-to", "") or "") or None
    result.to = str(msg.get("to", "") or "")
    result.date = str(msg.get("date", "") or "")
    result.message_id = str(msg.get("message-id", "") or "")

    # Multi-value headers
    for r in msg.get_all("received", []):
        result.received_headers.append(str(r).strip())
    for a in msg.get_all("authentication-results", []):
        result.auth_results_headers.append(str(a).strip())

    # Body extraction & attachment inspection
    found_urls = set()

    for part in msg.walk():
        content_disposition = str(part.get_content_disposition() or "").lower()
        content_type = str(part.get_content_type() or "").lower()
        filename = part.get_filename()

        if filename or content_disposition == "attachment":
            fn = str(filename or "unnamed_attachment")
            size = len(part.get_payload(decode=True) or b"")
            ext = "." + fn.split(".")[-1].lower() if "." in fn else ""

            att_info = {
                "filename": fn,
                "content_type": content_type,
                "size_bytes": size,
                "extension": ext,
            }
            result.attachments.append(att_info)

            # Check dangerous extensions
            if ext in DANGEROUS_EXTENSIONS:
                result.findings.append(
                    Finding(
                        category=FindingCategory.CONTENT,
                        severity=FindingSeverity.CRITICAL,
                        evidence=f"Executable/script attachment detected: '{fn}' ({content_type})",
                        explanation="Attackers use dangerous file extensions to execute malware, steal credentials, or drop spyware upon opening.",
                        recommended_action="Do NOT open or extract this attachment. Block sender at gateway.",
                        source_module="eml_attachment_inspector",
                    )
                )
        elif content_type == "text/plain":
            try:
                payload = part.get_content()
                if isinstance(payload, str):
                    result.body_text += "\n" + payload
            except Exception:
                pass
        elif content_type == "text/html":
            try:
                payload = part.get_content()
                if isinstance(payload, str):
                    result.body_html += "\n" + payload
                    for href in HREF_REGEX.findall(payload):
                        found_urls.add(href)
            except Exception:
                pass

    # Extract URLs from plain text as well
    for match in URL_REGEX.finditer(result.body_text):
        url = match.group(0).strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        found_urls.add(url)

    result.extracted_urls = sorted(list(found_urls))

    # Forensic checks: Reply-To Mismatch
    if result.reply_to and result.sender:
        from_match = re.search(r"@([\w.-]+)", result.sender)
        reply_match = re.search(r"@([\w.-]+)", result.reply_to)
        if from_match and reply_match:
            from_domain = from_match.group(1).lower()
            reply_domain = reply_match.group(1).lower()
            if from_domain != reply_domain:
                result.findings.append(
                    Finding(
                        category=FindingCategory.IMPERSONATION,
                        severity=FindingSeverity.HIGH,
                        evidence=f"Reply-To mismatch: Sender '@{from_domain}' vs Reply-To '@{reply_domain}'",
                        explanation="Phishers frequently display a legitimate brand address in From while directing responses to an attacker-controlled server in Reply-To.",
                        recommended_action="Do not reply. Verify legitimacy through verified external channels.",
                        source_module="eml_header_inspector",
                    )
                )

    # Forensic checks: Display Name Spoofing
    # E.g. "State Bank of India" <bad-actor@gmail.com>
    if result.sender and ("<" in result.sender and ">" in result.sender):
        display_part = result.sender.split("<")[0].strip(' "\'')
        addr_part = result.sender.split("<")[1].split(">")[0].strip().lower()
        known_brands = ["sbi", "hdfc", "icici", "google", "microsoft", "amazon", "paypal", "income tax", "rbi"]
        for brand in known_brands:
            if brand in display_part.lower() and brand not in addr_part:
                result.findings.append(
                    Finding(
                        category=FindingCategory.IMPERSONATION,
                        severity=FindingSeverity.HIGH,
                        evidence=f"Display-name spoofing: Display '{display_part}' contradicts mailbox '{addr_part}'",
                        explanation=f"Claimed organization '{display_part}' does not match the actual sending domain '{addr_part}'.",
                        recommended_action="Mark email as phishing and report to security team.",
                        source_module="eml_display_name_inspector",
                    )
                )
                break

    # Authentication-Results disclosure
    if result.auth_results_headers:
        # Honest disclosure: these are header claims, not independently verified
        combined_claims = " | ".join(result.auth_results_headers[:2])
        if "spf=fail" in combined_claims.lower() or "dkim=fail" in combined_claims.lower():
            result.findings.append(
                Finding(
                    category=FindingCategory.EMAIL_AUTH,
                    severity=FindingSeverity.HIGH,
                    evidence=f"Header Authentication-Results indicates failure: {combined_claims[:100]}",
                    explanation="Received headers record an SPF or DKIM validation failure by an intermediate mail relay.",
                    recommended_action="Treat email as spoofed.",
                    source_module="eml_auth_header_inspector",
                )
            )
        result.unavailable_checks.append(
            "DKIM/SPF Live DNS Verification: Read from received email headers; independent cryptographic key validation not executed."
        )
    else:
        result.unavailable_checks.append(
            "Email Authentication-Results header missing from uploaded .eml payload."
        )

    return result


# ---------------------------------------------------------------------------
# 2. Safe .pdf Parsing
# ---------------------------------------------------------------------------

def parse_pdf_bytes(file_bytes: bytes) -> PdfForensicResult:
    """Parse raw .pdf file bytes into forensic text and links safely in-memory."""
    result = PdfForensicResult()

    try:
        reader = PdfReader(io.BytesIO(file_bytes))
        result.page_count = len(reader.pages)

        # Metadata
        if reader.metadata:
            result.title = reader.metadata.title
            result.author = reader.metadata.author
            result.creator = reader.metadata.creator

        extracted_text_parts = []
        found_urls = set()

        # Limit to 25 pages and 100,000 characters to prevent resource exhaustion
        max_pages = min(result.page_count, 25)
        total_chars = 0

        for page_idx in range(max_pages):
            page = reader.pages[page_idx]

            # 1. Page text
            t = page.extract_text() or ""
            if t:
                extracted_text_parts.append(t)
                total_chars += len(t)

            # 2. Page annotations / Link URIs
            if "/Annots" in page:
                try:
                    annots = page["/Annots"]
                    if annots:
                        for a in annots:
                            annot_obj = a.get_object() if hasattr(a, "get_object") else a
                            if annot_obj and "/A" in annot_obj:
                                action = annot_obj["/A"]
                                if action and "/URI" in action:
                                    uri = str(action["/URI"]).strip()
                                    if uri.startswith("http://") or uri.startswith("https://"):
                                        found_urls.add(uri)
                except Exception:
                    pass

            if total_chars > 100_000:
                break

        full_text = "\n\n".join(extracted_text_parts)
        result.extracted_text = full_text

        # Extract text-based URLs
        for match in URL_REGEX.finditer(full_text):
            url = match.group(0).strip()
            if not url.startswith("http://") and not url.startswith("https://"):
                url = "http://" + url
            found_urls.add(url)

        result.extracted_urls = sorted(list(found_urls))

        # Check if scanned / image-only
        if len(full_text.strip()) < 40:
            result.is_scanned_or_empty = True
            result.findings.append(
                Finding(
                    category=FindingCategory.CONTENT,
                    severity=FindingSeverity.MEDIUM,
                    evidence="Scanned or image-only PDF document detected",
                    explanation="This PDF contains minimal or no extractable digital text layer (likely a flattened graphic or scan).",
                    recommended_action="Inspect the document visually or use multimodal vision analysis to review contents.",
                    source_module="pdf_forensic_inspector",
                )
            )
            result.unavailable_checks.append(
                "PDF Text Extraction: Document is image-only / scanned; optical OCR requires multimodal engine."
            )

    except Exception as e:
        result.findings.append(
            Finding(
                category=FindingCategory.CONTENT,
                severity=FindingSeverity.HIGH,
                evidence=f"PDF parsing error: {str(e)[:80]}",
                explanation="The PDF could not be completely parsed by standard readers. It may be encrypted, password-protected, or corrupted.",
                recommended_action="Do not open password-protected PDFs from untrusted sources.",
                source_module="pdf_forensic_inspector",
            )
        )
        result.unavailable_checks.append("PDF parsing halted due to encrypted or non-standard structure.")

    return result

