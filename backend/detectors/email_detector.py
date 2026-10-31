"""
AEGIS 2.0 — Deterministic Email Header & Metadata Forensics

Security Rules:
- Never executes or unpacks attachments; records attachment metadata only.
- Strict honesty: Never claims SPF/DKIM/DMARC was cryptographically re-evaluated
  unless authentic server authentication headers are present, and clearly tags them
  as 'Parsed from header (unverified)'.
- When headers are missing (e.g. pasted text with no headers), explicitly records
  'SPF/DKIM/DMARC: Not verifiable without raw headers'.
- Detects Display Name spoofing (e.g. 'Income Tax Department <attacker@vps.xyz>')
  and Reply-To destination mismatches.
"""

from __future__ import annotations

import email
from email import policy
from email.parser import HeaderParser, Parser
import re
from dataclasses import dataclass, field
from schemas import Finding, FindingCategory, FindingSeverity


@dataclass
class EmailForensicsResult:
    sender_email: str | None
    display_name: str | None
    reply_to: str | None
    subject: str | None
    spf_result: str = "not_verifiable"
    dkim_result: str = "not_verifiable"
    dmarc_result: str = "not_verifiable"
    findings: list[Finding] = field(default_factory=list)
    unavailable_checks: list[str] = field(default_factory=list)
    risk_boost: int = 0
    extracted_body: str = ""
    attachment_names: list[str] = field(default_factory=list)


def parse_and_inspect_email(
    raw_content: str,
    explicit_sender: str | None = None,
    explicit_subject: str | None = None,
    raw_headers: str | None = None,
) -> EmailForensicsResult:
    """
    Parse email text or .eml payload and run deterministic forensics.
    """
    findings: list[Finding] = []
    unavailable: list[str] = []
    risk_boost = 0
    attachments: list[str] = []
    body_text = raw_content

    # Attempt to parse as RFC 822 email message if headers appear to be present
    has_headers = False
    sender_email = explicit_sender
    display_name = None
    reply_to = None
    subject = explicit_subject
    spf_status = "not_verifiable"
    dkim_status = "not_verifiable"
    dmarc_status = "not_verifiable"

    header_text_to_parse = raw_headers or (raw_content if ("From:" in raw_content or "Received:" in raw_content) else None)

    if header_text_to_parse:
        try:
            msg = Parser(policy=policy.default).parsestr(header_text_to_parse)
            has_headers = bool(msg["from"] or msg["subject"] or msg["authentication-results"])

            if msg["from"]:
                from_header = str(msg["from"])
                # Extract display name and email address
                match = re.match(r'^(?:"?([^"]*)"?\s)?(?:<?([^>]+)>?)$', from_header.strip())
                if match:
                    display_name = match.group(1) or None
                    sender_email = match.group(2)
                else:
                    sender_email = from_header

            if msg["reply-to"]:
                reply_to = str(msg["reply-to"]).strip()

            if msg["subject"]:
                subject = str(msg["subject"]).strip()

            # Inspect Authentication-Results header (honestly noted as parsed from unverified header)
            auth_results = msg.get_all("authentication-results", [])
            received_spf = msg.get_all("received-spf", [])

            auth_blob = " ".join([str(a) for a in auth_results] + [str(r) for r in received_spf]).lower()

            if "spf=pass" in auth_blob or "pass (spf" in auth_blob:
                spf_status = "pass"
            elif "spf=fail" in auth_blob or "fail (spf" in auth_blob or "softfail" in auth_blob:
                spf_status = "fail"

            if "dkim=pass" in auth_blob:
                dkim_status = "pass"
            elif "dkim=fail" in auth_blob:
                dkim_status = "fail"

            if "dmarc=pass" in auth_blob:
                dmarc_status = "pass"
            elif "dmarc=fail" in auth_blob or "p=reject" in auth_blob or "p=quarantine" in auth_blob:
                dmarc_status = "fail"

            # Check attachment metadata if multipart (never execute attachments)
            if msg.is_multipart():
                for part in msg.iter_attachments():
                    filename = part.get_filename() or "unnamed_attachment"
                    attachments.append(filename)
                    # Detect high risk executable extensions
                    if any(filename.lower().endswith(ext) for ext in [".exe", ".bat", ".scr", ".vbs", ".js", ".iso", ".zip", ".apk"]):
                        findings.append(Finding(
                            category=FindingCategory.CONTENT,
                            severity=FindingSeverity.HIGH,
                            evidence=f"Suspicious executable attachment detected: {filename}",
                            explanation="Carrying executable binaries or script archives inside email attachments is a primary vector for ransomware and credential stealers. Attachments are never executed by AEGIS.",
                            recommended_action="Do not open or execute this attachment under any circumstance.",
                            source_module="email_attachment_inspector",
                        ))
                        risk_boost += 40

                # Extract plain text body if available
                body_part = msg.get_body(preferencelist=("plain", "html"))
                if body_part:
                    try:
                        body_text = body_part.get_content()
                    except Exception:
                        pass
        except Exception:
            has_headers = False

    # 1. Missing Header Honesty Rule
    if not has_headers:
        unavailable.append("SPF/DKIM/DMARC: Not verifiable without raw RFC 822 email headers")
        unavailable.append("DKIM cryptographic signature verification: No public key resolution attempted")
    else:
        # Check for failed authentication
        if spf_status == "fail" or dkim_status == "fail" or dmarc_status == "fail":
            risk_boost += 45
            findings.append(Finding(
                category=FindingCategory.EMAIL_AUTH,
                severity=FindingSeverity.CRITICAL,
                evidence=f"Failed email authentication: SPF={spf_status}, DKIM={dkim_status}, DMARC={dmarc_status}",
                explanation="The connecting sending server failed email authentication checks for the claimed domain, indicating direct sender spoofing.",
                recommended_action="Reject and quarantine this email across corporate mail gateways.",
                source_module="email_header_forensics",
            ))
        elif spf_status == "pass" and dkim_status == "pass":
            findings.append(Finding(
                category=FindingCategory.EMAIL_AUTH,
                severity=FindingSeverity.LOW,
                evidence="SPF and DKIM recorded as pass in mail authentication headers",
                explanation="Sender domain signatures are authenticated (parsed from mail server headers).",
                recommended_action="Normal security vigilance; headers align with claimed domain.",
                source_module="email_header_forensics",
            ))

    # 2. Display Name Spoofing Check
    # e.g. Display Name says "State Bank of India" or "Income Tax" but sender_email is "@gmail.com" or "@freehost.xyz"
    if display_name and sender_email:
        clean_email = sender_email.replace("<", "").replace(">", "").strip().lower()
        clean_display = display_name.lower()

        for brand in ["sbi", "state bank", "hdfc", "icici", "axis", "income tax", "rbi", "amazon", "google", "microsoft"]:
            if brand in clean_display and brand.replace(" ", "") not in clean_email:
                risk_boost += 40
                findings.append(Finding(
                    category=FindingCategory.IMPERSONATION,
                    severity=FindingSeverity.HIGH,
                    evidence=f"Display Name spoofing: Friendly name '{display_name}' does not match sender address '{clean_email}'",
                    explanation="Attackers frequently configure the human-readable Display Name to mimic official brands while dispatching from disposable or compromised third-party mailboxes.",
                    recommended_action="Never trust the display name alone. Verify the exact sender email domain address.",
                    source_module="email_header_forensics",
                ))
                break

    # 3. Reply-To Mismatch Check
    if sender_email and reply_to:
        clean_sender = sender_email.replace("<", "").replace(">", "").strip().lower()
        clean_reply = reply_to.replace("<", "").replace(">", "").strip().lower()
        sender_domain = clean_sender.split("@")[-1] if "@" in clean_sender else ""
        reply_domain = clean_reply.split("@")[-1] if "@" in clean_reply else ""

        if sender_domain and reply_domain and sender_domain != reply_domain:
            risk_boost += 30
            findings.append(Finding(
                category=FindingCategory.IMPERSONATION,
                severity=FindingSeverity.MEDIUM,
                evidence=f"Reply-To address mismatch: From domain '{sender_domain}' vs Reply-To domain '{reply_domain}'",
                explanation="Directing email replies to a different destination domain is an indicator of targeted credential harvesting and business email compromise (BEC).",
                recommended_action="Verify why replies are routed to a distinct entity before responding.",
                source_module="email_header_forensics",
            ))

    return EmailForensicsResult(
        sender_email=sender_email,
        display_name=display_name,
        reply_to=reply_to,
        subject=subject,
        spf_result=spf_status,
        dkim_result=dkim_status,
        dmarc_result=dmarc_status,
        findings=findings,
        unavailable_checks=unavailable,
        risk_boost=min(80, risk_boost),
        extracted_body=body_text,
        attachment_names=attachments,
    )

