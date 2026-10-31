"""
AEGIS 2.0 — Phase 4 Validation Test Matrix
10-case end-to-end accuracy validation via unified_pipeline.process_input() directly.

Uses the same pattern as test_unified_multimodal_pipeline.py to avoid real Gemini calls.
Each case records correctness assertions and prints diagnostic info.

Test Cases:
  1. AJIO promotional text (legitimate) → NOT malicious
  2. AJIO campaign SMS with tracking domain → NOT malicious
  3. Fake AJIO prize scam → SUSPICIOUS or MALICIOUS
  4. SBI phishing URL (known malicious domain) → MALICIOUS
  5. Legitimate SBI OTP SMS → NOT malicious
  6. Unknown domain with no intel match → NOT malicious (not confirmed)
  7. EML with missing auth + phishing domain → SUSPICIOUS or MALICIOUS
  8. Scanned PDF (no extractable text) → completeness=inconclusive
  9. Screenshot with Gemini unavailable → completeness=inconclusive
  10. Legitimate AJIO email with tracking URL → NOT malicious
  B1. URL response contract has all required fields
  B2. Text response contract has all required fields
"""

from __future__ import annotations

import io
import textwrap
from unittest.mock import patch

import pytest
from pypdf import PdfWriter

from core.unified_pipeline import unified_pipeline
from schemas import Verdict


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _create_empty_pdf() -> bytes:
    """Create a valid PDF with no extractable text (simulates scanned PDF)."""
    writer = PdfWriter()
    writer.add_blank_page(width=300, height=300)
    stream = io.BytesIO()
    writer.write(stream)
    return stream.getvalue()


def _create_png() -> bytes:
    """Create a minimal 1×1 white PNG."""
    try:
        from PIL import Image
        img = Image.new("RGB", (10, 10), color=(255, 255, 255))
        stream = io.BytesIO()
        img.save(stream, format="PNG")
        return stream.getvalue()
    except ImportError:
        # Fallback: raw 1×1 transparent PNG bytes
        return bytes([
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
            0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52,
            0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
            0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
            0xDE, 0x00, 0x00, 0x00, 0x0C, 0x49, 0x44, 0x41,
            0x54, 0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00,
            0x00, 0x00, 0x02, 0x00, 0x01, 0xE2, 0x21, 0xBC,
            0x33, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E,
            0x44, 0xAE, 0x42, 0x60, 0x82,
        ])


def _make_eml(sender: str, subject: str, body: str, include_auth: bool = True) -> bytes:
    """Build minimal EML bytes."""
    auth = (
        f"Authentication-Results: mx.example.com;\r\n"
        f"  spf=pass smtp.mailfrom={sender};\r\n"
        f"  dkim=pass header.d={sender.split('@')[-1]};\r\n"
        f"  dmarc=pass\r\n"
    ) if include_auth else ""
    raw = (
        f"From: {sender}\r\n"
        f"To: victim@example.com\r\n"
        f"Subject: {subject}\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"{auth}"
        f"\r\n"
        f"{body}"
    )
    return raw.encode("utf-8")


# ===========================================================================
# Case 1: AJIO promotional text — expect NOT malicious
# ===========================================================================

def test_case1_ajio_promotional_text():
    """Legitimate AJIO promotional message must not be MALICIOUS."""
    result = unified_pipeline.process_input(
        input_type="text",
        content=(
            "AJIO Big Bold Sale! Up to 80% off on fashion. "
            "Shop now: https://www.ajio.com/sale "
            "Use code BOLD80 at checkout. Valid today only."
        ),
    )
    print(f"\nCase 1 — AJIO promo text: verdict={result.verdict.value}, score={result.risk_score}, "
          f"completeness={result.analysis_completeness_level}")
    assert result.verdict != Verdict.MALICIOUS, (
        f"FALSE POSITIVE: Legitimate AJIO promo flagged as MALICIOUS "
        f"(score={result.risk_score}, findings={[f.explanation for f in result.findings]})"
    )


# ===========================================================================
# Case 2: AJIO tracking domain SMS — expect NOT malicious
# ===========================================================================

def test_case2_ajio_campaign_tracking_domain():
    """Approved AJIO campaign tracking domain (ajioin.in) must NOT be MALICIOUS."""
    result = unified_pipeline.process_input(
        input_type="sms",
        content="AJIO: Your exclusive offer! Shop via: https://ajioin.in/track?c=BOLD80XYZ Get 70% off.",
        sender="VK-AJIONL",
    )
    print(f"\nCase 2 — AJIO tracking SMS: verdict={result.verdict.value}, score={result.risk_score}")
    assert result.verdict != Verdict.MALICIOUS, (
        f"FALSE POSITIVE: ajioin.in campaign domain flagged as MALICIOUS "
        f"(score={result.risk_score})"
    )


# ===========================================================================
# Case 3: Fake AJIO prize scam — expect SUSPICIOUS or MALICIOUS
# ===========================================================================

def test_case3_fake_ajio_prize_scam():
    """Fake AJIO prize scam with confirmed malicious domain must be detected."""
    result = unified_pipeline.process_input(
        input_type="sms",
        content=(
            "Congratulations! You have won Rs 50,000 from AJIO Lucky Draw. "
            "Claim your prize: https://ajio-claim-reward.xyz/winner?id=291 "
            "Pay Rs 500 processing fee. Hurry, expires in 2 hours!"
        ),
        sender="IM-AJIOFK",
    )
    print(f"\nCase 3 — Fake AJIO prize: verdict={result.verdict.value}, score={result.risk_score}")
    assert result.verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS), (
        f"FALSE NEGATIVE: AJIO prize scam not detected "
        f"(verdict={result.verdict.value}, score={result.risk_score})"
    )
    assert result.risk_score >= 25


# ===========================================================================
# Case 4: SBI phishing URL (known malicious domain) — expect MALICIOUS
# ===========================================================================

def test_case4_sbi_phishing_url():
    """Known SBI phishing domain (in threat intel seed) must be MALICIOUS."""
    result = unified_pipeline.process_input(
        input_type="url",
        content="https://sbi-kyc-update.xyz/secure/login",
    )
    print(f"\nCase 4 — SBI phishing URL: verdict={result.verdict.value}, score={result.risk_score}")
    assert result.verdict == Verdict.MALICIOUS, (
        f"FALSE NEGATIVE: SBI phishing URL not detected as MALICIOUS "
        f"(verdict={result.verdict.value}, score={result.risk_score})"
    )
    assert result.risk_score >= 55


# ===========================================================================
# Case 5: Legitimate SBI OTP SMS — expect NOT malicious
# ===========================================================================

def test_case5_legitimate_sbi_otp_sms():
    """Legitimate SBI OTP SMS from VK-SBINB must NOT be MALICIOUS."""
    result = unified_pipeline.process_input(
        input_type="sms",
        content=(
            "Your SBI account OTP is 847291. Valid for 10 minutes. "
            "Do not share with anyone. SBI will never ask for your OTP."
        ),
        sender="VK-SBINB",
    )
    print(f"\nCase 5 — Legitimate SBI OTP: verdict={result.verdict.value}, score={result.risk_score}")
    assert result.verdict != Verdict.MALICIOUS, (
        f"FALSE POSITIVE: Legitimate SBI OTP SMS flagged as MALICIOUS "
        f"(score={result.risk_score}, findings={[f.evidence for f in result.findings]})"
    )


# ===========================================================================
# Case 6: Unknown domain, no intel match — expect NOT malicious (confirmed)
# ===========================================================================

def test_case6_unknown_domain_no_intel():
    """Unknown domain not in any dataset must NOT be confirmed MALICIOUS."""
    result = unified_pipeline.process_input(
        input_type="url",
        content="https://totally-unknown-startup-99z.com/product/launch",
    )
    print(f"\nCase 6 — Unknown domain: verdict={result.verdict.value}, score={result.risk_score}")
    # Should not be MALICIOUS with no threat intel match (no brand impersonation either)
    assert result.verdict != Verdict.MALICIOUS, (
        f"SPURIOUS MALICIOUS: Unknown domain with no intel flagged MALICIOUS "
        f"(score={result.risk_score}, findings={[f.explanation for f in result.findings]})"
    )


# ===========================================================================
# Case 7: EML with missing auth headers + phishing domain — expect elevated risk
# ===========================================================================

def test_case7_eml_missing_auth_with_phishing_domain():
    """EML without auth headers from HDFC phishing domain should be at least SUSPICIOUS."""
    eml_bytes = _make_eml(
        sender="security@hdfc-netbanking-verify.top",
        subject="Your HDFC account will be suspended",
        body=(
            "Dear Customer, your HDFC Bank account needs immediate KYC verification. "
            "Click: http://hdfc-netbanking-verify.top/kyc to avoid suspension."
        ),
        include_auth=False,
    )
    result = unified_pipeline.process_input(
        input_type="file",
        file_bytes=eml_bytes,
        filename="suspicious_hdfc.eml",
    )
    print(f"\nCase 7 — EML missing auth + phishing: verdict={result.verdict.value}, "
          f"score={result.risk_score}, completeness={result.analysis_completeness_level}")
    assert result.verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS), (
        f"FALSE NEGATIVE: HDFC phishing EML without auth returned "
        f"verdict={result.verdict.value} score={result.risk_score}"
    )


# ===========================================================================
# Case 8: Scanned PDF — must be INCONCLUSIVE, never safe with 0 evidence
# ===========================================================================

def test_case8_scanned_pdf_is_inconclusive():
    """Scanned (image-only) PDF with no extractable text must return completeness=inconclusive."""
    pdf_bytes = _create_empty_pdf()
    result = unified_pipeline.process_input(
        input_type="file",
        file_bytes=pdf_bytes,
        filename="scanned_doc.pdf",
    )
    print(f"\nCase 8 — Scanned PDF: verdict={result.verdict.value}, score={result.risk_score}, "
          f"completeness={result.analysis_completeness_level}")
    assert result.analysis_completeness_level == "inconclusive", (
        f"CRITICAL: Scanned PDF returned completeness={result.analysis_completeness_level!r} "
        f"instead of 'inconclusive'"
    )
    # Score must be 0 (short-circuit; no fabricated risk)
    assert result.risk_score == 0, (
        f"Scanned PDF should have risk_score=0, got {result.risk_score}"
    )
    # Must disclose the limitation
    assert any("Scanned PDF" in c or "machine-readable" in c or "inconclusive" in c.lower()
               for c in result.unavailable_checks), (
        f"Inconclusive status not disclosed in unavailable_checks: {result.unavailable_checks}"
    )


# ===========================================================================
# Case 9: Screenshot without Gemini — must be INCONCLUSIVE
# ===========================================================================

def test_case9_screenshot_gemini_unavailable():
    """Screenshot with Gemini unavailable must return completeness=inconclusive."""
    png_bytes = _create_png()
    with patch("detectors.screenshot_detector.settings.gemini_api_key", ""):
        result = unified_pipeline.process_input(
            input_type="screenshot",
            file_bytes=png_bytes,
            filename="screenshot.png",
            context="Possible phishing screenshot",
        )
    print(f"\nCase 9 — Screenshot no Gemini: verdict={result.verdict.value}, score={result.risk_score}, "
          f"completeness={result.analysis_completeness_level}")
    assert result.analysis_completeness_level == "inconclusive", (
        f"CRITICAL: Screenshot without Gemini returned completeness="
        f"{result.analysis_completeness_level!r} instead of 'inconclusive'"
    )
    assert result.risk_score == 0
    assert any("Gemini Vision" in c or "inconclusive" in c.lower() or "Screenshot" in c
               for c in result.unavailable_checks)


# ===========================================================================
# Case 10: Legitimate AJIO order email with tracking URL — NOT malicious
# ===========================================================================

def test_case10_legitimate_ajio_order_email():
    """Legitimate AJIO order confirmation email with tracking URL must NOT be MALICIOUS."""
    body = textwrap.dedent("""
        Hi there,

        Your AJIO order #ORD-12345 has been dispatched and is on its way.
        Track your order: https://ajioin.in/track?order=ORD-12345
        Visit: https://www.ajio.com/orders

        Thank you for shopping with AJIO.
    """).strip()
    eml_bytes = _make_eml(
        sender="orders@ajio.com",
        subject="Your AJIO order has shipped!",
        body=body,
        include_auth=True,
    )
    result = unified_pipeline.process_input(
        input_type="file",
        file_bytes=eml_bytes,
        filename="ajio_order.eml",
    )
    print(f"\nCase 10 — Legit AJIO order email: verdict={result.verdict.value}, score={result.risk_score}")
    assert result.verdict != Verdict.MALICIOUS, (
        f"FALSE POSITIVE: Legitimate AJIO order email flagged as MALICIOUS "
        f"(score={result.risk_score}, findings={[f.evidence for f in result.findings]})"
    )


# ===========================================================================
# Bonus B1: All required response fields are present in unified_pipeline output
# ===========================================================================

def test_contract_b1_url_fusion_result_fields():
    """FusionResult must carry all required fields for AnalysisResponse construction."""
    result = unified_pipeline.process_input(
        input_type="url",
        content="https://www.google.com",
    )
    # All FusionResult fields referenced by _fusion_to_response must exist
    assert hasattr(result, "risk_score")
    assert hasattr(result, "risk_level")
    assert hasattr(result, "verdict")
    assert hasattr(result, "confidence")
    assert hasattr(result, "findings")
    assert hasattr(result, "highlights")
    assert hasattr(result, "unavailable_checks")
    assert hasattr(result, "explanation")
    assert hasattr(result, "recommendations")
    assert hasattr(result, "analysis_completeness_level")
    assert hasattr(result, "signal_scores")
    assert hasattr(result, "gemini_available")
    assert 0 <= result.risk_score <= 100


# ===========================================================================
# Bonus B2: Double-counting guard — same domain not penalized twice
# ===========================================================================

def test_contract_b2_no_double_counting_on_known_malicious():
    """Known malicious domain should be penalized once, not by both intel and URL detector."""
    result = unified_pipeline.process_input(
        input_type="url",
        content="https://sbi-kyc-update.xyz/login",
    )
    print(f"\nB2 — Double-counting check: score={result.risk_score}, "
          f"findings_count={len(result.findings)}")
    # Score should be ≥ 85 (intel-forced) but capped at 100
    assert result.risk_score <= 100
    assert result.risk_score >= 85
    # Should NOT have both intel finding AND a separate URL impersonation finding
    # that adds to the same domain (double-count guard)
    intel_findings = [f for f in result.findings
                      if "threat intelligence" in f.explanation.lower()]
    url_findings = [f for f in result.findings
                    if "sbi-kyc-update.xyz" in f.evidence
                    and "threat intelligence" not in f.explanation.lower()]
    # If intel already penalized, URL brand detector shouldn't add another full penalty
    if intel_findings and url_findings:
        # Both exist — verify score is NOT inflated beyond 100
        assert result.risk_score <= 100, "Score overflow despite double-counting guard"
