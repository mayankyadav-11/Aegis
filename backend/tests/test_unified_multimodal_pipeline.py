"""
AEGIS 2.0 — Unified Multimodal Pipeline Comprehensive Test Suite

Tests all six input channels, canonical evidence extraction, evidence fusion engine,
DomainRel credibility provider, and the AJIO regressions.
"""

from __future__ import annotations

import io
from unittest.mock import MagicMock, patch

import pytest
from pypdf import PdfWriter

from core.canonical_evidence import (
    CanonicalEvidence,
    extract_for_email,
    extract_for_eml,
    extract_for_pdf,
    extract_for_screenshot,
    extract_for_text,
    extract_for_url,
)
from core.evidence_fusion import EvidenceFusionEngine, FusionResult
from core.unified_pipeline import UnifiedAnalysisPipeline, unified_pipeline
from intelligence.intelligence_service import DomainReputationLevel, intelligence_service
from intelligence.sources.domainrel_provider import domainrel_provider
from schemas import (
    Confidence,
    Finding,
    FindingCategory,
    FindingSeverity,
    InputType,
    RiskLevel,
    Verdict,
)


# ===========================================================================
# 1. Text Channel Tests
# ===========================================================================

class TestTextChannel:
    def test_neutral_message(self):
        result = unified_pipeline.process_input(
            input_type="text",
            content="Hey, are we still meeting for lunch at 1 PM tomorrow?",
        )
        assert result.verdict == Verdict.SAFE
        assert result.risk_score < 25

    def test_legitimate_banking_alert(self):
        msg = "Dear Customer, INR 1,500.00 debited from A/C XX1234 on 30-OCT-24 at ATM. Avail Bal: INR 25,400.00. Call 1800112211 if not you - SBI"
        result = unified_pipeline.process_input(
            input_type="text",
            content=msg,
        )
        assert result.verdict in (Verdict.SAFE, Verdict.SUSPICIOUS)
        assert result.risk_score < 55

    def test_kyc_phishing_scam(self):
        msg = "Dear Customer your SBI account blocked today. Immediately update your PAN card at https://sbi-kyc-update.xyz to avoid suspension."
        result = unified_pipeline.process_input(
            input_type="text",
            content=msg,
        )
        assert result.verdict == Verdict.MALICIOUS
        assert result.risk_score >= 55

    def test_ajio_promotional_text_not_malicious(self):
        msg = "Mega Diwali Sale is Live! Get flat 70% off on top brands only on AJIO. Shop now: https://ajioin.in/diwali-sale"
        result = unified_pipeline.process_input(
            input_type="text",
            content=msg,
        )
        # Commercial promotion must not be classified as MALICIOUS
        assert result.verdict != Verdict.MALICIOUS
        assert result.risk_score < 55


# ===========================================================================
# 2. SMS Channel Tests
# ===========================================================================

class TestSMSChannel:
    def test_sms_with_bank_sender(self):
        msg = "Your OTP for login to SBI NetBanking is 849201. Valid for 5 minutes. Do not share with anyone."
        result = unified_pipeline.process_input(
            input_type="sms",
            content=msg,
            sender="VK-SBINB",
        )
        assert result.verdict == Verdict.SAFE
        assert result.risk_score < 25
        assert any("SMS channel" in check for check in result.unavailable_checks)

    def test_sms_smishing_from_phone_number(self):
        msg = "Dear consumer your electricity power will be disconnected tonight at 9:30 PM due to unpaid bill. Immediately update at https://electricity-bill-pay.xyz"
        result = unified_pipeline.process_input(
            input_type="sms",
            content=msg,
            sender="+919876543210",
        )
        assert result.verdict == Verdict.MALICIOUS
        assert result.risk_score >= 55

    def test_sms_trai_unavailable_checks_reported(self):
        result = unified_pipeline.process_input(
            input_type="sms",
            content="Simple test message without links.",
        )
        check_text = " ".join(result.unavailable_checks)
        assert "Carrier DLT telemetry" in check_text


# ===========================================================================
# 3. URL Channel Tests
# ===========================================================================

class TestURLChannel:
    def test_official_sbi_domain(self):
        result = unified_pipeline.process_input(
            input_type="url",
            content="https://sbi.co.in/web/personal-banking",
        )
        assert result.verdict == Verdict.SAFE
        assert result.risk_score < 25

    def test_ajio_campaign_url_not_malicious(self):
        result = unified_pipeline.process_input(
            input_type="url",
            content="https://ajioin.in/offer/deals",
        )
        assert result.verdict != Verdict.MALICIOUS
        assert result.risk_score < 25

    def test_phishing_url_malicious(self):
        result = unified_pipeline.process_input(
            input_type="url",
            content="https://sbi-kyc-update.xyz/login.php",
        )
        assert result.verdict == Verdict.MALICIOUS
        assert result.risk_score >= 55

    def test_threat_intel_known_phishing_domain(self):
        # sbi-kyc-update.xyz is in known_phishing_domains seed
        result = unified_pipeline.process_input(
            input_type="url",
            content="https://sbi-kyc-update.xyz/auth",
        )
        assert result.verdict == Verdict.MALICIOUS
        assert result.risk_score >= 85
        assert any("threat intelligence" in f.explanation.lower() for f in result.findings)

    def test_ajio_prize_scam_positive_regression(self):
        # Fake reward scam impersonating AJIO on suspicious TLD
        result = unified_pipeline.process_input(
            input_type="url",
            content="https://ajio-claim-reward.xyz/win",
        )
        assert result.verdict == Verdict.MALICIOUS
        assert result.risk_score >= 80


# ===========================================================================
# 4. EML Email File Channel Tests
# ===========================================================================

class TestEMLChannel:
    def test_legitimate_eml(self):
        eml_bytes = (
            b"From: service@sbi.co.in\r\n"
            b"To: customer@example.com\r\n"
            b"Subject: Monthly Account Statement\r\n"
            b"Received: from mail.sbi.co.in (mail.sbi.co.in [1.2.3.4]) by mx.example.com\r\n"
            b"Authentication-Results: mx.example.com; spf=pass; dkim=pass\r\n"
            b"\r\n"
            b"Dear Customer, Please find your monthly statement attached.\r\n"
        )
        result = unified_pipeline.process_input(
            input_type="file",
            file_bytes=eml_bytes,
            filename="statement.eml",
        )
        assert result.verdict in (Verdict.SAFE, Verdict.SUSPICIOUS)
        assert result.risk_score < 55

    def test_eml_display_name_spoofing(self):
        eml_bytes = (
            b"From: \"State Bank of India\" <scammer99@free-mail.xyz>\r\n"
            b"To: victim@example.com\r\n"
            b"Subject: URGENT: KYC Expired - Account Blocked\r\n"
            b"\r\n"
            b"Click here to reactivate: http://sbi-kyc-renewal.site\r\n"
        )
        result = unified_pipeline.process_input(
            input_type="file",
            file_bytes=eml_bytes,
            filename="alert.eml",
        )
        assert result.verdict == Verdict.MALICIOUS
        assert result.risk_score >= 55

    def test_eml_dangerous_attachment(self):
        eml_bytes = (
            b"From: support@example.com\r\n"
            b"To: user@example.com\r\n"
            b"Subject: Invoice\r\n"
            b"Content-Type: multipart/mixed; boundary=\"boundary\"\r\n"
            b"\r\n"
            b"--boundary\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"Please run the attached patch.\r\n"
            b"--boundary\r\n"
            b"Content-Type: application/octet-stream; name=\"patch.exe\"\r\n"
            b"Content-Disposition: attachment; filename=\"patch.exe\"\r\n"
            b"\r\n"
            b"MZdummyexecutable\r\n"
            b"--boundary--\r\n"
        )
        result = unified_pipeline.process_input(
            input_type="file",
            file_bytes=eml_bytes,
            filename="invoice.eml",
        )
        assert result.verdict == Verdict.MALICIOUS
        assert any("patch.exe" in f.evidence or "executable" in f.explanation.lower() for f in result.findings)


# ===========================================================================
# 5. PDF Channel Tests
# ===========================================================================

class TestPDFChannel:
    def _create_sample_pdf(self, text: str) -> bytes:
        writer = PdfWriter()
        page = writer.add_blank_page(width=300, height=300)
        # Note: pypdf can write annotations or empty pages; for text extraction
        # we can build a minimal text object if needed or write a basic structure
        stream = io.BytesIO()
        writer.write(stream)
        return stream.getvalue()

    def test_scanned_empty_pdf_is_inconclusive(self):
        # Empty/scanned PDF without extractable text
        pdf_bytes = self._create_sample_pdf("")
        result = unified_pipeline.process_input(
            input_type="file",
            file_bytes=pdf_bytes,
            filename="scanned_receipt.pdf",
        )
        assert result.analysis_completeness_level == "inconclusive"
        assert result.verdict == Verdict.SAFE
        assert result.risk_score == 0
        assert any("Scanned PDF" in check or "No machine-readable text" in check for check in result.unavailable_checks)


# ===========================================================================
# 6. Screenshot Channel Tests
# ===========================================================================

class TestScreenshotChannel:
    def _create_test_image_bytes(self) -> bytes:
        from PIL import Image
        img = Image.new("RGB", (200, 100), color=(255, 255, 255))
        stream = io.BytesIO()
        img.save(stream, format="PNG")
        return stream.getvalue()

    def test_screenshot_fallback_when_gemini_unavailable(self):
        img_bytes = self._create_test_image_bytes()
        with patch("detectors.screenshot_detector.settings.gemini_api_key", ""):
            result = unified_pipeline.process_input(
                input_type="screenshot",
                file_bytes=img_bytes,
                filename="chat.png",
            )
            # Without Gemini Vision, visual inspection is inconclusive
            assert result.analysis_completeness_level == "inconclusive"
            assert result.verdict == Verdict.SAFE
            assert result.risk_score == 0
            assert any("Gemini Vision" in check or "inconclusive" in check for check in result.unavailable_checks)


# ===========================================================================
# 7. DomainRel Credibility Provider Tests
# ===========================================================================

class TestDomainRelProvider:
    def test_high_credibility_domain(self):
        score = domainrel_provider.get_credibility_score("sbi.co.in")
        assert score is not None
        assert score >= 0.90

    def test_low_credibility_domain(self):
        score = domainrel_provider.get_credibility_score("infowars.com")
        assert score is not None
        assert score < 0.20

    def test_missing_domain_returns_none(self):
        score = domainrel_provider.get_credibility_score("nonexistent-random-domain-12345.xyz")
        assert score is None

    def test_low_credibility_does_not_trigger_malicious(self):
        # Calling intelligence_service for credibility should provide an informational signal
        # but not mark the domain reputation as KNOWN_MALICIOUS
        cred = intelligence_service.lookup_domain_credibility("infowars.com")
        rep = intelligence_service.lookup_domain_reputation("infowars.com")
        assert cred is not None and cred < 0.25
        # Popularity/credibility provider alone does NOT mark reputation as KNOWN_MALICIOUS
        assert rep.reputation != DomainReputationLevel.KNOWN_MALICIOUS

    def test_high_credibility_does_not_whitelist_threat_intel(self):
        # If a domain has a threat record, threat intel must dominate over any credibility
        rep = intelligence_service.lookup_domain_reputation("sbi-kyc-update.xyz")
        assert rep.reputation == DomainReputationLevel.KNOWN_MALICIOUS


# ===========================================================================
# 8. Evidence Fusion & Double-Counting Guard Tests
# ===========================================================================

class TestEvidenceFusionEngine:
    def test_known_malicious_overrides_brand(self):
        engine = EvidenceFusionEngine()
        ev = extract_for_url("https://sbi-kyc-update.xyz/login")
        intel = {
            "sbi-kyc-update.xyz": intelligence_service.lookup_domain_reputation("sbi-kyc-update.xyz")
        }
        res = engine.fuse(
            evidence=ev,
            deterministic_findings=[],
            deterministic_url_scores={"https://sbi-kyc-update.xyz/login": 60},
            deterministic_text_score=0,
            gemini_result=None,
            intelligence_results=intel,
        )
        assert res.verdict == Verdict.MALICIOUS
        assert res.risk_score >= 85

    def test_double_counting_prevented(self):
        engine = EvidenceFusionEngine()
        ev = extract_for_url("https://sbi-kyc-update.xyz/login")
        intel = {
            "sbi-kyc-update.xyz": intelligence_service.lookup_domain_reputation("sbi-kyc-update.xyz")
        }
        # The URL detector provides 75, intel provides 75
        # The fused score must be capped appropriately at max (not 75 + 75 = 150)
        res = engine.fuse(
            evidence=ev,
            deterministic_findings=[],
            deterministic_url_scores={"sbi-kyc-update.xyz": 75},
            deterministic_text_score=0,
            gemini_result=None,
            intelligence_results=intel,
        )
        assert res.risk_score <= 100
        assert res.verdict == Verdict.MALICIOUS

    def test_commercial_urgency_alone_not_malicious(self):
        engine = EvidenceFusionEngine()
        ev = extract_for_text("Hurry! Sale ends in 2 hours. Order now for best discounts.")
        finding = Finding(
            category=FindingCategory.CONTENT,
            severity=FindingSeverity.LOW,
            evidence="ends in 2 hours",
            explanation="Commercial retail marketing urgency detected.",
            recommended_action="Take time to compare prices.",
            source_module="brand_detector:commercial_urgency",
        )
        res = engine.fuse(
            evidence=ev,
            deterministic_findings=[finding],
            deterministic_url_scores={},
            deterministic_text_score=10,
            gemini_result=None,
            intelligence_results={},
        )
        assert res.verdict == Verdict.SAFE
        assert res.risk_score < 25
