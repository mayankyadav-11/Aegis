"""
AEGIS 2.0 — Comprehensive Gemini API Failure Modes, Automatic Fallback, and Risk Fusion Tests

Covers 21 distinct scenarios:
1-13: Gemini failure triggers (missing key, 401, 403, 429, 500, 503, connect error, timeout, malformed JSON, empty candidates, empty parts, finishReason SAFETY, prompt blockReason SAFETY).
14: Provider status recovery tracking.
15-19: Fallback mode operation across text, sms, url, eml, pdf.
20: Screenshot without Gemini returns inconclusive (SAFE, risk_score 0, inconclusive completeness).
21: Deterministic risk fusion without AI.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi.testclient import TestClient
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from main import app
from api.routes import (
    analyze_email,
    analyze_file,
    analyze_sms,
    analyze_text,
    analyze_url,
    health,
)
from config import settings
from core.gemini_analyzer import (
    GeminiAnalysisResult,
    analyze_with_gemini,
    get_gemini_provider_status,
)
from detectors.screenshot_detector import analyze_screenshot
from schemas import (
    AnalysisResponse,
    EmailAnalyzeRequest,
    RiskLevel,
    TextAnalyzeRequest,
    UrlAnalyzeRequest,
    Verdict,
)


class TestGeminiAPIFailureTriggers:
    """Tests 1-14: Gemini API failure handling and status tracking."""

    def test_missing_api_key(self):
        """Scenario 1: Missing API key triggers graceful fallback with not_configured category."""
        original_key = settings.gemini_api_key
        settings.gemini_api_key = ""
        try:
            res = analyze_with_gemini("Urgent: your account will be suspended")
            assert res.available is False
            assert res.failure_category == "not_configured"
            status = get_gemini_provider_status()
            assert status["available"] is False
            assert status["last_failure_reason"] == "not_configured"
        finally:
            settings.gemini_api_key = original_key

    def test_invalid_api_key_401(self, monkeypatch):
        """Scenario 2: HTTP 401 Unauthorized triggers authentication_failure."""
        original_key = settings.gemini_api_key
        settings.gemini_api_key = "invalid_key_401"

        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.text = "API_KEY_INVALID"
        monkeypatch.setattr(httpx.Client, "post", lambda *a, **k: mock_resp)

        try:
            res = analyze_with_gemini("Test message")
            assert res.available is False
            assert res.failure_category == "authentication_failure"
        finally:
            settings.gemini_api_key = original_key

    def test_forbidden_api_key_403(self, monkeypatch):
        """Scenario 3: HTTP 403 Forbidden triggers authentication_failure."""
        original_key = settings.gemini_api_key
        settings.gemini_api_key = "forbidden_key_403"

        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "PERMISSION_DENIED"
        monkeypatch.setattr(httpx.Client, "post", lambda *a, **k: mock_resp)

        try:
            res = analyze_with_gemini("Test message")
            assert res.available is False
            assert res.failure_category == "authentication_failure"
        finally:
            settings.gemini_api_key = original_key

    def test_quota_exhausted_429(self, monkeypatch):
        """Scenario 4: HTTP 429 Rate/Quota limit triggers quota_or_rate_limit."""
        original_key = settings.gemini_api_key
        settings.gemini_api_key = "test_key"

        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_resp.text = "RESOURCE_EXHAUSTED"
        monkeypatch.setattr(httpx.Client, "post", lambda *a, **k: mock_resp)

        try:
            res = analyze_with_gemini("Test message")
            assert res.available is False
            assert res.failure_category == "quota_or_rate_limit"
        finally:
            settings.gemini_api_key = original_key

    def test_provider_error_500(self, monkeypatch):
        """Scenario 5: HTTP 500 Internal Server Error triggers provider_error."""
        original_key = settings.gemini_api_key
        settings.gemini_api_key = "test_key"

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "Internal error"
        monkeypatch.setattr(httpx.Client, "post", lambda *a, **k: mock_resp)

        try:
            res = analyze_with_gemini("Test message")
            assert res.available is False
            assert res.failure_category == "provider_error"
        finally:
            settings.gemini_api_key = original_key

    def test_provider_error_503(self, monkeypatch):
        """Scenario 6: HTTP 503 Service Unavailable triggers provider_error."""
        original_key = settings.gemini_api_key
        settings.gemini_api_key = "test_key"

        mock_resp = MagicMock()
        mock_resp.status_code = 503
        mock_resp.text = "Service unavailable"
        monkeypatch.setattr(httpx.Client, "post", lambda *a, **k: mock_resp)

        try:
            res = analyze_with_gemini("Test message")
            assert res.available is False
            assert res.failure_category == "provider_error"
        finally:
            settings.gemini_api_key = original_key

    def test_network_connect_error(self, monkeypatch):
        """Scenario 7: Network connect failure triggers network_unavailable."""
        original_key = settings.gemini_api_key
        settings.gemini_api_key = "test_key"

        def mock_post(*a, **k):
            raise httpx.ConnectError("Failed to resolve host")

        monkeypatch.setattr(httpx.Client, "post", mock_post)

        try:
            res = analyze_with_gemini("Test message")
            assert res.available is False
            assert res.failure_category == "network_unavailable"
        finally:
            settings.gemini_api_key = original_key

    def test_network_timeout(self, monkeypatch):
        """Scenario 8: Request timeout triggers request_timeout."""
        original_key = settings.gemini_api_key
        settings.gemini_api_key = "test_key"

        def mock_post(*a, **k):
            raise httpx.TimeoutException("Read timed out")

        monkeypatch.setattr(httpx.Client, "post", mock_post)

        try:
            res = analyze_with_gemini("Test message")
            assert res.available is False
            assert res.failure_category == "request_timeout"
        finally:
            settings.gemini_api_key = original_key

    def test_malformed_json_response(self, monkeypatch):
        """Scenario 9: Malformed JSON from Gemini triggers invalid_response."""
        original_key = settings.gemini_api_key
        settings.gemini_api_key = "test_key"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "candidates": [
                {"content": {"parts": [{"text": "{ not valid json"}]}}
            ]
        }
        monkeypatch.setattr(httpx.Client, "post", lambda *a, **k: mock_resp)

        try:
            res = analyze_with_gemini("Test message")
            assert res.available is False
            assert res.failure_category == "invalid_response"
        finally:
            settings.gemini_api_key = original_key

    def test_empty_candidates(self, monkeypatch):
        """Scenario 10: Empty candidates array triggers empty_response."""
        original_key = settings.gemini_api_key
        settings.gemini_api_key = "test_key"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"candidates": []}
        monkeypatch.setattr(httpx.Client, "post", lambda *a, **k: mock_resp)

        try:
            res = analyze_with_gemini("Test message")
            assert res.available is False
            assert res.failure_category == "empty_response"
        finally:
            settings.gemini_api_key = original_key

    def test_empty_content_parts(self, monkeypatch):
        """Scenario 11: Empty content parts triggers empty_response."""
        original_key = settings.gemini_api_key
        settings.gemini_api_key = "test_key"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "candidates": [{"content": {"parts": []}, "finishReason": "STOP"}]
        }
        monkeypatch.setattr(httpx.Client, "post", lambda *a, **k: mock_resp)

        try:
            res = analyze_with_gemini("Test message")
            assert res.available is False
            assert res.failure_category == "empty_response"
        finally:
            settings.gemini_api_key = original_key

    def test_safety_blocked_finish_reason(self, monkeypatch):
        """Scenario 12: finishReason=SAFETY triggers safety_blocked."""
        original_key = settings.gemini_api_key
        settings.gemini_api_key = "test_key"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "candidates": [{"finishReason": "SAFETY"}]
        }
        monkeypatch.setattr(httpx.Client, "post", lambda *a, **k: mock_resp)

        try:
            res = analyze_with_gemini("Dangerous text")
            assert res.available is False
            assert res.failure_category == "safety_blocked"
        finally:
            settings.gemini_api_key = original_key

    def test_safety_blocked_prompt_feedback(self, monkeypatch):
        """Scenario 13: promptFeedback blockReason triggers safety_blocked."""
        original_key = settings.gemini_api_key
        settings.gemini_api_key = "test_key"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "promptFeedback": {"blockReason": "SAFETY"}
        }
        monkeypatch.setattr(httpx.Client, "post", lambda *a, **k: mock_resp)

        try:
            res = analyze_with_gemini("Test prompt")
            assert res.available is False
            assert res.failure_category == "safety_blocked"
        finally:
            settings.gemini_api_key = original_key

    def test_provider_status_recovery_after_success(self, monkeypatch):
        """Scenario 14: After a failure, a successful response marks provider as available."""
        original_key = settings.gemini_api_key
        settings.gemini_api_key = "valid_key"

        valid_gemini_payload = {
            "risk_score": 10,
            "risk_level": "low",
            "verdict": "safe",
            "confidence": "high",
            "explanation": "Content appears standard.",
            "recommendations": ["Verify links."],
            "findings": [],
            "highlights": [],
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "candidates": [
                {"content": {"parts": [{"text": json.dumps(valid_gemini_payload)}]}}
            ]
        }
        monkeypatch.setattr(httpx.Client, "post", lambda *a, **k: mock_resp)

        try:
            res = analyze_with_gemini("Hello world")
            assert res.available is True
            assert res.risk_score == 10
            status = get_gemini_provider_status()
            assert status["available"] is True
            assert status["mode"] == "full_ai"
            assert status["success_count"] >= 1
            assert status["last_success_at"] is not None
        finally:
            settings.gemini_api_key = original_key


class TestFallbackByInputType:
    """Tests 15-20: Automatic fallback across all channel input types."""

    def test_text_fallback_mode_schema(self):
        """Scenario 15: Text analysis in fallback mode sets ai_status and analysis_completeness."""
        original_key = settings.gemini_api_key
        settings.gemini_api_key = ""
        try:
            req = TextAnalyzeRequest(content="Dear user click http://fake-bank.site to update KYC.")
            result = analyze_text(req)
            assert isinstance(result, AnalysisResponse)
            assert result.ai_status.mode == "python_fallback"
            assert result.ai_status.available is False
            assert result.analysis_completeness.level == "partial"
            assert result.risk_score >= 30  # brand/normalizer/url detection works
        finally:
            settings.gemini_api_key = original_key

    def test_sms_fallback_mode_schema(self):
        """Scenario 16: SMS smishing analysis functions with Python rules in fallback mode."""
        original_key = settings.gemini_api_key
        settings.gemini_api_key = ""
        try:
            req = TextAnalyzeRequest(
                content="Urgent: Your SBI account is blocked. Visit http://sbi-unblock.xyz now.",
                sender="+919876543210",
            )
            result = analyze_sms(req)
            assert isinstance(result, AnalysisResponse)
            assert result.input_type == "sms"
            assert result.ai_status.mode == "python_fallback"
            assert result.risk_score >= 50
            assert result.verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)
        finally:
            settings.gemini_api_key = original_key

    def test_url_fallback_mode_schema(self):
        """Scenario 17: URL analysis functions completely in fallback mode."""
        original_key = settings.gemini_api_key
        settings.gemini_api_key = ""
        try:
            req = UrlAnalyzeRequest(url="http://sbi-verification.top/login")
            result = analyze_url(req)
            assert isinstance(result, AnalysisResponse)
            assert result.input_type == "url"
            assert result.ai_status.mode == "python_fallback"
            assert result.risk_score >= 50
            assert len(result.findings) >= 1
        finally:
            settings.gemini_api_key = original_key

    def test_eml_fallback_mode_schema(self, tmp_path):
        """Scenario 18: EML file forensics works in fallback mode."""
        original_key = settings.gemini_api_key
        settings.gemini_api_key = ""

        eml_content = (
            b"From: \"State Bank of India\" <attacker@scam-domain.xyz>\r\n"
            b"To: victim@example.com\r\n"
            b"Subject: Immediate Action Required: YONO KYC Update\r\n"
            b"Date: Wed, 20 Oct 2026 10:00:00 +0000\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
            b"Your SBI account has been deactivated. Please update KYC immediately."
        )

        mock_file = MagicMock()
        mock_file.filename = "urgent_notice.eml"
        mock_file.content_type = "message/rfc822"
        mock_file.file.read.return_value = eml_content

        try:
            result = analyze_file(file=mock_file)
            assert isinstance(result, AnalysisResponse)
            assert result.ai_status.mode == "python_fallback"
            assert result.risk_score >= 30
            assert len(result.findings) >= 1
        finally:
            settings.gemini_api_key = original_key

    def test_pdf_with_text_fallback_mode(self):
        """Scenario 19: PDF forensics extracts text and analyzes deterministically in fallback mode."""
        from pypdf import PdfWriter

        writer = PdfWriter()
        writer.add_blank_page(width=200, height=200)

        pdf_bytes = io.BytesIO()
        writer.write(pdf_bytes)
        raw_pdf = pdf_bytes.getvalue()

        original_key = settings.gemini_api_key
        settings.gemini_api_key = ""

        mock_file = MagicMock()
        mock_file.filename = "invoice.pdf"
        mock_file.content_type = "application/pdf"
        mock_file.file.read.return_value = raw_pdf

        try:
            result = analyze_file(file=mock_file)
            assert isinstance(result, AnalysisResponse)
            assert result.ai_status.mode == "python_fallback"
            assert result.analysis_completeness.level in ("inconclusive", "partial")
        finally:
            settings.gemini_api_key = original_key

    def test_screenshot_fallback_is_inconclusive(self):
        """
        Scenario 20: CRITICAL REQUIREMENT — Screenshot analysis without Gemini Vision MUST
        return verdict=SAFE, risk_score=0, and analysis_completeness=inconclusive.
        It must NEVER fabricate a suspicious or malicious verdict from image metadata alone!
        """
        original_key = settings.gemini_api_key
        settings.gemini_api_key = ""

        # Create a small valid test PNG image
        img = Image.new("RGB", (200, 200), color=(73, 109, 137))
        img_bytes = io.BytesIO()
        img.save(img_bytes, format="PNG")
        raw_bytes = img_bytes.getvalue()

        try:
            # 1. Direct screenshot detector test
            screen_res = analyze_screenshot(raw_bytes)
            assert screen_res.available is False
            assert screen_res.risk_score == 0
            assert screen_res.verdict == Verdict.SAFE
            assert "requires Gemini Vision API" in screen_res.explanation

            # 2. End-to-end route test
            mock_file = MagicMock()
            mock_file.filename = "whatsapp_chat.png"
            mock_file.content_type = "image/png"
            mock_file.file.read.return_value = raw_bytes

            result = analyze_file(file=mock_file)
            assert isinstance(result, AnalysisResponse)
            assert result.verdict == Verdict.SAFE
            assert result.risk_score == 0
            assert result.analysis_completeness.level == "inconclusive"
            assert result.ai_status.mode == "python_fallback"
        finally:
            settings.gemini_api_key = original_key


class TestRiskFusionAndSchema:
    """Test 21: Risk fusion without AI and health telemetry."""

    def test_risk_fusion_without_ai(self):
        """Scenario 21: Multi-signal risk fusion aggregates deterministic rules without AI."""
        original_key = settings.gemini_api_key
        settings.gemini_api_key = ""

        try:
            # Text with both homoglyphs, brand keyword, and phishing URL
            text_with_threats = "Dеar SBI user your YONO KYC is pending. Click http://sbi-fake.top immediately."
            req = TextAnalyzeRequest(content=text_with_threats)
            result = analyze_text(req)

            assert result.risk_score >= 50
            assert result.verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)
            assert result.signal_scores.url > 0
            assert result.ai_status.available is False
            assert result.ai_status.mode == "python_fallback"

            # Check health telemetry exposes proper status
            health_info = health()
            assert "ai_engine" in health_info
            assert health_info["ai_engine"]["provider"] == "Google Gemini"
            assert "status" in health_info["ai_engine"]
        finally:
            settings.gemini_api_key = original_key

