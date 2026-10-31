"""
AEGIS 2.0 — Tests for Gemini Fallback & API Contract Conformance
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.routes import analyze_email, analyze_sms, analyze_text, analyze_url, health
from config import settings
from core.gemini_analyzer import analyze_with_gemini
from schemas import (
    AnalysisResponse,
    EmailAnalyzeRequest,
    RiskLevel,
    TextAnalyzeRequest,
    UrlAnalyzeRequest,
    Verdict,
)


class TestGeminiFallback:
    def test_fallback_when_api_key_missing(self):
        original_key = settings.gemini_api_key
        settings.gemini_api_key = ""
        try:
            res = analyze_with_gemini("Update your SBI KYC account today")
            assert res.available is False
            assert "GEMINI_API_KEY is not configured" in res.error
        finally:
            settings.gemini_api_key = original_key

    def test_fallback_on_network_failure(self, monkeypatch):
        original_key = settings.gemini_api_key
        settings.gemini_api_key = "dummy_invalid_key_for_testing"

        import httpx

        def mock_post(*args, **kwargs):
            raise httpx.ConnectError("Simulated network connection failure")

        monkeypatch.setattr(httpx.Client, "post", mock_post)

        try:
            res = analyze_with_gemini("Test message")
            assert res.available is False
            assert "Simulated network connection failure" in res.error
        finally:
            settings.gemini_api_key = original_key

    def test_fallback_on_empty_candidates(self, monkeypatch):
        original_key = settings.gemini_api_key
        settings.gemini_api_key = "test_key"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"candidates": []}

        import httpx
        monkeypatch.setattr(httpx.Client, "post", lambda *args, **kwargs: mock_resp)

        try:
            res = analyze_with_gemini("Test message")
            assert res.available is False
            assert "no response candidates" in res.error
        finally:
            settings.gemini_api_key = original_key

    def test_fallback_on_empty_parts(self, monkeypatch):
        original_key = settings.gemini_api_key
        settings.gemini_api_key = "test_key"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "candidates": [{"content": {"parts": []}, "finishReason": "STOP"}]
        }

        import httpx
        monkeypatch.setattr(httpx.Client, "post", lambda *args, **kwargs: mock_resp)

        try:
            res = analyze_with_gemini("Test message")
            assert res.available is False
            assert "no content parts" in res.error
        finally:
            settings.gemini_api_key = original_key

    def test_fallback_on_safety_blocked_candidate(self, monkeypatch):
        original_key = settings.gemini_api_key
        settings.gemini_api_key = "test_key"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "candidates": [{"finishReason": "SAFETY"}]
        }

        import httpx
        monkeypatch.setattr(httpx.Client, "post", lambda *args, **kwargs: mock_resp)

        try:
            res = analyze_with_gemini("Test violent or restricted text")
            assert res.available is False
            assert "finishReason=SAFETY" in res.error
        finally:
            settings.gemini_api_key = original_key

    def test_fallback_on_prompt_safety_block(self, monkeypatch):
        original_key = settings.gemini_api_key
        settings.gemini_api_key = "test_key"

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "promptFeedback": {"blockReason": "SAFETY"}
        }

        import httpx
        monkeypatch.setattr(httpx.Client, "post", lambda *args, **kwargs: mock_resp)

        try:
            res = analyze_with_gemini("Test message")
            assert res.available is False
            assert "blocked by safety filter: SAFETY" in res.error
        finally:
            settings.gemini_api_key = original_key


class TestAPIEndpoints:
    def test_health_endpoint(self):
        data = health()
        assert data["status"] == "ok"
        assert "ai_engine" in data
        assert "detectors" in data

    def test_analyze_url_contract_with_url_key(self):
        # Format 1: {"url": "https://..."}
        payload = UrlAnalyzeRequest(url="http://sbi-kyc-update.top/login.php")
        result = analyze_url(payload)

        assert isinstance(result, AnalysisResponse)
        assert result.case_id.startswith("AEG-")
        assert result.input_type == "url"
        assert result.risk_score >= 50
        assert result.evidence_hash is not None
        assert len(result.extracted_urls) == 1
        assert result.extracted_urls[0].reputation in ("suspicious", "malicious")

    def test_analyze_url_contract_with_content_key(self):
        # Format 2: {"content": "https://..."} (matching generic frontend AnalyzeRequest)
        payload = UrlAnalyzeRequest.model_validate({"content": "http://sbi-kyc-update.top/login.php"})
        assert payload.url == "http://sbi-kyc-update.top/login.php"
        result = analyze_url(payload)

        assert isinstance(result, AnalysisResponse)
        assert result.case_id.startswith("AEG-")
        assert result.input_type == "url"
        assert result.risk_score >= 50
        assert len(result.extracted_urls) == 1

    def test_analyze_text_contract(self):
        payload = TextAnalyzeRequest(
            content="Aapka account block ho jayega turant KYC update karo http://sbi-fake.xyz",
            input_type="text",
        )
        result = analyze_text(payload)

        assert isinstance(result, AnalysisResponse)
        assert result.input_type == "text"
        assert result.risk_score >= 30
        assert len(result.extracted_urls) == 1
        assert result.evidence_hash is not None

    def test_analyze_sms_contract(self):
        payload = TextAnalyzeRequest(
            content="Dear SBI user your YONO account will be suspended today. Click http://sbi-kyc.top to verify.",
            sender="+919876543210",
        )
        result = analyze_sms(payload)

        assert isinstance(result, AnalysisResponse)
        assert result.input_type == "sms"
        assert result.risk_score >= 60
        assert result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert result.verdict == Verdict.MALICIOUS
        assert len(result.findings) >= 2
        assert len(result.highlights) >= 1

    def test_analyze_email_contract(self):
        payload = EmailAnalyzeRequest(
            content="Please verify your Income Tax refund at http://tax-claim.site",
            sender="tax-refund@vps-spoofer.top",
            subject="Income Tax Refund Notification",
            raw_headers='From: "Income Tax Department" <tax-refund@vps-spoofer.top>\nSubject: Notice',
        )
        result = analyze_email(payload)

        assert isinstance(result, AnalysisResponse)
        assert result.input_type == "email"
        assert result.risk_score >= 40
        assert result.evidence_hash is not None
        assert len(result.findings) >= 1
