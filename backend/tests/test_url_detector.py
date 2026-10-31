"""
AEGIS 2.0 — Tests for Deterministic URL & SSRF Inspector
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detectors.url_detector import (
    analyze_url_deterministic,
    inspect_redirect_chain_safe,
    is_private_or_blocked_ip,
    validate_hostname_safe,
    validate_url_scheme_and_port,
)
from schemas import FindingCategory, FindingSeverity, UrlReputation


class TestSSRFProtection:
    """Verifies that SSRF attack vectors, loopback, and private IPs are blocked."""

    def test_blocks_localhost(self):
        assert is_private_or_blocked_ip("127.0.0.1") is True
        safe, ip, err = validate_hostname_safe("localhost")
        assert safe is False
        assert "Blocked loopback" in err

    def test_blocks_rfc1918_private_ranges(self):
        assert is_private_or_blocked_ip("10.0.0.1") is True
        assert is_private_or_blocked_ip("172.16.0.5") is True
        assert is_private_or_blocked_ip("192.168.1.1") is True

    def test_blocks_cloud_metadata_ip(self):
        assert is_private_or_blocked_ip("169.254.169.254") is True

    def test_blocks_link_local_and_multicast(self):
        assert is_private_or_blocked_ip("169.254.1.1") is True
        assert is_private_or_blocked_ip("224.0.0.1") is True

    def test_allows_public_ip_and_domains(self):
        # Test literal public IP (does not require external DNS)
        safe, ip, err = validate_hostname_safe("8.8.8.8")
        assert safe is True
        assert err is None
        assert ip == "8.8.8.8"


class TestPortAndSchemeValidation:
    """Verifies strict restriction to HTTP:80 and HTTPS:443."""

    def test_http_port_8080_rejected(self):
        valid, err = validate_url_scheme_and_port("http://example.com:8080/test")
        assert valid is False
        assert "Rejected non-standard port 8080" in err

    def test_http_port_22_rejected(self):
        valid, err = validate_url_scheme_and_port("http://example.com:22/ssh")
        assert valid is False
        assert "Rejected non-standard port 22" in err

    def test_https_port_8080_rejected(self):
        valid, err = validate_url_scheme_and_port("https://example.com:8080/secure")
        assert valid is False
        assert "Rejected non-standard port 8080" in err

    def test_allowed_http_port_80(self):
        # Explicit port 80
        valid, err = validate_url_scheme_and_port("http://example.com:80/path")
        assert valid is True
        assert err is None

        # Implicit port 80
        valid_default, _ = validate_url_scheme_and_port("http://example.com/path")
        assert valid_default is True

    def test_allowed_https_port_443(self):
        # Explicit port 443
        valid, err = validate_url_scheme_and_port("https://example.com:443/login")
        assert valid is True
        assert err is None

        # Implicit port 443
        valid_default, _ = validate_url_scheme_and_port("https://example.com/login")
        assert valid_default is True

    def test_non_http_schemes_rejected(self):
        for bad_url in [
            "ftp://ftp.example.com/file.txt",
            "file:///etc/passwd",
            "gopher://gopher.example.com",
            "javascript:alert(1)",
        ]:
            valid, err = validate_url_scheme_and_port(bad_url)
            assert valid is False
            assert "Only http and https protocols are permitted" in err


class TestURLDetectorRules:
    """Verifies deterministic heuristic flags and brand impersonation."""

    def test_detects_brand_impersonation_in_domain(self):
        res = analyze_url_deterministic("http://sbi-kyc-update.top/login.php")
        assert "typosquatting" in res.flags or "brand_in_subdomain" in res.flags
        assert "non_standard_tld" in res.flags
        assert res.reputation == UrlReputation.MALICIOUS
        assert res.risk_score >= 50
        assert any(f.category == FindingCategory.IMPERSONATION for f in res.findings)

    def test_legitimate_brand_domain_not_flagged_as_impersonation(self):
        res = analyze_url_deterministic("https://www.onlinesbi.sbi/personal/index.html")
        assert "typosquatting" not in res.flags
        assert "brand_in_subdomain" not in res.flags
        assert res.reputation == UrlReputation.CLEAN
        assert res.risk_score < 30

    def test_detects_raw_ip_hostname(self):
        res = analyze_url_deterministic("http://185.190.140.2/verify")
        assert "ip_based_hostname" in res.flags
        assert res.risk_score >= 35

    def test_detects_at_symbol_obfuscation(self):
        res = analyze_url_deterministic("http://google.com@phishingsite.xyz/claim")
        assert "at_symbol_obfuscation" in res.flags
        assert res.risk_score >= 40

    def test_detects_url_shortener(self):
        res = analyze_url_deterministic("https://bit.ly/secure-login-3902")
        assert "url_shortener_detected" in res.flags
        assert res.risk_score >= 15

    def test_detects_non_standard_port_flag(self):
        res = analyze_url_deterministic("http://legit-looking-site.com:8080/portal")
        assert "security_rejected_port_or_scheme" in res.flags
        assert "non_standard_port" in res.flags
        assert res.risk_score >= 45

    def test_detects_malformed_url(self):
        res = analyze_url_deterministic("http://")
        assert res.risk_score > 0
        assert "malformed_url" in res.flags or res.reputation in (UrlReputation.SUSPICIOUS, UrlReputation.CLEAN)


class TestLinkInspectorSafeHandling:
    """Verifies safe redirect following, unsafe redirect rejection, and HTML form detection."""

    def test_unsafe_redirect_destination_rejected(self, monkeypatch):
        # Initial hop is safe, but redirect points to non-standard port 8080
        mock_response = MagicMock()
        mock_response.status_code = 302
        mock_response.headers = {
            "Location": "http://evil-server.com:8080/steal",
            "content-type": "text/html",
        }
        mock_response.text = "Redirecting..."

        import httpx
        monkeypatch.setattr(httpx.Client, "get", lambda *args, **kwargs: mock_response)
        monkeypatch.setattr(
            "detectors.url_detector.validate_hostname_safe",
            lambda host: (True, "93.184.216.34", None),
        )

        hops = inspect_redirect_chain_safe("http://initial-safe.com/step1")
        assert len(hops) == 2
        assert hops[0].status == 302
        assert hops[1].status == 403
        assert hops[1].final is True
        assert "unsafe_redirect_rejected" in hops[1].flags
        assert any("Rejected non-standard port 8080" in f for f in hops[1].flags)

    def test_html_credential_and_otp_form_detection(self, monkeypatch):
        # Inspect returns HTML with title, password, and OTP input fields
        html_content = """
        <!DOCTYPE html>
        <html>
        <head><title>Secure Banking Login</title></head>
        <body>
            <form action="/login" method="POST">
                <input type="text" name="username">
                <input type="password" name="user_password">
                <input type="text" name="otp" placeholder="Enter 6-digit OTP">
                <button type="submit">Submit</button>
            </form>
        </body>
        </html>
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {"content-type": "text/html; charset=utf-8"}
        mock_response.text = html_content

        import httpx
        monkeypatch.setattr(httpx.Client, "get", lambda *args, **kwargs: mock_response)
        monkeypatch.setattr(
            "detectors.url_detector.validate_hostname_safe",
            lambda host: (True, "93.184.216.34", None),
        )

        hops = inspect_redirect_chain_safe("https://banking-portal.org/login")
        assert len(hops) == 1
        assert hops[0].status == 200
        assert hops[0].final is True
        assert hops[0].page_title == "Secure Banking Login"
        assert "credential_harvesting_form" in hops[0].flags
        assert "otp_input_detected" in hops[0].flags
