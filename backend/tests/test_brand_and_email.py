"""
AEGIS 2.0 — Tests for Brand Impersonation, Social Engineering, and Email Forensics
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detectors.brand_detector import analyze_brand_and_social_engineering
from detectors.email_detector import parse_and_inspect_email
from schemas import FindingCategory, FindingSeverity


class TestBrandAndSocialEngineering:
    def test_bank_kyc_suspension_detection(self):
        text = "Dear customer, your SBI account will be blocked today due to pending KYC. Update immediately."
        res = analyze_brand_and_social_engineering(text, sender="+919876543210")
        assert res.claimed_brand == "SBI"
        assert res.is_spoofed_sender is True
        assert res.risk_boost >= 50
        assert len(res.highlights) > 0
        assert any(f.category == FindingCategory.IMPERSONATION for f in res.findings)
        assert any(f.category == FindingCategory.SOCIAL_ENGINEERING for f in res.findings)

    def test_electricity_bill_panic_detection(self):
        text = "Dear Consumer, your electricity power will be disconnected at 9:30 PM from the power house. Call electricity officer now."
        res = analyze_brand_and_social_engineering(text)
        assert res.risk_boost >= 30
        assert any(f.severity == FindingSeverity.HIGH for f in res.findings)

    def test_upi_refund_lure_detection(self):
        text = "Congratulations! You have received a UPI refund of Rs 2400. Enter UPI PIN to claim."
        res = analyze_brand_and_social_engineering(text)
        assert res.risk_boost >= 30
        assert any("PIN" in f.explanation or "UPI" in f.evidence for f in res.findings)

    def test_benign_personal_message_no_false_alarm(self):
        text = "Hey, let's catch up tomorrow for lunch at the cafeteria."
        res = analyze_brand_and_social_engineering(text)
        assert res.risk_boost == 0
        assert len(res.findings) == 0


class TestEmailForensics:
    def test_display_name_spoofing(self):
        raw = """From: "Income Tax Department" <refund-portal@vps-server.xyz>
Subject: Your Tax Refund is Ready
To: citizen@example.com

Please download the attached form to claim your refund.
"""
        res = parse_and_inspect_email(raw)
        assert res.display_name == "Income Tax Department"
        assert res.sender_email == "refund-portal@vps-server.xyz"
        assert res.risk_boost >= 40
        assert any(f.category == FindingCategory.IMPERSONATION for f in res.findings)

    def test_reply_to_mismatch(self):
        raw = """From: Security Alert <alerts@hdfcbank.com>
Reply-To: attacker-collector@darkweb.org
Subject: Urgent Security Notice
To: user@example.com

Please verify your credentials immediately.
"""
        res = parse_and_inspect_email(raw)
        assert res.reply_to == "attacker-collector@darkweb.org"
        assert any("Reply-To" in f.evidence for f in res.findings)
        assert res.risk_boost >= 30

    def test_missing_headers_honesty_rule(self):
        # When only message body is pasted with no RFC 822 headers
        raw = "Your account has been debited by Rs. 500."
        res = parse_and_inspect_email(raw)
        assert any("Not verifiable" in u for u in res.unavailable_checks)
        # Must not fabricate a pass or fail
        assert res.spf_result == "not_verifiable"
        assert res.dkim_result == "not_verifiable"

    def test_failed_authentication_headers(self):
        raw = """From: accounts@sbi.co.in
Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=attacker.com; dkim=fail; dmarc=fail action=quarantine
Subject: Notice

Update KYC now.
"""
        res = parse_and_inspect_email(raw)
        assert res.spf_result == "fail"
        assert res.dkim_result == "fail"
        assert res.dmarc_result == "fail"
        assert any(f.category == FindingCategory.EMAIL_AUTH and f.severity == FindingSeverity.CRITICAL for f in res.findings)

