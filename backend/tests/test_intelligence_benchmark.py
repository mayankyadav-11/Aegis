"""
AEGIS Intelligence Benchmark Test Suite — Phase 3.7

Tests 105 labelled evaluation cases covering:
  - Legitimate communications (banking alerts, OTPs, retail promotions, deliveries, travel, government)
  - Malicious communications (KYC phishing, UPI traps, electricity scams, prize scams, credential harvesting, coercion)
  - Ambiguous cases (unverified secondary campaign links, newly registered neutral domains)

Metrics evaluated: Precision, Recall, F1 Score, False Positive Rate (FPR), False Negative Rate (FNR).

DISCLAIMER: This benchmark uses synthetic and anonymized evaluation cases.
Results reflect deterministic engine accuracy on defined benchmark sets,
NOT real-world population-level safety guarantees.
"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from detectors.url_detector import analyze_url_deterministic
from detectors.brand_detector import analyze_brand_and_social_engineering
from detectors.text_detector import analyze_text_content
from intelligence.intelligence_service import intelligence_service, DomainReputationLevel
from schemas import UrlReputation, FindingCategory, FindingSeverity


# ===========================================================================
# 1. AJIO Regression Tests (Mandatory Acceptance Criteria)
# ===========================================================================

class TestAJIORegressionNegative:
    """AJIO Regression Test 1: Legitimate promotional communication must NOT be MALICIOUS."""

    AJIO_PROMO_TEXT = (
        "You have a SURPRISE OFFER waiting in your AJIO cart for the next few hours. "
        "Shop your faves before the stock runs out! HURRY\nhttps://ajioin.in/AJIOIN/gnuEbp"
    )
    AJIO_PROMO_URL = "https://ajioin.in/AJIOIN/gnuEbp"

    def test_ajio_promo_url_not_malicious(self):
        """ajioin.in campaign URL must NOT trigger MALICIOUS verdict."""
        result = analyze_url_deterministic(self.AJIO_PROMO_URL)
        assert result.reputation != UrlReputation.MALICIOUS, (
            f"AJIO regression failed: ajioin.in was incorrectly flagged MALICIOUS. "
            f"Score: {result.risk_score}, Flags: {result.flags}"
        )
        assert "typosquatting" not in result.flags
        assert "brand_in_subdomain" not in result.flags

    def test_ajio_promo_domain_intelligence_not_malicious(self):
        """ajioin.in domain reputation must NOT be KNOWN_MALICIOUS in threat intel."""
        result = intelligence_service.lookup_domain_reputation("ajioin.in")
        assert result.reputation != DomainReputationLevel.KNOWN_MALICIOUS, (
            "ajioin.in returned KNOWN_MALICIOUS — threat feed false positive detected"
        )

    def test_ajio_promo_domain_is_known_secondary(self):
        """ajioin.in must be recognized as an approved secondary with unverified status."""
        result = intelligence_service.lookup_domain_reputation("ajioin.in")
        assert result.is_approved_secondary is True, "ajioin.in must be recognized as approved_additional_domain"
        assert result.secondary_verification_status == "unverified", "ajioin.in must remain unverified"
        assert result.reputation == DomainReputationLevel.UNKNOWN

    def test_ajio_promo_message_not_malicious(self):
        """Full promotional message must NOT be rated MALICIOUS (>60) without adversarial threat signals."""
        result = analyze_brand_and_social_engineering(
            text=self.AJIO_PROMO_TEXT,
            extracted_urls=[self.AJIO_PROMO_URL],
        )
        # Commercial urgency should contribute at most minimal boost, not panic score
        assert result.risk_boost < 30, f"Promo risk boost too high: {result.risk_boost}"


class TestAJIORegressionPositive:
    """AJIO Regression Test 2: Fake prize / advance-fee scam must be MALICIOUS."""

    AJIO_SCAM_URL = "https://ajio-claim-reward.xyz/login"
    AJIO_SCAM_TEXT = (
        "AJIO Congratulations! You have won an iPhone 16 in AJIO Diwali Lucky Draw. "
        "Claim your prize within 2 hours by paying ₹499 shipping charges at "
        "https://ajio-claim-reward.xyz/login"
    )

    def test_ajio_scam_url_is_malicious(self):
        """ajio-claim-reward.xyz prize scam URL must return MALICIOUS."""
        result = analyze_url_deterministic(self.AJIO_SCAM_URL)
        assert result.reputation == UrlReputation.MALICIOUS, (
            f"AJIO scam regression failed: expected MALICIOUS but got {result.reputation}. "
            f"Score: {result.risk_score}, Flags: {result.flags}"
        )
        assert result.risk_score >= 60

    def test_ajio_scam_message_detected(self):
        """Prize scam social engineering pattern must be detected with high risk."""
        result = analyze_brand_and_social_engineering(
            text=self.AJIO_SCAM_TEXT,
            extracted_urls=[self.AJIO_SCAM_URL],
        )
        assert result.risk_boost >= 50
        assert any(
            "Prize" in f.evidence or "Prize" in f.explanation or "threat_intelligence" in f.source_module
            for f in result.findings
        )


# ===========================================================================
# 2. Intelligence Service Unit Tests
# ===========================================================================

class TestIntelligenceServiceDomainLookup:

    def test_official_primary_domain_verified_legitimate(self):
        """Primary domains in registry must return VERIFIED_LEGITIMATE."""
        for domain in ["sbi.co.in", "hdfcbank.com", "icicibank.com", "ajio.com", "flipkart.com"]:
            result = intelligence_service.lookup_domain_reputation(domain)
            assert result.reputation == DomainReputationLevel.VERIFIED_LEGITIMATE, f"{domain} should be VERIFIED_LEGITIMATE"
            assert result.is_official_primary is True
            assert result.confidence >= 0.85

    def test_unverified_secondary_domains_return_unknown(self):
        """Secondary domains without corporate verification must return UNKNOWN."""
        for domain in ["ajioin.in", "hdfcbk.io"]:
            result = intelligence_service.lookup_domain_reputation(domain)
            assert result.reputation == DomainReputationLevel.UNKNOWN, f"{domain} must return UNKNOWN"
            assert result.is_approved_secondary is True
            assert result.secondary_verification_status == "unverified"

    def test_verified_secondary_domains_return_verified_legitimate(self):
        """Secondary domains with verified status must return VERIFIED_LEGITIMATE."""
        result = intelligence_service.lookup_domain_reputation("onlinesbi.sbi")
        assert result.reputation == DomainReputationLevel.VERIFIED_LEGITIMATE
        assert result.is_approved_secondary is True
        assert result.secondary_verification_status == "verified"

    def test_random_domain_returns_unknown(self):
        """Random uncatalogued domains must return UNKNOWN."""
        result = intelligence_service.lookup_domain_reputation("random-novel-startup-123.com")
        assert result.reputation == DomainReputationLevel.UNKNOWN
        assert result.is_official_primary is False
        assert result.is_approved_secondary is False

    def test_popularity_rank_alone_does_not_grant_legitimacy(self):
        """Tranco listed domain not in brand registry must remain UNKNOWN (popularity != legitimacy)."""
        result = intelligence_service.lookup_domain_reputation("swiggy.com")
        assert result.tranco_rank is not None, "swiggy.com should have Tranco rank"
        assert result.reputation == DomainReputationLevel.UNKNOWN, "Tranco rank alone must NOT make domain VERIFIED_LEGITIMATE"

    def test_active_threat_record_returns_known_malicious(self):
        """Known malicious domain from threat database returns KNOWN_MALICIOUS."""
        result = intelligence_service.lookup_domain_reputation("sbi-kyc-update.xyz")
        assert result.reputation == DomainReputationLevel.KNOWN_MALICIOUS
        assert result.freshness == "fresh"
        assert len(result.evidence) > 0


class TestIntelligenceServiceMessagePatterns:

    def test_scam_pattern_matching(self):
        """Scam text matches relevant scam patterns in knowledge base."""
        text = "Your electricity will be cut tonight at 9:30 PM due to unpaid bill."
        matches = intelligence_service.lookup_scam_message_patterns(text)
        assert len(matches) > 0
        assert all(hasattr(m, "similarity_score") for m in matches)

    def test_legitimate_pattern_matching(self):
        """Banking alert text matches legitimate patterns."""
        text = "Dear customer, your A/c XXXX1234 is debited by Rs. 1500.00 on 31-Oct-2026."
        matches = intelligence_service.lookup_legitimate_message_patterns(text)
        assert len(matches) > 0

    def test_pattern_notes_contain_authenticity_disclaimer(self):
        """Pattern matches must explicitly carry disclaimers that similarity != authenticity."""
        matches = intelligence_service.lookup_legitimate_message_patterns("Rs 500 debited")
        for match in matches:
            assert "inference signal only" in match.notes.lower()


# ===========================================================================
# 3. 105-Case Evaluation Benchmark
# ===========================================================================

# Benchmark cases format: (case_type, content, expected_malicious, label_description)
# expected_malicious: True = Malicious, False = Non-Malicious (Safe or Ambiguous)
BENCHMARK_CASES = [
    # --- LEGITIMATE COMMUNICATIONS (40 cases) ---
    # Official Banking URLs
    ("url", "https://sbi.co.in/portal/web/guest/home", False, "SBI official portal"),
    ("url", "https://onlinesbi.sbi/personal/index.html", False, "OnlineSBI verified secondary"),
    ("url", "https://hdfcbank.com/personal/online-banking", False, "HDFC official banking"),
    ("url", "https://icicibank.com/personal-banking/insta-save", False, "ICICI savings portal"),
    ("url", "https://axisbank.com/retail/accounts/savings-account", False, "Axis Bank official"),
    ("url", "https://kotak.com/en/personal-banking.html", False, "Kotak Bank official"),
    ("url", "https://pnbindia.in/retail.html", False, "PNB official portal"),
    ("url", "https://bankofbaroda.in/personal-banking", False, "Bank of Baroda official"),
    ("url", "https://bankofbaroda.com/about-us", False, "Bank of Baroda verified secondary"),
    ("url", "https://rbi.org.in/Scripts/BS_PressReleaseDisplay.aspx", False, "RBI official portal"),

    # Official Government & Regulatory URLs
    ("url", "https://incometax.gov.in/iec/foportal/", False, "Income Tax official e-filing"),
    ("url", "https://uidai.gov.in/en/my-aadhaar.html", False, "UIDAI Aadhaar portal"),
    ("url", "https://myaadhaar.uidai.gov.in/", False, "MyAadhaar verified sub-portal"),
    ("url", "https://indiapost.gov.in/VAS/Pages/trackconsignment.aspx", False, "India Post consignment tracking"),
    ("url", "https://epfindia.gov.in/site_en/index.php", False, "EPFO official portal"),
    ("url", "https://bhimupi.org.in/", False, "BHIM UPI official"),
    ("url", "https://npci.org.in/", False, "NPCI official"),

    # Official E-Commerce & Retail URLs
    ("url", "https://ajio.com/shop/sale", False, "AJIO official storefront"),
    ("url", "https://flipkart.com/big-billion-days", False, "Flipkart official storefront"),
    ("url", "https://myntra.com/sale", False, "Myntra official storefront"),
    ("url", "https://amazon.in/deals", False, "Amazon India official"),
    ("url", "https://paytm.com/recharge", False, "Paytm official recharges"),
    ("url", "https://phonepe.com/en/", False, "PhonePe official"),

    # Legitimate Banking Alerts (Text)
    ("text", "Dear SBI User, your A/c XXXX1234 is debited by Rs. 1500.00 on 31-Oct-2026. Avl Bal Rs. 24500.50.", False, "SBI debit alert"),
    ("text", "HDFC Bank: Rs 5,000.00 deposited in your A/c ending 5678 via UPI on 31-OCT-26. Current balance: Rs 42,150.00.", False, "HDFC deposit alert"),
    ("text", "ICICI Bank: Alert! Transaction of INR 750.00 made on your Credit Card ending 9012 at SWIGGY.", False, "ICICI credit card alert"),
    ("text", "Axis Bank: INR 3,200.00 debited from A/c XX3456 at ATM cash withdrawal. Avail Bal: INR 12,800.00.", False, "Axis ATM alert"),
    ("text", "Kotak Bank: Rs. 1200.00 sent to Priya via Kotak UPI from A/c ending 7890. Ref no 630512345678.", False, "Kotak UPI transfer"),
    ("text", "PNB: Your account XX1122 has been credited with salary INR 65,000.00. Available balance INR 72,500.00.", False, "PNB salary alert"),

    # Legitimate OTPs (Text)
    ("text", "458921 is the OTP for login to SBI NetBanking. Valid for 3 mins. Never share OTP with anyone.", False, "SBI login OTP"),
    ("text", "912345 is your OTP for HDFC Bank card payment of Rs 1,499.00 at AMAZON. Do NOT share OTP.", False, "HDFC purchase OTP"),
    ("text", "Your Swiggy login code is 882190. Valid for 10 minutes. Please do not share this with anyone.", False, "Swiggy OTP"),
    ("text", "349012 is your Amazon OTP. Don't share it with anyone.", False, "Amazon sign-in OTP"),
    ("text", "G-782194 is your Google verification code. Do not share your code with anyone.", False, "Google 2FA code"),

    # Legitimate Retail Promotions (Text)
    ("text", "Big Billion Days are BACK! Grab mega deals on electronics starting midnight at flipkart.com", False, "Flipkart promo text"),
    ("text", "Hungry? Get 50% OFF up to Rs. 100 on your favourite restaurants today! Code: WELCOME50 on Swiggy.", False, "Swiggy promo text"),
    ("text", "Weekend Special! Flat ₹150 off on orders above ₹399 with Zomato Gold.", False, "Zomato dining offer"),
    ("text", "Pay your electricity bill on Paytm and win assured cashback up to ₹100. Code: BIJLI100.", False, "Paytm bill promo"),
    ("text", "Myntra End of Reason Sale! 50-80% off on premium apparel valid till Sunday midnight.", False, "Myntra sale promo"),

    # --- MALICIOUS COMMUNICATIONS (45 cases) ---
    # Phishing URLs targeting Banking
    ("url", "https://sbi-kyc-update.xyz/login", True, "SBI KYC phishing .xyz"),
    ("url", "https://hdfc-netbanking-verify.top/account", True, "HDFC Netbanking fake .top"),
    ("url", "https://icici-imobile-login.xyz/auth", True, "ICICI mobile phishing"),
    ("url", "https://axis-bank-verify.top/pan-link", True, "Axis Bank fake KYC"),
    ("url", "https://kotak811-kyc.xyz/unblock", True, "Kotak 811 phishing"),
    ("url", "https://pnb-one-kyc.top/update", True, "PNB One fake portal"),
    ("url", "https://bob-world-kyc.xyz/login", True, "BoB World fake KYC"),
    ("url", "https://onlinesbi-retail-login.club/auth", True, "SBI phishing on .club"),
    ("url", "https://sbi.netbanking-login.top/", True, "Subdomain spoofing SBI"),
    ("url", "https://hdfc-card-rewards.top/claim", True, "HDFC reward scam site"),

    # Phishing URLs targeting Government / Identity / Tax
    ("url", "https://incometax-refund-claim.xyz/submit", True, "Income tax fake refund portal"),
    ("url", "https://income-tax-refund2026.top/pan", True, "Income tax fake portal .top"),
    ("url", "https://uidai-aadhaar-update.xyz/biometric", True, "UIDAI fake biometric site"),
    ("url", "https://myaadhaar-download.top/otp", True, "Fake Aadhaar download portal"),
    ("url", "https://indiapost-customs-fee.xyz/pay", True, "India Post fake parcel site"),
    ("url", "https://epfo-claim-status.xyz/uan", True, "EPFO fake claim portal"),
    ("url", "https://rbi-lottery-approval.top/claim", True, "RBI lottery scam portal"),

    # Scam & Lottery URLs targeting E-Commerce
    ("url", "https://ajio-claim-reward.xyz/login", True, "AJIO fake prize portal"),
    ("url", "https://flipkart-winner-prize.xyz/claim", True, "Flipkart lucky draw scam"),
    ("url", "https://amazon-india-offer.xyz/gift-card", True, "Amazon fake gift card"),
    ("url", "https://myntra-scratch-win.top/reward", True, "Myntra scratch card scam"),
    ("url", "https://paytm-kyc.xyz/verify", True, "Paytm fake KYC portal"),
    ("url", "https://phonepe-rewards-claim.xyz/scratch", True, "PhonePe fake cashback"),
    ("url", "https://gpay-rewards-fest.top/claim", True, "GPay fake reward page"),
    ("url", "https://upi-pin-update.xyz/verify", True, "UPI PIN phishing portal"),
    ("url", "https://electricity-bill-pay.xyz/bill", True, "Electricity disconnect fake portal"),

    # Malicious Social Engineering Messages (Text)
    ("text", "URGENT: Your SBI Bank account will be BLOCKED within 24 hours due to pending KYC update. Click: https://sbi-kyc-update.xyz/login", True, "SBI account block text"),
    ("text", "Dear Customer, your HDFC netbanking access is suspended today. Update PAN at https://hdfc-netbanking-verify.top/account", True, "HDFC suspension text"),
    ("text", "Dear consumer, your electricity power will be disconnected tonight at 9:30 PM due to unpaid bill. Pay at https://electricity-bill-pay.xyz", True, "Electricity disconnection scam"),
    ("text", "AJIO Congratulations! You have won an iPhone 16 in AJIO Diwali Lucky Draw. Pay ₹499 shipping charges at https://ajio-claim-reward.xyz/login", True, "AJIO advance fee scam"),
    ("text", "KBC Lottery Dept: You have won Rs 25,00,000 in Kaun Banega Crorepati WhatsApp lucky draw. Call 9123456789.", True, "KBC lottery scam text"),
    ("text", "India Post: Your package cannot be delivered due to wrong address. Pay Rs 25 fee at https://indiapost-customs-fee.xyz", True, "India Post fee smishing"),
    ("text", "Income Tax Department: Tax refund of Rs. 42,500 has been approved. Confirm details at https://income-tax-refund2026.top", True, "IT refund phishing text"),
    ("text", "Income Tax dept has filed case against you. Pay Rs 15000 fine immediately to avoid arrest.", True, "Law enforcement coercion"),
    ("text", "Receive Rs 3000 cashback directly in bank! Enter UPI PIN to claim reward immediately.", True, "UPI PIN receive money trap"),
    ("text", "Your UPI PIN will expire. Reset at https://upi-pin-update.xyz to avoid transaction failure.", True, "UPI PIN expiry phishing"),
    ("text", "Part-time job offer! Earn Rs 2000 to Rs 5000 daily by liking YouTube videos. Join Telegram: t.me/fake_job", True, "Telegram review job scam"),
    ("text", "Aapka SBI account aaj raat 10 baje block ho jayega KYC na hone ke karan. Link par click karein: https://sbi-kyc-update.xyz/login", True, "Hinglish KYC panic text"),
    ("text", "Badhai ho! Aapne Flipkart Diwali contest me Safari car jeeti hai. Processing fees Rs 1500 pay karein.", True, "Hinglish car prize advance fee"),
    ("text", "Electricity alert: Power cut at 9:30 PM for non payment. Call electricity officer immediately.", True, "Electricity officer call trap"),
    ("text", "Your SIM card KYC has expired. BSNL/Jio service will be suspended tonight. Update now.", True, "SIM card KYC suspension scam"),
    ("text", "Police warrant issued against you for cyber fraud. Pay fine to avoid arrest within 1 hour.", True, "Police cyber fraud arrest scam"),
    ("text", "Congratulations! You won free gift card worth Rs 10000. Enter credit card details to activate.", True, "Gift card credit card theft"),
    ("text", "Your ICICI Bank account is frozen. Click http://icici-verify.xyz to submit Aadhaar copy.", True, "Frozen account Aadhaar scam"),
    ("text", "Court summons delivered to your name. Download legal notice PDF and pay bail charge.", True, "Court summons bail extortion"),

    # --- AMBIGUOUS / UNVERIFIED / NEUTRAL COMMUNICATIONS (20 cases) ---
    # Unverified campaign tracking links (should NOT be classified as Malicious without threat intel)
    ("url", "https://ajioin.in/AJIOIN/gnuEbp", False, "AJIO unverified campaign tracking URL"),
    ("url", "https://hdfcbk.io/s/x92", False, "HDFC unverified SMS shortlink"),
    ("url", "https://unknown-local-gym-delhi.in/membership", False, "Unknown local business domain"),
    ("url", "https://myshop-artisan-crafts.co.in/store", False, "Small merchant website"),
    ("url", "https://tech-blog-tutorials-daily.org/python", False, "Independent blog domain"),
    ("url", "https://acme-consulting-partners.in/about", False, "Consulting firm domain"),
    ("url", "https://neighborhood-bakery-pune.com/menu", False, "Local bakery website"),
    ("url", "https://regional-organic-farms.in/order", False, "Regional farm store"),
    ("url", "https://dev-portfolio-rahul.me/projects", False, "Developer portfolio"),
    ("url", "https://coaching-classes-jaipur.org/admission", False, "Coaching institute portal"),

    # Neutral or Ambiguous Text Messages
    ("text", "You have a SURPRISE OFFER waiting in your AJIO cart for the next few hours. Shop your faves before stock runs out! HURRY", False, "AJIO marketing text alone"),
    ("text", "Hey Rahul, let's catch up tomorrow for lunch at the office cafeteria.", False, "Casual workplace message"),
    ("text", "Your appointment with Dr. Sharma is scheduled for tomorrow 4:00 PM at Apollo Clinic.", False, "Doctor appointment confirmation"),
    ("text", "Your order from Sharma Sweets is ready for pickup. Thank you for ordering with us.", False, "Local store order notification"),
    ("text", "Meeting rescheduled to 3:30 PM today on Google Meet. Link in calendar invite.", False, "Calendar rescheduling note"),
    ("text", "Please find attached the quarterly financial summary report for your review.", False, "Neutral business email body"),
    ("text", "Reminder: Library book 'Clean Code' is due for return on 05-Nov-2026.", False, "Library return reminder"),
    ("text", "Your gym membership renewal is due next week. Visit desk or pay via reception UPI.", False, "Gym membership renewal"),
    ("text", "Gas cylinder booking confirmed. Delivery expected in 2 working days. Ref: IND90214.", False, "LPG cylinder delivery alert"),
    ("text", "Society maintenance charges of Rs 2500 for October are due. Please pay to treasurer.", False, "Apartment society dues alert"),
]


def _evaluate_benchmark_case(case_type: str, content: str) -> bool:
    """Evaluate whether a benchmark case is predicted as MALICIOUS."""
    if case_type == "url":
        res = analyze_url_deterministic(content)
        return res.reputation == UrlReputation.MALICIOUS
    else:
        # Extract URLs if present in text
        import re
        urls = re.findall(r'https?://[^\s]+', content)
        brand_res = analyze_brand_and_social_engineering(content, extracted_urls=urls)
        # Text is malicious if risk_boost indicates high malicious confidence (>= 50)
        return brand_res.risk_boost >= 50


class TestIntelligenceBenchmark:
    """
    Evaluation benchmark for AEGIS Phase 3.7.

    Evaluates 105 labelled benchmark cases and reports metrics:
      - Precision: TP / (TP + FP)
      - Recall:    TP / (TP + FN)
      - F1 Score:  2 * P * R / (P + R)
      - False Positive Rate: FP / (FP + TN)
      - False Negative Rate: FN / (FN + TP)

    DISCLAIMER: Synthetic benchmark — NOT real-world accuracy claims.
    """

    def test_benchmark_metrics_and_quality_gates(self):
        tp = tn = fp = fn = 0
        false_positive_cases = []
        false_negative_cases = []

        for case_type, content, expected_malicious, description in BENCHMARK_CASES:
            predicted_malicious = _evaluate_benchmark_case(case_type, content)

            if expected_malicious and predicted_malicious:
                tp += 1
            elif not expected_malicious and not predicted_malicious:
                tn += 1
            elif not expected_malicious and predicted_malicious:
                fp += 1
                false_positive_cases.append((description, content[:60]))
            elif expected_malicious and not predicted_malicious:
                fn += 1
                false_negative_cases.append((description, content[:60]))

        total = tp + tn + fp + fn
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

        print(f"\n==================================================")
        print(f"AEGIS Phase 3.7 Threat Intelligence Benchmark")
        print(f"==================================================")
        print(f"Total Cases:     {total}")
        print(f"True Positives:  {tp}")
        print(f"True Negatives:  {tn}")
        print(f"False Positives: {fp}")
        print(f"False Negatives: {fn}")
        print(f"--------------------------------------------------")
        print(f"Precision:       {precision:.4f} ({precision*100:.2f}%)")
        print(f"Recall:          {recall:.4f} ({recall*100:.2f}%)")
        print(f"F1 Score:        {f1:.4f}")
        print(f"FPR (False Pos): {fpr:.4f} ({fpr*100:.2f}%)")
        print(f"FNR (False Neg): {fnr:.4f} ({fnr*100:.2f}%)")
        print(f"==================================================")
        print(f"DISCLAIMER: Synthetic evaluation cases only.")
        print(f"Not a real-world population security guarantee.")
        print(f"==================================================")

        if false_positive_cases:
            print("\nFALSE POSITIVES:")
            for desc, snippet in false_positive_cases:
                print(f"  - {desc}: {snippet}")

        if false_negative_cases:
            print("\nFALSE NEGATIVES:")
            for desc, snippet in false_negative_cases:
                print(f"  - {desc}: {snippet}")

        # Quality Gates:
        # 1. Zero false positives on legitimate banking & retail communications
        assert fp == 0, f"Expected 0 False Positives, but got {fp}: {false_positive_cases}"
        # 2. High detection recall on known malicious patterns (>= 80%)
        assert recall >= 0.80, f"Recall {recall:.4f} below target quality gate 0.80"
        # 3. High F1 score (>= 0.85)
        assert f1 >= 0.85, f"F1 score {f1:.4f} below target quality gate 0.85"

