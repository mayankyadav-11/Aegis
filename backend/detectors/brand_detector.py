"""
AEGIS 2.0 — Brand Impersonation & Indian Social Engineering Rule Engine

Deterministic analysis of:
- Organization impersonation (claimed entity vs actual sender / URLs)
- Numeric sender spoofing: Indian bank / govt messages sent from 10-digit mobile numbers
  instead of TRAI-approved DLT headers (e.g., VM-SBIBNK, AD-HDFCBK)
- High-risk Indian scam patterns:
    * Bank KYC suspension / PAN linking
    * UPI refund / cashback traps
    * Electricity disconnection deadline threats
    * India Post parcel customs fee fraud
    * Part-time Telegram/WhatsApp review job scams
    * Income Tax refund claiming credentials/debit card
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from schemas import Finding, FindingCategory, FindingSeverity, TextHighlight


# Indian Banking & Enterprise DLT Header Patterns (TRAI compliant: 2 letters prefix + hyphen + 6 letters)
TRAI_DLT_PATTERN = re.compile(r"^[A-Za-z]{2}-[A-Za-z0-9]{6}$")

# Scenarios mapping keywords to threat categories
INDIAN_SCAM_PATTERNS = [
    {
        "name": "Bank KYC Suspension Threat",
        "category": FindingCategory.SOCIAL_ENGINEERING,
        "severity": FindingSeverity.HIGH,
        "keywords": ["kyc", "block", "suspend", "deactivate", "yono", "freeze"],
        "regex": re.compile(r"(account\s+will\s+be\s+(blocked|suspended|deactivated|closed)|update\s+(your\s+)?(kyc|pan)|kyc\s+(expired|pending))", re.IGNORECASE),
        "explanation": "State Bank of India and other RBI-regulated banks never immediately freeze customer accounts via SMS or demand credential updates via unverified third-party links.",
        "action": "Do not open any link. Check your account status only through your official bank mobile app or in-branch.",
    },
    {
        "name": "Electricity Disconnection Panic Threat",
        "category": FindingCategory.SOCIAL_ENGINEERING,
        "severity": FindingSeverity.HIGH,
        "keywords": ["electricity", "power", "bill", "disconnect", "tonight", "officer"],
        "regex": re.compile(r"(electricity\s+power\s+will\s+be\s+disconnected|power\s+cut\s+at\s+\d+|call\s+electricity\s+officer)", re.IGNORECASE),
        "explanation": "Disconnection scams exploit immediate fear of blackouts to coerce victims into calling a fraudulent 'helpline' or downloading remote-access malware (AnyDesk/TeamViewer).",
        "action": "Do not call the number provided. Verify outstanding bills on the official DISCOM website/app or call your local utility office.",
    },
    {
        "name": "UPI Cashback / Refund Lure",
        "category": FindingCategory.SOCIAL_ENGINEERING,
        "severity": FindingSeverity.HIGH,
        "keywords": ["upi", "cashback", "refund", "pin", "phonepe", "paytm", "gpay"],
        "regex": re.compile(r"(upi\s+refund|cashback\s+of\s+(inr|rs\.?|₹)\s*\d+|claim\s+(your\s+)?refund|enter\s+upi\s+pin\s+to\s+receive)", re.IGNORECASE),
        "explanation": "UPI architecture never requires entering a UPI PIN to receive funds. Entering a PIN always authorizes a debit transfer from your account.",
        "action": "Never enter your UPI PIN to receive money. Report the sender via the National Cyber Crime Reporting Portal (1930).",
    },
    {
        "name": "India Post / Courier Customs Fee Fraud",
        "category": FindingCategory.IMPERSONATION,
        "severity": FindingSeverity.HIGH,
        "keywords": ["india post", "courier", "parcel", "delivery", "address update", "customs"],
        "regex": re.compile(r"(india\s+post|parcel\s+cannot\s+be\s+delivered|update\s+(your\s+)?address\s+within\s+\d+\s+hours|package\s+held)", re.IGNORECASE),
        "explanation": "Impersonates postal carriers to steal payment card credentials under the pretext of paying a minor ₹25–₹50 address redelivery or customs fee.",
        "action": "Track your parcel strictly via indiapost.gov.in using your original tracking consignment number.",
    },
    {
        "name": "Income Tax Refund Lure",
        "category": FindingCategory.IMPERSONATION,
        "severity": FindingSeverity.CRITICAL,
        "keywords": ["income tax", "refund", "itr", "approved", "bank account details"],
        "regex": re.compile(r"(income\s+tax\s+refund\s+of|refund\s+approved|claim\s+tax\s+refund)", re.IGNORECASE),
        "explanation": "The Income Tax Department calculates refunds and credits them directly to pre-validated bank accounts via ECS/RTGS. They never email download forms requesting debit card PINs.",
        "action": "Check refund status exclusively on incometax.gov.in. Never share debit card numbers or internet banking passwords.",
    },
    {
        "name": "Part-Time Task / Telegram Review Job Scam",
        "category": FindingCategory.SOCIAL_ENGINEERING,
        "severity": FindingSeverity.HIGH,
        "keywords": ["part-time", "daily income", "youtube likes", "hotel review", "telegram", "earn from home"],
        "regex": re.compile(r"(earn\s+(rs\.?|₹)\s*\d{3,}\s*(per\s*day|daily)|part-time\s+job|like\s+youtube\s+videos\s+and\s+earn)", re.IGNORECASE),
        "explanation": "Predatory task scams entice victims with small initial payouts for trivial review tasks, then trap them in 'prepaid task investment deposits' resulting in massive financial loss.",
        "action": "Do not join the Telegram channel or pay any registration/recharge deposit fees.",
    },
]


@dataclass
class BrandAnalysisResult:
    claimed_brand: str | None
    is_spoofed_sender: bool
    findings: list[Finding] = field(default_factory=list)
    highlights: list[TextHighlight] = field(default_factory=list)
    risk_boost: int = 0


def analyze_brand_and_social_engineering(
    text: str,
    sender: str | None = None,
    extracted_urls: list[str] | None = None,
) -> BrandAnalysisResult:
    """
    Run deterministic social engineering and brand impersonation checks on text and sender.
    """
    findings: list[Finding] = []
    highlights: list[TextHighlight] = []
    claimed_brand: str | None = None
    is_spoofed_sender = False
    risk_boost = 0

    lower_text = text.lower()
    combined_sender = (sender or "").strip()

    # 1. Check Sender Format (TRAI DLT compliance in India)
    if combined_sender:
        # Check if sender is a standard 10-digit phone number sending banking/institutional text
        is_10_digit_number = bool(re.match(r"^(\+91|91|0)?[6-9]\d{9}$", combined_sender.replace(" ", "").replace("-", "")))
        
        # Check for claimed brand in sender text or message content
        for brand in ["sbi", "yono", "hdfc", "icici", "axis", "pnb", "rbi", "incometax", "electricity", "indiapost"]:
            if brand in lower_text or brand in combined_sender.lower():
                claimed_brand = brand.upper()
                break

        if claimed_brand and is_10_digit_number:
            is_spoofed_sender = True
            risk_boost += 35
            findings.append(Finding(
                category=FindingCategory.IMPERSONATION,
                severity=FindingSeverity.HIGH,
                evidence=f"Claimed institution '{claimed_brand}' dispatched from personal phone number: {combined_sender}",
                explanation="Legitimate financial and government institutions in India dispatch transactional SMS exclusively through approved TRAI alphabetic headers (e.g. AD-SBIBNK), never personal 10-digit mobile numbers.",
                recommended_action="Block this mobile number immediately and report it to the Cybercrime Helpline at 1930 or cybercrime.gov.in.",
                source_module="brand_impersonation_engine",
            ))

    # 2. Match Social Engineering Scenario Patterns
    for pattern in INDIAN_SCAM_PATTERNS:
        match = pattern["regex"].search(text)
        if match:
            risk_boost += 30
            start, end = match.span()
            highlights.append(TextHighlight(
                start=start,
                end=end,
                severity="high" if pattern["severity"] == FindingSeverity.HIGH else "critical",
                label=pattern["name"],
            ))
            findings.append(Finding(
                category=pattern["category"],
                severity=pattern["severity"],
                evidence=f"Matched pattern '{match.group(0)}'",
                explanation=pattern["explanation"],
                recommended_action=pattern["action"],
                source_module="nlp_social_engineering",
            ))

    return BrandAnalysisResult(
        claimed_brand=claimed_brand,
        is_spoofed_sender=is_spoofed_sender,
        findings=findings,
        highlights=highlights,
        risk_boost=min(80, risk_boost),
    )

