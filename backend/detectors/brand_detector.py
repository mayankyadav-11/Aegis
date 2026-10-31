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

try:
    from intelligence.intelligence_service import intelligence_service, DomainReputationLevel
except ImportError:
    try:
        from backend.intelligence.intelligence_service import intelligence_service, DomainReputationLevel
    except ImportError:
        intelligence_service = None
        DomainReputationLevel = None


# Indian Banking & Enterprise DLT Header Patterns (TRAI compliant: 2 letters prefix + hyphen + 6 letters)
TRAI_DLT_PATTERN = re.compile(r"^[A-Za-z]{2}-[A-Za-z0-9]{6}$")

# Scenarios mapping keywords to threat categories
INDIAN_SCAM_PATTERNS = [
    {
        "name": "Bank KYC Suspension Threat",
        "category": FindingCategory.SOCIAL_ENGINEERING,
        "severity": FindingSeverity.HIGH,
        "keywords": ["kyc", "block", "suspend", "deactivate", "yono", "freeze", "frozen"],
        "regex": re.compile(r"(account\s+(will\s+be|aaj|is)?.*?(blocked|suspended|deactivated|closed|freeze|frozen)|(update|link)\s+(your\s+)?(kyc|pan|aadhaar)|kyc\s+(has\s+)?(expired|pending)|(block|suspend).*?(kyc))", re.IGNORECASE),
        "explanation": "State Bank of India and other RBI-regulated banks never immediately freeze customer accounts via SMS or demand credential updates via unverified third-party links.",
        "action": "Do not open any link. Check your account status only through your official bank mobile app or in-branch.",
    },
    {
        "name": "Electricity Disconnection Panic Threat",
        "category": FindingCategory.SOCIAL_ENGINEERING,
        "severity": FindingSeverity.HIGH,
        "keywords": ["electricity", "power", "bill", "disconnect", "tonight", "officer"],
        "regex": re.compile(r"(electricity\s+(power\s+will\s+be\s+disconnected|power\s+cut|alert)|power\s+cut\s+at\s+\d+|call\s+electricity\s+officer)", re.IGNORECASE),
        "explanation": "Disconnection scams exploit immediate fear of blackouts to coerce victims into calling a fraudulent 'helpline' or downloading remote-access malware (AnyDesk/TeamViewer).",
        "action": "Do not call the number provided. Verify outstanding bills on the official DISCOM website/app or call your local utility office.",
    },
    {
        "name": "UPI Cashback / Refund Lure",
        "category": FindingCategory.SOCIAL_ENGINEERING,
        "severity": FindingSeverity.HIGH,
        "keywords": ["upi", "cashback", "refund", "pin", "phonepe", "paytm", "gpay"],
        "regex": re.compile(r"(upi\s+refund|cashback\s+of\s+(inr|rs\.?|₹)\s*\d+|claim\s+(your\s+)?refund|enter\s+upi\s+pin\s+to\s+(receive|claim)|receive\s+(rs\.?|inr|₹)\s*\d+\s*cashback)", re.IGNORECASE),
        "explanation": "UPI architecture never requires entering a UPI PIN to receive funds. Entering a PIN always authorizes a debit transfer from your account.",
        "action": "Never enter your UPI PIN to receive money. Report the sender via the National Cyber Crime Reporting Portal (1930).",
    },
    {
        "name": "India Post / Courier Customs Fee Fraud",
        "category": FindingCategory.IMPERSONATION,
        "severity": FindingSeverity.HIGH,
        "keywords": ["india post", "courier", "parcel", "delivery", "address update", "customs"],
        "regex": re.compile(r"(india\s+post|(parcel|package)\s+cannot\s+be\s+delivered|update\s+(your\s+)?address\s+within\s+\d+\s+hours|package\s+held)", re.IGNORECASE),
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
    {
        "name": "Law Enforcement / Arrest Threat",
        "category": FindingCategory.SOCIAL_ENGINEERING,
        "severity": FindingSeverity.CRITICAL,
        "keywords": ["arrest", "warrant", "filed case", "police", "legal action"],
        "regex": re.compile(r"(filed\s+case\s+against\s+you|pay\s+(rs\.?|inr|₹)\s*\d+\s*(fine)?\s*immediately\s+to\s+avoid\s+arrest|arrest\s+warrant|police\s+(warrant|action)|court\s+summons|bail\s+charge)", re.IGNORECASE),
        "explanation": "Law enforcement and government agencies in India never issue arrest notices or settlement demands via SMS/messaging apps.",
        "action": "Do not pay any fine or respond. Contact local police or report to cybercrime.gov.in (1930).",
    },
    {
        "name": "Prize / Lottery Advance-Fee Scam",
        "category": FindingCategory.SOCIAL_ENGINEERING,
        "severity": FindingSeverity.HIGH,
        "keywords": ["won", "lucky draw", "lottery", "prize", "shipping charges", "processing fee"],
        "regex": re.compile(r"(congratulations!?\s*you\s+(have\s+)?won|badhai\s+ho|lucky\s+draw|kbc\s+lottery|contest\s+me.*?jeeti|pay\s+(rs\.?|₹)\s*\d+\s*(shipping|processing|clearance)\s*(charges|fee)|processing\s+fees?\s+(rs\.?|₹)\s*\d+|won\s+(free\s+)?gift\s+card)", re.IGNORECASE),
        "explanation": "Advance fee scams claim a major prize was won and require upfront 'shipping charges' or 'taxes' before releasing the non-existent prize.",
        "action": "Never pay money or fees to claim any prize. Legitimate promotions do not demand upfront fees to deliver winnings.",
    },
    {
        "name": "UPI PIN Trap / Expiry Deception",
        "category": FindingCategory.SOCIAL_ENGINEERING,
        "severity": FindingSeverity.HIGH,
        "keywords": ["upi pin", "pin will expire", "reset pin"],
        "regex": re.compile(r"(upi\s+pin\s+will\s+expire|reset\s+at\s+https?://|enter\s+upi\s+pin\s+to\s+claim)", re.IGNORECASE),
        "explanation": "UPI PINs never expire and do not require online portal resets. Entering a UPI PIN always authorizes an outgoing transfer.",
        "action": "Never enter your UPI PIN on external websites or to claim money.",
    },
    {
        "name": "Telecom / SIM Deactivation Scam",
        "category": FindingCategory.SOCIAL_ENGINEERING,
        "severity": FindingSeverity.HIGH,
        "keywords": ["sim card kyc", "service will be suspended"],
        "regex": re.compile(r"(sim\s+card\s+kyc|service\s+will\s+be\s+suspended\s+tonight|bsnl/jio)", re.IGNORECASE),
        "explanation": "Telecom providers do not summarily suspend services overnight via informal SMS requesting third-party KYC verification.",
        "action": "Verify SIM KYC status exclusively at an official operator store or app.",
    },
]

# Commercial marketing urgency (distinguished from adversarial panic)
COMMERCIAL_URGENCY_PATTERN = re.compile(
    r"\b(hurry|limited\s+time|stock\s+runs\s+out|offer\s+expires|don't\s+miss\s+out|sale\s+ends|surprise\s+offer|shop\s+your\s+faves)\b",
    re.IGNORECASE,
)


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
        for brand in [
            "sbi", "yono", "hdfc", "icici", "axis", "pnb", "rbi", "incometax", "electricity",
            "indiapost", "ajio", "kotak", "bob", "bhim", "bluedart", "delhivery", "myntra",
            "amazon", "flipkart", "paytm", "phonepe", "google", "apple", "netflix"
        ]:
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
    matched_scam_pattern = False
    for pattern in INDIAN_SCAM_PATTERNS:
        match = pattern["regex"].search(text)
        if match:
            matched_scam_pattern = True
            boost = 55 if pattern["severity"] == FindingSeverity.CRITICAL else 50
            risk_boost += boost
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

    # 3. Commercial Marketing Urgency (differentiated from adversarial panic)
    commercial_match = COMMERCIAL_URGENCY_PATTERN.search(text)
    if commercial_match and not matched_scam_pattern:
        # Commercial urgency alone carries minimal score and is informational only
        risk_boost += 5
        findings.append(Finding(
            category=FindingCategory.CONTENT,
            severity=FindingSeverity.LOW,
            evidence=f"Marketing urgency indicator: '{commercial_match.group(0)}'",
            explanation="Commercial marketing urgency (e.g. hurry, sale ends, limited stock) is standard in promotional retail campaigns and does not indicate an adversarial security threat.",
            recommended_action="Verify offers directly within the official mobile app or verified portal.",
            source_module="promotional_urgency_analyzer",
        ))

    # 4. Check Extracted URLs Against Threat Intelligence
    if extracted_urls and intelligence_service is not None:
        for url in extracted_urls:
            try:
                # Simple domain extraction
                clean_url = url.strip()
                if "://" in clean_url:
                    clean_url = clean_url.split("://", 1)[1]
                dom = clean_url.split("/")[0].split("?")[0].split(":")[0].lower()
                if dom:
                    intel = intelligence_service.lookup_domain_reputation(dom)
                    if intel.reputation == DomainReputationLevel.KNOWN_MALICIOUS:
                        risk_boost += 50
                        findings.append(Finding(
                            category=FindingCategory.URL,
                            severity=FindingSeverity.CRITICAL,
                            evidence=f"Message contains URL matching threat intelligence: {dom} ({intel.source})",
                            explanation="The destination domain embedded in this communication matches active threat intelligence records for phishing or malware distribution.",
                            recommended_action="Do not click or interact with links in this message.",
                            source_module="threat_intelligence",
                        ))
                        break
            except Exception:
                pass

    return BrandAnalysisResult(
        claimed_brand=claimed_brand,
        is_spoofed_sender=is_spoofed_sender,
        findings=findings,
        highlights=highlights,
        risk_boost=min(80, risk_boost),
    )

