"""
AEGIS Intelligence Service — central lookup for domain reputation and message patterns.

Aggregates signals from:
  1. Threat feed database (threat_feed_loader) — SQLite cache
  2. Brand registry (domain_loader) — static registry
  3. Tranco domain rankings (tranco_provider) — popularity only, NOT legitimacy
  4. Message pattern datasets (message_loader) — inference signals only

Domain Reputation Precedence (highest to lowest):
  1. threat_intel.db active record -> KNOWN_MALICIOUS (cannot be overridden by allowlist)
  2. threat_intel.db stale/TTL record -> STALE
  3. official_domains.json primary domain + verified -> VERIFIED_LEGITIMATE
  4. official_domains.json secondary domain + verified -> VERIFIED_LEGITIMATE
  5. official_domains.json secondary domain + unverified -> UNKNOWN
  6. Tranco top list -> UNKNOWN (popularity != legitimacy)
  7. Otherwise -> UNKNOWN

IMPORTANT CONSTRAINTS:
  - Message template similarity is an inference signal only — NOT proof of sender authenticity
  - Sender ID patterns are NOT proof of sender authenticity
  - Trusted domain does NOT make every URL path safe
  - Historical malicious records must be marked STALE after TTL, NOT deleted
  - Active KNOWN_MALICIOUS cannot be overridden by allowlist
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional

from .loaders.domain_loader import domain_registry, OfficialDomainEntry, BrandEntry
from .loaders.message_loader import message_loader, MessagePattern
from .loaders.threat_feed_loader import lookup_domain as threat_lookup, ThreatRecord
from .sources.tranco_provider import tranco_provider


class DomainReputationLevel(str, Enum):
    VERIFIED_LEGITIMATE = "verified_legitimate"
    KNOWN_MALICIOUS = "known_malicious"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"
    STALE = "stale"


@dataclass
class DomainReputationResult:
    domain: str
    reputation: DomainReputationLevel
    confidence: float  # 0.0 – 1.0
    source: str
    evidence: list[str] = field(default_factory=list)
    brand: Optional[str] = None
    brand_id: Optional[str] = None
    is_official_primary: bool = False
    is_approved_secondary: bool = False
    secondary_verification_status: Optional[str] = None  # "verified" or "unverified"
    tranco_rank: Optional[int] = None
    threat_record: Optional[ThreatRecord] = None
    freshness: str = "unknown"  # "fresh", "stale", "unknown"


@dataclass
class PatternMatch:
    pattern_id: str
    label: str
    category: str
    similarity_score: float
    notes: str
    # IMPORTANT: similarity is an inference signal only — NOT proof of authenticity


class IntelligenceService:
    """Central intelligence service for AEGIS domain and message analysis."""

    def lookup_domain_reputation(self, domain: str) -> DomainReputationResult:
        """
        Look up domain reputation using the precedence chain.

        Precedence (highest to lowest):
          1. Active threat record -> KNOWN_MALICIOUS
          2. Stale threat record -> STALE
          3. Verified primary domain -> VERIFIED_LEGITIMATE
          4. Verified secondary domain -> VERIFIED_LEGITIMATE
          5. Unverified secondary domain -> UNKNOWN
          6. Tranco top list -> UNKNOWN
          7. Default -> UNKNOWN
        """
        domain = domain.lower().strip()
        tranco_rank = tranco_provider.get_rank(domain)

        # Step 1 & 2: Check threat intel database (highest priority — cannot be overridden)
        threat_record = threat_lookup(domain)
        if threat_record is not None and threat_record.is_active:
            if threat_record.is_stale:
                return DomainReputationResult(
                    domain=domain,
                    reputation=DomainReputationLevel.STALE,
                    confidence=max(0.3, threat_record.confidence * 0.4),
                    source=f"threat_db:{threat_record.source}",
                    evidence=[
                        f"Historical threat record from {threat_record.source}",
                        f"Last seen: {threat_record.last_seen} (exceeds TTL)",
                    ],
                    tranco_rank=tranco_rank,
                    threat_record=threat_record,
                    freshness="stale",
                )
            else:
                return DomainReputationResult(
                    domain=domain,
                    reputation=DomainReputationLevel.KNOWN_MALICIOUS,
                    confidence=threat_record.confidence,
                    source=f"threat_db:{threat_record.source}",
                    evidence=[
                        f"Active threat record from {threat_record.source}",
                        f"First seen: {threat_record.first_seen}",
                    ],
                    tranco_rank=tranco_rank,
                    threat_record=threat_record,
                    freshness="fresh",
                )

        # Steps 3-5: Check brand registry
        domain_entry: Optional[OfficialDomainEntry] = domain_registry.get_domain_entry(domain)
        if domain_entry is not None:
            brand_entry: Optional[BrandEntry] = domain_registry.get_brand(domain_entry.brand_id)
            brand_name = brand_entry.brand_name if brand_entry else domain_entry.brand_id

            if domain_entry.is_primary and domain_entry.verification_status == "verified":
                return DomainReputationResult(
                    domain=domain,
                    reputation=DomainReputationLevel.VERIFIED_LEGITIMATE,
                    confidence=0.95,
                    source="brand_registry:primary",
                    evidence=[f"Official primary domain for {brand_name}"],
                    brand=brand_name,
                    brand_id=domain_entry.brand_id,
                    is_official_primary=True,
                    is_approved_secondary=False,
                    secondary_verification_status=None,
                    tranco_rank=tranco_rank,
                    freshness="fresh",
                )
            elif not domain_entry.is_primary and domain_entry.verification_status == "verified":
                return DomainReputationResult(
                    domain=domain,
                    reputation=DomainReputationLevel.VERIFIED_LEGITIMATE,
                    confidence=0.80,
                    source="brand_registry:secondary:verified",
                    evidence=[f"Verified secondary domain for {brand_name}: {domain_entry.purpose}"],
                    brand=brand_name,
                    brand_id=domain_entry.brand_id,
                    is_official_primary=False,
                    is_approved_secondary=True,
                    secondary_verification_status="verified",
                    tranco_rank=tranco_rank,
                    freshness="fresh",
                )
            elif not domain_entry.is_primary and domain_entry.verification_status == "unverified":
                # Unverified secondary -> UNKNOWN, not VERIFIED_LEGITIMATE
                return DomainReputationResult(
                    domain=domain,
                    reputation=DomainReputationLevel.UNKNOWN,
                    confidence=0.4,
                    source="brand_registry:secondary:unverified",
                    evidence=[f"Listed as secondary domain for {brand_name} but not independently verified ({domain_entry.purpose})"],
                    brand=brand_name,
                    brand_id=domain_entry.brand_id,
                    is_official_primary=False,
                    is_approved_secondary=True,
                    secondary_verification_status="unverified",
                    tranco_rank=tranco_rank,
                    freshness="unknown",
                )

        # Step 6: Tranco popularity — UNKNOWN, not VERIFIED
        if tranco_rank is not None:
            return DomainReputationResult(
                domain=domain,
                reputation=DomainReputationLevel.UNKNOWN,
                confidence=0.3,
                source="tranco_rank",
                evidence=[f"Domain appears in Tranco top list at rank {tranco_rank} — popularity does not indicate legitimacy"],
                tranco_rank=tranco_rank,
                freshness="unknown",
            )

        # Step 7: Default — UNKNOWN
        return DomainReputationResult(
            domain=domain,
            reputation=DomainReputationLevel.UNKNOWN,
            confidence=0.1,
            source="none",
            evidence=["No intelligence records found for this domain"],
            tranco_rank=None,
            freshness="unknown",
        )

    def lookup_official_domain(self, domain: str) -> Optional[OfficialDomainEntry]:
        return domain_registry.get_domain_entry(domain.lower().strip())

    def lookup_brand_domains(self, brand_id: str) -> Optional[BrandEntry]:
        return domain_registry.get_brand(brand_id)

    def lookup_known_malicious_domain(self, domain: str) -> Optional[ThreatRecord]:
        record = threat_lookup(domain.lower().strip())
        if record and not record.is_stale and record.is_active:
            return record
        return None

    def lookup_legitimate_message_patterns(self, text: str) -> list[PatternMatch]:
        """Find legitimate message patterns similar to text.

        Returns inference signals only — NOT proof of sender authenticity.
        """
        matches = message_loader.find_similar_patterns(text, label="legitimate", top_n=3)
        return [
            PatternMatch(
                pattern_id=pattern.id,
                label=pattern.label,
                category=pattern.category,
                similarity_score=score,
                notes=f"Similar to legitimate {pattern.category} pattern (inference signal only — not authenticity proof)",
            )
            for score, pattern in matches
        ]

    def lookup_scam_message_patterns(self, text: str) -> list[PatternMatch]:
        """Find scam message patterns similar to text.

        Returns inference signals only — NOT proof of malicious intent.
        Template similarity alone is insufficient for a MALICIOUS verdict.
        """
        matches = message_loader.find_similar_patterns(text, label="malicious", top_n=3)
        return [
            PatternMatch(
                pattern_id=pattern.id,
                label=pattern.label,
                category=pattern.category,
                similarity_score=score,
                notes=f"Similar to known scam {pattern.category} pattern (similarity score: {score:.2f})",
            )
            for score, pattern in matches
        ]


# Module-level singleton
intelligence_service = IntelligenceService()

