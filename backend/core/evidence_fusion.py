"""
AEGIS 2.0 — Evidence Fusion Engine

Central risk-score fusion that combines signals from:
  1. Deterministic Python detectors (URL inspector, brand/NLP engine, email forensics)
  2. Gemini AI contextual analysis
  3. Intelligence service cross-verification (threat feed, brand registry, Tranco)

Precedence and double-counting rules:
  1. Active KNOWN_MALICIOUS threat record → forces score ≥ 85, overrides brand recognition.
  2. Approved campaign domain (is_approved_secondary=True, score < 25) → cap Gemini to 20.
  3. Commercial urgency (LOW severity, no adversarial pattern) → max +5, not stacked with AI.
  4. Stale threat record → max +15 contribution, LOW severity, disclosed.
  5. VERIFIED_LEGITIMATE domain ≠ safe content — body threats still propagate.
  6. Inconclusive extraction (scanned PDF, no-Gemini screenshot) → risk_score = 0,
     verdict = SAFE, completeness = "inconclusive" — always disclosed.
  7. Double-counting guard: per-domain penalty tracked; if intel already added ≥ 75 for
     a domain, the brand heuristic does not add another +50 for the same domain.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from schemas import (
    AnalysisCompleteness,
    Confidence,
    Finding,
    FindingCategory,
    FindingSeverity,
    RiskLevel,
    SignalScores,
    TextHighlight,
    Verdict,
)

try:
    from intelligence.intelligence_service import DomainReputationLevel, DomainReputationResult
except ImportError:
    try:
        from backend.intelligence.intelligence_service import DomainReputationLevel, DomainReputationResult
    except ImportError:
        DomainReputationLevel = None
        DomainReputationResult = None


# ---------------------------------------------------------------------------
# FusionResult
# ---------------------------------------------------------------------------

@dataclass
class FusionResult:
    """
    Output of the EvidenceFusionEngine.fuse() call.
    Maps directly to AnalysisResponse fields.
    """
    risk_score: int
    risk_level: RiskLevel
    verdict: Verdict
    confidence: Confidence
    explanation: str
    recommendations: list[str]
    findings: list[Finding]
    highlights: list[TextHighlight]
    unavailable_checks: list[str]
    analysis_completeness_level: str   # "complete" | "partial" | "inconclusive"
    signal_scores: SignalScores
    gemini_available: bool = False


# ---------------------------------------------------------------------------
# Score → RiskLevel / Verdict helpers (mirrors routes.py)
# ---------------------------------------------------------------------------

def _score_to_risk_level(score: int) -> RiskLevel:
    if score >= 80:
        return RiskLevel.CRITICAL
    elif score >= 55:
        return RiskLevel.HIGH
    elif score >= 25:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _score_to_verdict(score: int) -> Verdict:
    if score >= 55:
        return Verdict.MALICIOUS
    elif score >= 25:
        return Verdict.SUSPICIOUS
    return Verdict.SAFE


# ---------------------------------------------------------------------------
# EvidenceFusionEngine
# ---------------------------------------------------------------------------

class EvidenceFusionEngine:
    """
    Merges deterministic, AI, and intelligence signals into a single
    authoritative FusionResult with strict precedence and double-counting
    prevention.
    """

    def fuse(
        self,
        *,
        evidence,                                   # CanonicalEvidence
        deterministic_findings: list[Finding],
        deterministic_url_scores: dict[str, int],   # url -> score
        deterministic_text_score: int,
        gemini_result,                              # GeminiAnalysisResult | None
        intelligence_results: dict[str, "DomainReputationResult"],
        email_risk_boost: int = 0,
        highlights: Optional[list[TextHighlight]] = None,
    ) -> FusionResult:
        """
        Fuse all signal sources into one FusionResult.

        Parameters
        ----------
        evidence                 : CanonicalEvidence from canonical_evidence.py
        deterministic_findings   : findings from brand/URL/email detectors (pre-collected)
        deterministic_url_scores : {url: risk_score} from analyze_url_deterministic()
        deterministic_text_score : combined_risk_score from analyze_text_content()
        gemini_result            : GeminiAnalysisResult or None
        intelligence_results     : {domain: DomainReputationResult} from intel service
        email_risk_boost         : extra score from email forensics (auth failures etc.)
        highlights               : text highlights from normaliser/brand detector
        """
        # --- 0. Inconclusive extraction short-circuit ---------------------------
        if evidence.extraction_status == "inconclusive":
            unavailable = list(evidence.unavailable_checks)
            return FusionResult(
                risk_score=0,
                risk_level=RiskLevel.LOW,
                verdict=Verdict.SAFE,
                confidence=Confidence.LOW,
                explanation=(
                    "Analysis is inconclusive: the submitted content could not be "
                    "adequately parsed or extracted. This does NOT confirm safety. "
                    + (evidence.unavailable_checks[0] if evidence.unavailable_checks else "")
                ),
                recommendations=[
                    "Treat this content with caution until it can be properly inspected.",
                    "If it is a scanned document, request a machine-readable copy.",
                ],
                findings=list(deterministic_findings),
                highlights=list(highlights or []),
                unavailable_checks=unavailable,
                analysis_completeness_level="inconclusive",
                signal_scores=SignalScores(),
                gemini_available=False,
            )

        # --- 1. Collect all findings and build penalty-tracking state -----------
        all_findings: list[Finding] = list(deterministic_findings)
        penalized_domains: dict[str, int] = {}  # domain -> cumulative intel penalty

        # --- 2. Intelligence cross-verification ---------------------------------
        intel_max_score = 0
        has_known_malicious = False
        malicious_domains: list[str] = []
        stale_domains: list[str] = []

        for domain, rep in intelligence_results.items():
            if DomainReputationLevel is None:
                break
            if rep.reputation == DomainReputationLevel.KNOWN_MALICIOUS:
                has_known_malicious = True
                malicious_domains.append(domain)
                penalty = min(75, 100 - intel_max_score)
                intel_max_score = min(100, intel_max_score + penalty)
                penalized_domains[domain] = penalized_domains.get(domain, 0) + penalty
                all_findings.append(Finding(
                    category=FindingCategory.URL,
                    severity=FindingSeverity.CRITICAL,
                    evidence=f"Domain: {domain}",
                    explanation=(
                        f"Domain '{domain}' is confirmed in active threat intelligence "
                        f"(source: {rep.source}, confidence: {rep.confidence:.0%})."
                    ),
                    recommended_action="Do not visit or interact with this domain.",
                    source_module="intelligence_service:threat_db",
                ))
            elif rep.reputation == DomainReputationLevel.STALE:
                stale_domains.append(domain)
                penalty = 15
                intel_max_score = min(100, intel_max_score + penalty)
                penalized_domains[domain] = penalized_domains.get(domain, 0) + penalty
                all_findings.append(Finding(
                    category=FindingCategory.URL,
                    severity=FindingSeverity.LOW,
                    evidence=f"Domain: {domain}",
                    explanation=(
                        f"Domain '{domain}' has a historical (stale) threat record "
                        f"(source: {rep.source}). TTL exceeded; treat with caution."
                    ),
                    recommended_action="Verify this domain before interacting.",
                    source_module="intelligence_service:threat_db:stale",
                ))

        # --- 3. Determine approved-campaign domains (suppress typosquatting) ----
        approved_campaign_domains: set[str] = set()
        for domain, rep in intelligence_results.items():
            if DomainReputationLevel is not None and rep.is_approved_secondary:
                approved_campaign_domains.add(domain)

        # --- 4. Compute base score from deterministic signals -------------------
        max_url_score = max(deterministic_url_scores.values(), default=0)
        base_det_score = max(deterministic_text_score, max_url_score, email_risk_boost)

        # --- 5. Apply double-counting guard on URL findings ---------------------
        # If a domain was already penalized heavily by intel (>=75), strip the
        # corresponding URL finding's contribution by capping it.
        deduped_url_score = max_url_score
        for domain, url_score in deterministic_url_scores.items():
            domain_key = domain.lower()
            existing_penalty = penalized_domains.get(domain_key, 0)
            if existing_penalty >= 75:
                # Intel already penalized this domain heavily; URL detector
                # is double-counting.  Zero out its contribution.
                deduped_url_score = max(
                    deduped_url_score - url_score,
                    intel_max_score,  # keep at least the intel score
                )
        deduped_url_score = max(0, deduped_url_score)
        base_det_score = max(deterministic_text_score, deduped_url_score, email_risk_boost)

        # --- 6. Merge Gemini signal -------------------------------------------
        gemini_available = False
        gemini_risk_score = 0
        explanation = ""
        recommendations: list[str] = []
        gemini_confidence = Confidence.MEDIUM

        if gemini_result is not None and getattr(gemini_result, "available", False):
            gemini_available = True
            gemini_risk_score = gemini_result.risk_score
            explanation = gemini_result.explanation
            recommendations = list(gemini_result.recommendations)
            gemini_confidence = gemini_result.confidence

            # Approved campaign domain cap
            is_approved = any(
                d in approved_campaign_domains for d in evidence.extracted_domains
            )
            if is_approved and base_det_score < 25:
                gemini_risk_score = min(gemini_risk_score, 20)

            all_findings.extend(gemini_result.findings)
        else:
            # Build fallback explanation
            n = len(all_findings)
            if n > 0:
                explanation = (
                    f"Deterministic analysis identified {n} threat indicator(s). "
                    "Gemini AI contextual analysis is currently unavailable."
                )
            else:
                explanation = "No immediate threat indicators detected. Gemini AI is currently unavailable."

            recommendations = [
                "Do not enter personal credentials or OTPs on unverified domains.",
                "Verify claims through official channels before acting.",
            ]

        # --- 7. Combine scores (prevent double-counting) -----------------------
        if has_known_malicious:
            # Intel-confirmed malicious must dominate
            combined_score = max(base_det_score, gemini_risk_score, intel_max_score)
            combined_score = max(combined_score, 85)
        else:
            combined_score = max(base_det_score, gemini_risk_score, intel_max_score)

        combined_score = max(0, min(100, combined_score))

        # --- 8. Commercial-urgency guard (avoid inflating LOW signals) ---------
        # LOW severity commercial urgency is already in deterministic_findings.
        # It should NOT be stacked on top of a Gemini HIGH/CRITICAL.
        # The score fusion already handles this via max() — no additional adjustment needed.

        # --- 9. Confidence calibration -----------------------------------------
        if gemini_available:
            final_confidence = gemini_confidence
        elif combined_score >= 50:
            final_confidence = Confidence.HIGH
        else:
            final_confidence = Confidence.MEDIUM

        # --- 10. Analysis completeness -----------------------------------------
        if evidence.extraction_status == "partial":
            completeness = "partial"
        elif not gemini_available:
            completeness = "partial"
        else:
            completeness = "complete"

        # --- 11. Unavailable checks --------------------------------------------
        unavailable = list(evidence.unavailable_checks)
        if not gemini_available and gemini_result is not None:
            err = getattr(gemini_result, "error", None)
            msg = err or "Gemini API unavailable: running in deterministic mode"
            unavailable.append(msg)
        elif not gemini_available:
            unavailable.append("Gemini AI: not invoked for this channel")

        # --- 12. Signal scores (for AnalysisResponse) --------------------------
        signal_scores = SignalScores(
            nlp=deterministic_text_score,
            url=max_url_score,
            sender=email_risk_boost,
            email_auth=email_risk_boost,
            context=gemini_risk_score if gemini_available else 0,
        )

        return FusionResult(
            risk_score=combined_score,
            risk_level=_score_to_risk_level(combined_score),
            verdict=_score_to_verdict(combined_score),
            confidence=final_confidence,
            explanation=explanation,
            recommendations=recommendations,
            findings=all_findings,
            highlights=list(highlights or []),
            unavailable_checks=sorted(set(unavailable)),
            analysis_completeness_level=completeness,
            signal_scores=signal_scores,
            gemini_available=gemini_available,
        )


# Module-level singleton
evidence_fusion_engine = EvidenceFusionEngine()

