"""
AEGIS 2.0 — Text Threat Detector

Combines:
1. Deterministic normalisation (NFKC, zero-width, homoglyph detection) via core.normalizer
2. Deterministic Indian social engineering & sender checks via detectors.brand_detector
3. Deep contextual LLM analysis via core.gemini_analyzer (with graceful fallback)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from core.normalizer import normalise, NormalisationResult
from detectors.brand_detector import analyze_brand_and_social_engineering, BrandAnalysisResult
from core.gemini_analyzer import analyze_with_gemini, GeminiAnalysisResult
from schemas import Finding, FindingCategory, FindingSeverity, TextHighlight


@dataclass
class TextThreatAnalysis:
    normalisation: NormalisationResult
    brand_analysis: BrandAnalysisResult
    gemini_analysis: GeminiAnalysisResult
    findings: list[Finding] = field(default_factory=list)
    highlights: list[TextHighlight] = field(default_factory=list)
    combined_risk_score: int = 0
    unavailable_checks: list[str] = field(default_factory=list)


def analyze_text_content(
    content: str,
    channel_type: str = "text",
    sender: str | None = None,
    subject: str | None = None,
) -> TextThreatAnalysis:
    """
    Run complete text threat analysis across deterministic normalizer,
    brand/social engineering engine, and Gemini API.
    """
    findings: list[Finding] = []
    highlights: list[TextHighlight] = []
    unavailable: list[str] = []

    # 1. Normalisation
    norm = normalise(content)

    if norm.zero_width_count > 0:
        findings.append(Finding(
            category=FindingCategory.CONTENT,
            severity=FindingSeverity.MEDIUM,
            evidence=f"Detected {norm.zero_width_count} hidden zero-width character(s)",
            explanation="Zero-width characters (e.g. U+200B) are frequently inserted between letters to evade keyword-based security filters while remaining invisible to the user.",
            recommended_action="Exercise caution; obfuscation techniques were detected in this message.",
            source_module="input_normalizer",
        ))

    if norm.homoglyph_count > 0:
        findings.append(Finding(
            category=FindingCategory.CONTENT,
            severity=FindingSeverity.HIGH,
            evidence=f"Detected {norm.homoglyph_count} look-alike homoglyph character(s)",
            explanation="Homoglyphs (such as Cyrillic 'а' replacing Latin 'a') are used to craft deceptive brand names and bypass spam filters.",
            recommended_action="Do not click links or trust sender display names.",
            source_module="input_normalizer",
        ))

    # 2. Deterministic Social Engineering & Brand Impersonation
    brand_res = analyze_brand_and_social_engineering(
        text=norm.normalised,
        sender=sender,
        extracted_urls=norm.extracted_urls,
    )
    findings.extend(brand_res.findings)
    highlights.extend(brand_res.highlights)

    # 3. Consolidated Gemini API Analysis
    gemini_res = analyze_with_gemini(
        content=norm.normalised,
        channel_type=channel_type,
        sender=sender,
        subject=subject,
        deterministic_findings=findings,
    )

    if gemini_res.available:
        findings.extend(gemini_res.findings)
        highlights.extend(gemini_res.highlights)
    else:
        if gemini_res.error:
            unavailable.append(f"AI Contextual Engine: {gemini_res.error}")

    # 4. Compute composite risk score
    # Start with deterministic signals
    deterministic_score = 0
    if norm.homoglyph_count > 0:
        deterministic_score += 35
    if norm.zero_width_count > 0:
        deterministic_score += 20
    deterministic_score += brand_res.risk_boost

    if gemini_res.available:
        # Fuse deterministic + LLM score (max + contextual blend)
        combined_score = max(gemini_res.risk_score, deterministic_score)
    else:
        # Fallback to deterministic scoring alone
        combined_score = min(100, deterministic_score)

    return TextThreatAnalysis(
        normalisation=norm,
        brand_analysis=brand_res,
        gemini_analysis=gemini_res,
        findings=findings,
        highlights=highlights,
        combined_risk_score=combined_score,
        unavailable_checks=unavailable,
    )
