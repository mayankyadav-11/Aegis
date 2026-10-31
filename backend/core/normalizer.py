"""
AEGIS 2.0 Backend — Input Normalisation

Handles Unicode normalisation, zero-width character detection, homoglyph
detection, whitespace normalisation, URL extraction, and safe handling
of malformed inputs.

The normaliser preserves the original submitted content separately
from its normalised representation so that evidence and highlights
reference the original byte offsets.
"""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Homoglyph mapping (Cyrillic & other common look-alikes → Latin)
# ---------------------------------------------------------------------------

HOMOGLYPH_MAP: dict[str, str] = {
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Ukrainian і
    "\u0458": "j",  # Cyrillic ј
    "\u04bb": "h",  # Cyrillic һ
    "\u0501": "d",  # Cyrillic ԁ
    "\u051b": "q",  # Cyrillic ԛ
    "\u0261": "g",  # Latin ɡ
    "\u1d00": "a",  # Latin small cap A
    "\u1d04": "c",  # Latin small cap C
    "\u1d07": "e",  # Latin small cap E
    "\u0222": "8",  # Ȣ (looks like 8)
    "\uff10": "0",  # Fullwidth 0
    "\uff11": "1",  # Fullwidth 1
    "\uff12": "2",  # Fullwidth 2
    "\uff13": "3",  # Fullwidth 3
    "\uff14": "4",  # Fullwidth 4
    "\uff15": "5",  # Fullwidth 5
    "\uff16": "6",  # Fullwidth 6
    "\uff17": "7",  # Fullwidth 7
    "\uff18": "8",  # Fullwidth 8
    "\uff19": "9",  # Fullwidth 9
}

# Zero-width and invisible characters
ZERO_WIDTH_CHARS = {
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\u200e",  # Left-to-right mark
    "\u200f",  # Right-to-left mark
    "\u2060",  # Word joiner
    "\u2061",  # Function application
    "\u2062",  # Invisible times
    "\u2063",  # Invisible separator
    "\u2064",  # Invisible plus
    "\ufeff",  # BOM / zero-width no-break space
    "\u00ad",  # Soft hyphen
    "\u034f",  # Combining grapheme joiner
    "\u061c",  # Arabic letter mark
    "\u180e",  # Mongolian vowel separator
}

# URL extraction regex (broad match)
_URL_RE = re.compile(
    r"https?://[^\s<>\"')\]]+|"         # Standard http/https URLs
    r"(?<!\w)[a-zA-Z0-9]"               # Domain-like strings
    r"(?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z]{2,}){1,3}"
    r"(?:/[^\s<>\"')\]]*)?",
    re.IGNORECASE,
)


@dataclass
class SuspiciousCharInfo:
    """Information about a suspicious character found in the input."""
    char: str
    position: int
    unicode_name: str
    category: str  # 'zero_width', 'homoglyph', 'control', 'bidi'
    latin_equivalent: Optional[str] = None


@dataclass
class NormalisationResult:
    """Result of the normalisation pipeline."""
    original: str
    normalised: str
    extracted_urls: list[str] = field(default_factory=list)
    suspicious_chars: list[SuspiciousCharInfo] = field(default_factory=list)
    zero_width_count: int = 0
    homoglyph_count: int = 0
    has_mixed_scripts: bool = False
    entropy: float = 0.0


def _char_entropy(text: str) -> float:
    """Calculate Shannon entropy of the character distribution."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum(
        (c / length) * math.log2(c / length) for c in freq.values() if c > 0
    )


def _detect_mixed_scripts(text: str) -> bool:
    """Detect if text contains mixed Unicode scripts (e.g. Latin + Cyrillic)."""
    scripts: set[str] = set()
    for ch in text:
        cat = unicodedata.category(ch)
        if cat.startswith("L"):  # Letter categories
            # Simple heuristic using Unicode block ranges
            cp = ord(ch)
            if 0x0400 <= cp <= 0x04FF:
                scripts.add("CYRILLIC")
            elif 0x0041 <= cp <= 0x024F:
                scripts.add("LATIN")
            elif 0x0900 <= cp <= 0x097F:
                scripts.add("DEVANAGARI")
            elif 0x0600 <= cp <= 0x06FF:
                scripts.add("ARABIC")
    # Mixed if more than one letter script is present
    return len(scripts) > 1


def normalise(text: str) -> NormalisationResult:
    """
    Run the full normalisation pipeline on input text.

    Steps:
    1. Record original text.
    2. Unicode NFKC normalisation.
    3. Detect and record zero-width characters.
    4. Detect and record homoglyphs.
    5. Strip zero-width characters for the normalised output.
    6. Normalise whitespace (collapse runs, strip).
    7. Extract URLs.
    8. Calculate entropy.
    9. Detect mixed scripts.

    Returns a NormalisationResult with both original and normalised
    text, plus all detected suspicious artefacts.
    """
    if not isinstance(text, str):
        text = str(text) if text is not None else ""

    original = text
    suspicious: list[SuspiciousCharInfo] = []
    zw_count = 0
    hg_count = 0

    # --- 1. NFKC normalisation ---
    nfkc = unicodedata.normalize("NFKC", text)

    # --- 2. Detect zero-width characters (scan NFKC output) ---
    for i, ch in enumerate(nfkc):
        if ch in ZERO_WIDTH_CHARS:
            zw_count += 1
            try:
                name = unicodedata.name(ch, f"U+{ord(ch):04X}")
            except ValueError:
                name = f"U+{ord(ch):04X}"
            suspicious.append(
                SuspiciousCharInfo(
                    char=repr(ch),
                    position=i,
                    unicode_name=name,
                    category="zero_width",
                )
            )

    # --- 3. Detect homoglyphs ---
    for i, ch in enumerate(nfkc):
        if ch in HOMOGLYPH_MAP:
            hg_count += 1
            try:
                name = unicodedata.name(ch, f"U+{ord(ch):04X}")
            except ValueError:
                name = f"U+{ord(ch):04X}"
            suspicious.append(
                SuspiciousCharInfo(
                    char=ch,
                    position=i,
                    unicode_name=name,
                    category="homoglyph",
                    latin_equivalent=HOMOGLYPH_MAP[ch],
                )
            )

    # --- 4. Detect control characters (excluding common whitespace) ---
    for i, ch in enumerate(nfkc):
        cat = unicodedata.category(ch)
        if cat.startswith("C") and ch not in ("\n", "\r", "\t") and ch not in ZERO_WIDTH_CHARS:
            try:
                name = unicodedata.name(ch, f"U+{ord(ch):04X}")
            except ValueError:
                name = f"U+{ord(ch):04X}"
            suspicious.append(
                SuspiciousCharInfo(
                    char=repr(ch),
                    position=i,
                    unicode_name=name,
                    category="control",
                )
            )

    # --- 5. Strip zero-width characters for normalised text ---
    cleaned = "".join(ch for ch in nfkc if ch not in ZERO_WIDTH_CHARS)

    # --- 6. Whitespace normalisation ---
    normalised = re.sub(r"\s+", " ", cleaned).strip()

    # --- 7. URL extraction ---
    urls = _URL_RE.findall(normalised)
    # Deduplicate while preserving order
    seen: set[str] = set()
    unique_urls: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            unique_urls.append(u)

    # --- 8. Entropy ---
    entropy = _char_entropy(normalised)

    # --- 9. Mixed script detection ---
    mixed = _detect_mixed_scripts(normalised)

    return NormalisationResult(
        original=original,
        normalised=normalised,
        extracted_urls=unique_urls,
        suspicious_chars=suspicious,
        zero_width_count=zw_count,
        homoglyph_count=hg_count,
        has_mixed_scripts=mixed,
        entropy=entropy,
    )

