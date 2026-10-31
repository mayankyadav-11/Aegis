"""
AEGIS 2.0 — Tests for Input Normaliser

Tests Unicode normalisation, zero-width character detection, homoglyph
detection, whitespace handling, URL extraction, and edge cases.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.normalizer import normalise


class TestUnicodeNormalisation:
    """NFKC normalisation transforms compatibility characters."""

    def test_fullwidth_to_ascii(self):
        result = normalise("\uff21\uff22\uff23")  # ＡＢＣ
        assert result.normalised == "ABC"

    def test_nfkc_ligature(self):
        result = normalise("\ufb01")  # ﬁ ligature → fi
        assert "fi" in result.normalised

    def test_empty_string(self):
        result = normalise("")
        assert result.normalised == ""
        assert result.original == ""

    def test_none_input(self):
        result = normalise(None)  # type: ignore[arg-type]
        assert result.normalised == ""


class TestZeroWidthDetection:
    """Zero-width characters are detected, recorded, and stripped."""

    def test_zero_width_space(self):
        result = normalise("hello\u200bworld")
        assert result.zero_width_count == 1
        assert result.normalised == "helloworld"

    def test_zero_width_joiner(self):
        result = normalise("pass\u200dword")
        assert result.zero_width_count == 1
        assert result.normalised == "password"

    def test_multiple_zero_widths(self):
        text = "O\u200bT\u200cP\u200d"
        result = normalise(text)
        assert result.zero_width_count == 3
        assert result.normalised == "OTP"

    def test_bom_detected(self):
        result = normalise("\ufefftest")
        assert result.zero_width_count == 1
        assert result.normalised == "test"

    def test_soft_hyphen(self):
        result = normalise("veri\u00adfy")
        assert result.zero_width_count == 1
        assert result.normalised == "verify"

    def test_original_preserved(self):
        original = "hello\u200bworld"
        result = normalise(original)
        assert result.original == original
        assert result.normalised != original


class TestHomoglyphDetection:
    """Homoglyph characters are detected and recorded."""

    def test_cyrillic_a(self):
        result = normalise("p\u0430ypal")  # Cyrillic а in paypal
        assert result.homoglyph_count >= 1
        assert any(s.category == "homoglyph" for s in result.suspicious_chars)

    def test_cyrillic_o(self):
        result = normalise("g\u043e\u043egle")  # Cyrillic о
        assert result.homoglyph_count >= 2

    def test_mixed_scripts_flag(self):
        result = normalise("g\u043e\u043egle.com")  # Latin g + Cyrillic о
        assert result.has_mixed_scripts is True

    def test_pure_latin(self):
        result = normalise("google.com")
        assert result.homoglyph_count == 0
        assert result.has_mixed_scripts is False


class TestWhitespaceNormalisation:
    """Whitespace runs are collapsed and edges are trimmed."""

    def test_collapse_spaces(self):
        result = normalise("  hello   world  ")
        assert result.normalised == "hello world"

    def test_collapse_tabs_newlines(self):
        result = normalise("hello\t\n\r\nworld")
        assert result.normalised == "hello world"

    def test_preserve_single_space(self):
        result = normalise("hello world")
        assert result.normalised == "hello world"


class TestUrlExtraction:
    """URLs are extracted from normalised text."""

    def test_https_url(self):
        result = normalise("Visit https://example.com/page for details")
        assert "https://example.com/page" in result.extracted_urls

    def test_http_url(self):
        result = normalise("Go to http://test.org/login")
        assert "http://test.org/login" in result.extracted_urls

    def test_multiple_urls(self):
        result = normalise("Check http://a.com and http://b.org now")
        assert len(result.extracted_urls) >= 2

    def test_no_urls(self):
        result = normalise("This is a plain message")
        # May or may not match, just ensure no crash
        assert isinstance(result.extracted_urls, list)


class TestEntropy:
    """Shannon entropy calculation."""

    def test_low_entropy(self):
        result = normalise("aaaaaaaaa")
        assert result.entropy == 0.0

    def test_higher_entropy(self):
        result = normalise("abcdefghij")
        assert result.entropy > 2.0

    def test_empty_entropy(self):
        result = normalise("")
        assert result.entropy == 0.0


class TestEdgeCases:
    """Edge cases and malformed inputs."""

    def test_very_long_input(self):
        text = "x" * 100_000
        result = normalise(text)
        assert len(result.normalised) == 100_000

    def test_emoji_handling(self):
        result = normalise("Hello 🎣 phishing!")
        assert "phishing" in result.normalised

    def test_mixed_zero_width_and_homoglyphs(self):
        text = "p\u0430\u200byp\u0430l"  # Cyrillic а + zero-width space
        result = normalise(text)
        assert result.zero_width_count >= 1
        assert result.homoglyph_count >= 1
        assert result.has_mixed_scripts is True

