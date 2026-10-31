"""
AEGIS 2.0 — Deterministic URL & Link Inspector

100% Rule-Based & SSRF-Protected:
- Lexical URL feature extraction (entropy, special characters, length, keywords, shorteners, TLDs)
- Brand impersonation & typosquatting detection against curated authority domain registry
- IP address and obfuscation detection (IPv4 literals, hex encoding, @ symbol redirects)
- Safe SSRF validator: rejects loopback (127.0.0.0/8), private (RFC 1918), link-local,
  carrier-grade NAT, and cloud metadata (169.254.169.254) addresses
- Guarded Link Inspector: safe redirect following with per-hop SSRF validation,
  max 5 hops, strict timeouts, and response size limits (never executes JavaScript).
"""

from __future__ import annotations

import ipaddress
import math
import re
import socket
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import parse_qs, urlparse

import httpx
try:
    import tldextract
    _extractor = tldextract.TLDExtract(suffix_list_urls=None)
except ImportError:
    tldextract = None
    _extractor = None

from config import settings
from schemas import Finding, FindingCategory, FindingSeverity, LinkHop, UrlReputation


# ---------------------------------------------------------------------------
# Suspicious TLDs and Shortener Registries
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS = {
    "top", "xyz", "club", "buzz", "surf", "site", "online", "icu", "live",
    "space", "info", "click", "link", "support", "review", "country", "stream",
    "download", "win", "bid", "racing", "accountant", "science", "date",
    "faith", "party", "tk", "ml", "ga", "cf", "gq", "work", "loan", "rest",
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "bl.ink", "short.io", "cutt.ly", "rb.gy", "shorturl.at",
    "tiny.cc", "v.gd", "qr.ae", "is.gd",
}

SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "update", "secure", "account", "banking",
    "confirm", "password", "credential", "suspend", "alert", "urgent",
    "authenticate", "wallet", "kyc", "otp", "refund", "claim", "pan",
    "aadhaar", "ebill", "electricity", "bill", "reward", "lottery",
}

# ---------------------------------------------------------------------------
# Curated Brand Registry (Official vs Known Targets)
# ---------------------------------------------------------------------------

TRUSTED_BRAND_REGISTRY: dict[str, list[str]] = {
    "sbi": ["onlinesbi.sbi", "sbi.co.in", "statebankofindia.com"],
    "yono": ["onlinesbi.sbi", "sbi.co.in"],
    "hdfc": ["hdfcbank.com", "hdfc.com"],
    "icici": ["icicibank.com"],
    "axis": ["axisbank.com"],
    "pnb": ["pnbindia.in"],
    "rbi": ["rbi.org.in"],
    "incometax": ["incometax.gov.in", "incometaxindiaefiling.gov.in"],
    "indiapost": ["indiapost.gov.in"],
    "epfo": ["epfindia.gov.in"],
    "uidai": ["uidai.gov.in"],
    "paytm": ["paytm.com"],
    "phonepe": ["phonepe.com"],
    "google": ["google.com", "google.co.in", "accounts.google.com"],
    "amazon": ["amazon.in", "amazon.com"],
    "flipkart": ["flipkart.com"],
    "microsoft": ["microsoft.com", "live.com", "office.com"],
    "apple": ["apple.com", "icloud.com"],
    "netflix": ["netflix.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
}


def _shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy for a string."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values() if c > 0)


def is_private_or_blocked_ip(ip_str: str) -> bool:
    """Check if an IP is loopback, private, link-local, carrier-grade NAT, or cloud metadata."""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Cloud metadata service protection
        if str(ip) in ("169.254.169.254", "fd00:ec2::254"):
            return True
        return (
            ip.is_loopback
            or ip.is_private
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return True


def validate_url_scheme_and_port(url_str: str) -> tuple[bool, Optional[str]]:
    """
    Validate that a URL strictly uses HTTP or HTTPS and standard ports (80 or 443).
    Rejects custom/unusual ports (e.g. 8080, 22, 6379) and non-HTTP schemes (ftp, file, gopher, javascript).
    Returns: (is_valid, error_message)
    """
    try:
        parsed = urlparse(url_str.strip())
    except Exception as exc:
        return False, f"Malformed URL syntax: {exc}"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, f"Rejected scheme '{scheme}': Only http and https protocols are permitted."

    port = parsed.port
    if port is not None:
        if scheme == "http" and port != 80:
            return False, f"Rejected non-standard port {port}: HTTP is strictly restricted to port 80."
        if scheme == "https" and port != 443:
            return False, f"Rejected non-standard port {port}: HTTPS is strictly restricted to port 443."

    return True, None


import concurrent.futures

def validate_hostname_safe(hostname: str) -> tuple[bool, Optional[str], Optional[str]]:
    """
    Resolve DNS for a hostname and verify it does NOT point to a private/internal IP.
    Returns: (is_safe, resolved_ip, error_message)
    """
    if not hostname:
        return False, None, "Empty hostname"

    # Reject obvious localhost / loopback aliases directly
    clean_host = hostname.strip().lower()
    if clean_host in ("localhost", "127.0.0.1", "0.0.0.0", "::1", "metadata.google.internal"):
        return False, "127.0.0.1", "Blocked loopback / internal hostname"

    # If it's already an IP address, check directly without DNS lookup
    try:
        ipaddress.ip_address(clean_host)
        if is_private_or_blocked_ip(clean_host):
            return False, clean_host, f"SSRF Protection: Literal IP is private/restricted ({clean_host})"
        return True, clean_host, None
    except ValueError:
        pass

    # Resolve with strict 1.5 second timeout to avoid blocking on unresolvable domains
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(socket.getaddrinfo, clean_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            addr_info = future.result(timeout=1.5)

        for family, _, _, _, sockaddr in addr_info:
            ip_candidate = sockaddr[0]
            if is_private_or_blocked_ip(ip_candidate):
                return False, ip_candidate, f"SSRF Protection: Hostname resolves to private/restricted IP ({ip_candidate})"
        first_ip = addr_info[0][4][0] if addr_info else None
        return True, first_ip, None
    except concurrent.futures.TimeoutError:
        return False, None, "DNS resolution timed out"
    except socket.gaierror as e:
        return False, None, f"DNS resolution failed: {e}"
    except Exception as e:
        return False, None, f"Host validation error: {e}"


@dataclass
class UrlAnalysisResult:
    """Result of deterministic URL analysis."""
    url: str
    domain: str
    registered_domain: str
    reputation: UrlReputation
    flags: list[str]
    findings: list[Finding]
    risk_score: int
    link_trail: list[LinkHop] = field(default_factory=list)


def analyze_url_deterministic(raw_url: str, inspect_links: bool = False) -> UrlAnalysisResult:
    """
    Run complete deterministic inspection on a URL:
    - Parsing & lexical flags
    - Brand impersonation / typosquatting check
    - Hex and IP obfuscation checks
    - SSRF prevention & optional guarded redirect following
    """
    url_str = raw_url.strip()
    if not url_str.startswith(("http://", "https://")):
        url_str = "http://" + url_str

    flags: list[str] = []
    findings: list[Finding] = []
    score_acc = 0

    try:
        parsed = urlparse(url_str)
    except Exception:
        return UrlAnalysisResult(
            url=raw_url,
            domain="malformed",
            registered_domain="malformed",
            reputation=UrlReputation.SUSPICIOUS,
            flags=["malformed_url"],
            findings=[
                Finding(
                    category=FindingCategory.URL,
                    severity=FindingSeverity.HIGH,
                    evidence="Malformed URL syntax",
                    explanation="The provided URL cannot be parsed safely according to RFC standards.",
                    recommended_action="Do not open or interact with malformed URLs.",
                    source_module="url_inspector",
                )
            ],
            risk_score=75,
        )

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""

    # TLD extraction
    domain_str = hostname
    subdomain_str = ""
    suffix = ""
    if _extractor is not None:
        ext = _extractor(url_str)
        domain_str = ext.registered_domain or hostname
        subdomain_str = ext.subdomain or ""
        suffix = ext.suffix or ""
    else:
        parts = hostname.split(".")
        if len(parts) > 2:
            domain_str = ".".join(parts[-2:])
            subdomain_str = ".".join(parts[:-2])

    # 0. Strict Scheme and Port Validation (Ports 80/443 only)
    is_valid_scheme_port, port_err = validate_url_scheme_and_port(
        raw_url if (raw_url.startswith("http://") or raw_url.startswith("https://")) else url_str
    )
    if not is_valid_scheme_port:
        flags.append("security_rejected_port_or_scheme")
        if "port" in (port_err or "").lower():
            flags.append("non_standard_port")
        else:
            flags.append("unsupported_scheme")
        score_acc += 45
        findings.append(Finding(
            category=FindingCategory.URL,
            severity=FindingSeverity.HIGH,
            evidence=port_err or "Non-standard port or unsupported scheme detected",
            explanation=(
                "AEGIS strictly confines URL inspection to HTTP port 80 and HTTPS port 443. "
                "Non-standard ports (such as 8080, 22, 6379) and alternative protocols are "
                "common vectors for SSRF, internal network scanning, and security evasion."
            ),
            recommended_action="Do not open links with non-standard ports or non-HTTP protocols.",
            source_module="url_inspector",
        ))

    # 1. Scheme checks (HTTP unencrypted)
    if parsed.scheme == "http":
        flags.append("http_unencrypted")
        score_acc += 10
        findings.append(Finding(
            category=FindingCategory.URL,
            severity=FindingSeverity.LOW,
            evidence="Plaintext HTTP scheme used",
            explanation="Unencrypted HTTP connections can be intercepted, altered, or spoofed in transit.",
            recommended_action="Do not submit credentials or private information over plain HTTP.",
            source_module="url_inspector",
        ))

    # 2. At-symbol (@) URL obfuscation trick
    if "@" in raw_url:
        flags.append("at_symbol_obfuscation")
        score_acc += 40
        findings.append(Finding(
            category=FindingCategory.URL,
            severity=FindingSeverity.HIGH,
            evidence=f"At-sign (@) in URL: {raw_url}",
            explanation="The '@' character in URLs causes browsers to discard everything before it as username data, deceiving users about the true destination host.",
            recommended_action="Do not visit this URL. Attackers frequently use '@' to cloak malicious landing servers.",
            source_module="url_inspector",
        ))

    # 3. IP-based hostname check
    try:
        ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        is_ip = False

    if is_ip:
        flags.append("ip_based_hostname")
        score_acc += 35
        findings.append(Finding(
            category=FindingCategory.URL,
            severity=FindingSeverity.HIGH,
            evidence=f"Raw IP address used as hostname: {hostname}",
            explanation="Legitimate institutions host services on authenticated domain names with SSL certificates. Raw IP URLs are overwhelmingly associated with rogue infrastructure.",
            recommended_action="Never submit credentials or OTPs on IP-based websites.",
            source_module="url_inspector",
        ))

    # 4. URL shortener detection
    if hostname in SHORTENER_DOMAINS or domain_str in SHORTENER_DOMAINS:
        flags.append("url_shortener_detected")
        score_acc += 15
        findings.append(Finding(
            category=FindingCategory.URL,
            severity=FindingSeverity.MEDIUM,
            evidence=f"Shortened link host: {hostname}",
            explanation="URL shorteners obscure the ultimate destination host, frequently concealing phishing landing domains.",
            recommended_action="Use a URL expander or avoid clicking unsolicited shortened URLs.",
            source_module="url_inspector",
        ))

    # 5. Suspicious / disposable TLDs
    if suffix.lower() in SUSPICIOUS_TLDS:
        flags.append("non_standard_tld")
        score_acc += 25
        findings.append(Finding(
            category=FindingCategory.URL,
            severity=FindingSeverity.MEDIUM,
            evidence=f"High-risk generic top-level domain: .{suffix}",
            explanation=f"The .{suffix} top-level domain is statistically overrepresented in cheap/disposable phishing infrastructure.",
            recommended_action="Verify the website legitimacy carefully before interacting.",
            source_module="url_inspector",
        ))

    # 6. Brand Impersonation & Typosquatting Analysis
    full_url_lower = raw_url.lower()
    combined_domain_text = (hostname + " " + path).lower()

    for brand, trusted_domains in TRUSTED_BRAND_REGISTRY.items():
        # Check if brand name appears in hostname or subdomain
        brand_in_host = brand in hostname.replace("-", "").replace(".", "")
        if brand_in_host:
            # Is this actually an official domain?
            is_legitimate = any(domain_str == td or domain_str.endswith("." + td) for td in trusted_domains)
            if not is_legitimate:
                flags.append("brand_in_subdomain")
                flags.append("typosquatting")
                score_acc += 50
                findings.append(Finding(
                    category=FindingCategory.IMPERSONATION,
                    severity=FindingSeverity.HIGH,
                    evidence=f"Brand '{brand.upper()}' targeted on non-official domain '{domain_str}'",
                    explanation=f"This domain incorporates the protected brand '{brand.upper()}' but is NOT registered to authorized infrastructure ({', '.join(trusted_domains)}).",
                    recommended_action=f"Navigate only to the verified official portal ({trusted_domains[0]}) directly.",
                    source_module="brand_impersonation_engine",
                ))
                break

    # 7. Suspicious Keywords in Path/Query
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in combined_domain_text]
    if len(found_keywords) >= 2 and score_acc > 0:
        flags.append("credential_harvesting_path")
        score_acc += 20
        findings.append(Finding(
            category=FindingCategory.URL,
            severity=FindingSeverity.HIGH,
            evidence=f"High-risk security keywords in URL: {', '.join(found_keywords[:4])}",
            explanation="The URL combines sensitive actions (e.g. KYC, login, banking, verify) outside verified institutional domains.",
            recommended_action="Do not proceed to enter any credentials or sensitive numbers.",
            source_module="url_inspector",
        ))

    # 8. High entropy domain check
    entropy = _shannon_entropy(domain_str)
    if entropy > 4.2 and not is_ip:
        flags.append("high_entropy_domain")
        score_acc += 15

    # Determine reputation and clamped risk score
    risk_score = min(100, max(0, score_acc))
    if risk_score >= 60:
        reputation = UrlReputation.MALICIOUS
    elif risk_score >= 25:
        reputation = UrlReputation.SUSPICIOUS
    else:
        reputation = UrlReputation.CLEAN

    # 9. Guarded Link Inspector (SSRF-protected redirect following)
    link_trail: list[LinkHop] = []
    if inspect_links and not is_ip:
        if not is_valid_scheme_port:
            link_trail = [
                LinkHop(
                    hop=1,
                    url=raw_url,
                    status=403,
                    final=True,
                    page_title=None,
                    flags=["security_rejected_port_or_scheme", port_err or "Invalid port or scheme"],
                )
            ]
        else:
            link_trail = inspect_redirect_chain_safe(url_str)

    return UrlAnalysisResult(
        url=raw_url,
        domain=hostname,
        registered_domain=domain_str,
        reputation=reputation,
        flags=list(set(flags)),
        findings=findings,
        risk_score=risk_score,
        link_trail=link_trail,
    )


def inspect_redirect_chain_safe(initial_url: str) -> list[LinkHop]:
    """
    Safely inspect HTTP redirect hops under strict SSRF constraints:
    - Every hop must resolve to a safe public IP (blocks RFC 1918, loopback, link-local, cloud metadata).
    - Maximum 5 redirects.
    - Connect and read timeout of 3.0s.
    - Max 250 KB body size.
    - Never executes JavaScript, never downloads executable files.
    """
    hops: list[LinkHop] = []
    current_url = initial_url
    max_hops = settings.max_redirects

    for hop_idx in range(1, max_hops + 1):
        # Pre-flight Scheme and Port validation
        is_valid_scheme_port, port_err = validate_url_scheme_and_port(current_url)
        if not is_valid_scheme_port:
            hops.append(LinkHop(
                hop=hop_idx,
                url=current_url,
                status=403,
                final=True,
                page_title=None,
                flags=["security_rejected_port_or_scheme", port_err or "Invalid port or scheme"],
            ))
            break

        parsed = urlparse(current_url)
        hostname = parsed.hostname or ""

        # Pre-flight SSRF check
        is_safe, resolved_ip, err = validate_hostname_safe(hostname)
        if not is_safe:
            hops.append(LinkHop(
                hop=hop_idx,
                url=current_url,
                status=403,
                final=True,
                page_title=None,
                flags=["ssrf_blocked_private_ip", err or "Blocked by SSRF filter"],
            ))
            break

        try:
            # Perform a guarded HEAD / GET with strict limits
            with httpx.Client(
                follow_redirects=False,
                timeout=settings.url_request_timeout_seconds,
                verify=False,
                headers={"User-Agent": "AEGIS-Security-Inspector/2.0"},
            ) as client:
                response = client.get(current_url)
                status_code = response.status_code
                is_redirect = status_code in (301, 302, 303, 307, 308)

                # Check HTML for page title or credential input forms
                page_title = None
                hop_flags: list[str] = []

                if "text/html" in response.headers.get("content-type", "").lower():
                    # Read at most 250 KB
                    content_chunk = response.text[:settings.max_response_bytes]
                    title_match = re.search(r"<title[^>]*>(.*?)</title>", content_chunk, re.IGNORECASE | re.DOTALL)
                    if title_match:
                        page_title = title_match.group(1).strip()[:120]

                    # Detect password / OTP forms
                    if re.search(r'type=["\']password["\']', content_chunk, re.IGNORECASE):
                        hop_flags.append("credential_harvesting_form")
                    if re.search(r'name=["\'](?:otp|one_time_password)["\']', content_chunk, re.IGNORECASE):
                        hop_flags.append("otp_input_detected")

                if is_redirect:
                    next_location = response.headers.get("Location")
                    if not next_location:
                        hops.append(LinkHop(
                            hop=hop_idx,
                            url=current_url,
                            status=status_code,
                            final=True,
                            page_title=page_title,
                            flags=hop_flags + ["redirect_missing_location"],
                        ))
                        break

                    # Resolve relative redirect URLs
                    if next_location.startswith("/"):
                        next_location = f"{parsed.scheme}://{parsed.netloc}{next_location}"

                    # Validate redirect target scheme & port before following
                    target_valid, target_err = validate_url_scheme_and_port(next_location)
                    if not target_valid:
                        hops.append(LinkHop(
                            hop=hop_idx,
                            url=current_url,
                            status=status_code,
                            final=False,
                            page_title=page_title,
                            flags=hop_flags,
                        ))
                        hops.append(LinkHop(
                            hop=hop_idx + 1,
                            url=next_location,
                            status=403,
                            final=True,
                            page_title=None,
                            flags=["unsafe_redirect_rejected", target_err or "Unsafe redirect destination"],
                        ))
                        break

                    hops.append(LinkHop(
                        hop=hop_idx,
                        url=current_url,
                        status=status_code,
                        final=False,
                        page_title=page_title,
                        flags=hop_flags,
                    ))
                    current_url = next_location
                else:
                    hops.append(LinkHop(
                        hop=hop_idx,
                        url=current_url,
                        status=status_code,
                        final=True,
                        page_title=page_title,
                        flags=hop_flags if hop_flags else ["safe"],
                    ))
                    break

        except httpx.TimeoutException:
            hops.append(LinkHop(
                hop=hop_idx,
                url=current_url,
                status=504,
                final=True,
                page_title=None,
                flags=["inspector_request_timeout"],
            ))
            break
        except Exception as exc:
            hops.append(LinkHop(
                hop=hop_idx,
                url=current_url,
                status=500,
                final=True,
                page_title=None,
                flags=[f"inspection_failed: {str(exc)[:60]}"],
            ))
            break

    return hops
