"""
Threat feed loader for AEGIS intelligence service.

Target feeds (with offline fallback):
  - OpenPhish Community Feed: https://openphish.com/feed.txt
    License: Free for defensive/research use with attribution
    Attribution: OpenPhish (https://openphish.com)
  - URLhaus (Abuse.ch): https://urlhaus.abuse.ch/downloads/text_recent/
    License: CC0 — https://creativecommons.org/publicdomain/zero/1.0/

IMPORTANT:
  - Feed fetching must never crash the analysis pipeline.
  - Raw malicious URLs are NOT followed during ingestion.
  - Domains are extracted from URLs (path stripped) for storage.
  - Records older than TTL_DAYS are marked STALE, not deleted.
  - Historical malicious records do NOT automatically override verified entries,
    but STALE records reduce confidence and are noted in evidence.
  - Active KNOWN_MALICIOUS records CANNOT be overridden by any allowlist.
"""

import sqlite3
import re
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass

DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "threat_intel.db"
SEED_FILE = Path(__file__).resolve().parent.parent / "datasets" / "malicious_domains" / "known_phishing_domains.jsonl"
TTL_DAYS = 30


@dataclass
class ThreatRecord:
    domain: str
    url_sample: str
    source: str
    first_seen: str
    last_seen: str
    is_active: bool
    is_stale: bool
    confidence: float
    notes: str


def _init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS malicious_domains (
            domain TEXT PRIMARY KEY,
            url_sample TEXT,
            source TEXT,
            first_seen TEXT,
            last_seen TEXT,
            is_active INTEGER DEFAULT 1,
            confidence REAL DEFAULT 0.8,
            notes TEXT DEFAULT ''
        )
    """)
    conn.commit()

    # Pre-seed from local dataset if table is empty
    count = conn.execute("SELECT COUNT(*) FROM malicious_domains").fetchone()[0]
    if count == 0 and SEED_FILE.exists():
        now = datetime.now(timezone.utc).isoformat()
        with open(SEED_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entry = json.loads(line)
                        dom = entry.get("domain", "").lower().strip()
                        if dom:
                            conn.execute("""
                                INSERT OR IGNORE INTO malicious_domains 
                                (domain, url_sample, source, first_seen, last_seen, is_active, confidence, notes)
                                VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                            """, (
                                dom,
                                f"https://{dom}/",
                                entry.get("source", "seed_dataset"),
                                now,
                                now,
                                float(entry.get("confidence", 0.9)),
                                entry.get("notes", "Seed malicious domain"),
                            ))
                    except Exception:
                        pass
        conn.commit()

    conn.close()


def _extract_domain(url: str) -> Optional[str]:
    """Extract registered domain from URL without following the URL."""
    try:
        url = url.strip()
        if "://" in url:
            url = url.split("://", 1)[1]
        domain = url.split("/")[0].split("?")[0].split("#")[0]
        domain = domain.split(":")[0]  # Remove port
        domain = domain.lower().strip()
        if domain and re.match(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$', domain) and '.' in domain:
            return domain
    except Exception:
        pass
    return None


def lookup_domain(domain: str) -> Optional[ThreatRecord]:
    """Look up a domain in the local threat intel database."""
    try:
        _init_db()
        conn = sqlite3.connect(str(DB_PATH))
        row = conn.execute(
            "SELECT domain, url_sample, source, first_seen, last_seen, is_active, confidence, notes FROM malicious_domains WHERE domain = ?",
            (domain.lower().strip(),)
        ).fetchone()
        conn.close()

        if row is None:
            return None

        domain_val, url_sample, source, first_seen, last_seen, is_active, confidence, notes = row

        # Check TTL
        is_stale = False
        try:
            last_seen_dt = datetime.fromisoformat(last_seen)
            if last_seen_dt.tzinfo is None:
                last_seen_dt = last_seen_dt.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - last_seen_dt).days
            is_stale = age_days > TTL_DAYS
        except Exception:
            is_stale = True

        return ThreatRecord(
            domain=domain_val,
            url_sample=url_sample or "",
            source=source or "",
            first_seen=first_seen or "",
            last_seen=last_seen or "",
            is_active=bool(is_active),
            is_stale=is_stale,
            confidence=float(confidence or 0.8),
            notes=notes or "",
        )
    except Exception:
        return None


def ingest_feed_line(url: str, source: str, conn: sqlite3.Connection) -> bool:
    """Ingest a single URL from a threat feed into database. Returns True if ingested."""
    domain = _extract_domain(url)
    if not domain:
        return False

    now = datetime.now(timezone.utc).isoformat()
    conn.execute("""
        INSERT INTO malicious_domains (domain, url_sample, source, first_seen, last_seen, is_active, confidence, notes)
        VALUES (?, ?, ?, ?, ?, 1, 0.8, 'From threat feed')
        ON CONFLICT(domain) DO UPDATE SET
            last_seen = excluded.last_seen,
            is_active = 1,
            source = CASE WHEN source LIKE '%' || excluded.source || '%' THEN source ELSE source || ', ' || excluded.source END
    """, (domain, url[:200], source, now, now))
    return True


async def refresh_feeds_async():
    """
    Asynchronously refresh threat feeds from OpenPhish and URLhaus.

    This function must not block or crash the analysis pipeline.
    Feed download failures are silently caught.
    """
    try:
        import httpx
    except ImportError:
        return

    try:
        _init_db()
    except Exception:
        return

    feeds = [
        ("https://openphish.com/feed.txt", "openphish"),
        ("https://urlhaus.abuse.ch/downloads/text_recent/", "urlhaus"),
    ]

    for feed_url, source_name in feeds:
        try:
            async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
                response = await client.get(feed_url)
                if response.status_code == 200:
                    conn = sqlite3.connect(str(DB_PATH))
                    for line in response.text.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            ingest_feed_line(line, source_name, conn)
                    conn.commit()
                    conn.close()
        except Exception:
            pass

