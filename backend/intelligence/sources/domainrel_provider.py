"""
AEGIS 2.0 — DomainRel Credibility Provider

Provides an offline credibility score (0.0–1.0) for domains based on a
snapshot of the DomainRel dataset (CC-BY 4.0, credi-net/DomainRel project,
Mila / Oxford / McGill).

IMPORTANT CONSTRAINTS:
  - Low DomainRel score NEVER independently triggers a MALICIOUS verdict.
  - High DomainRel score NEVER whitelists a domain or bypasses URL checks.
  - A missing record is treated as UNKNOWN — NOT SAFE.
  - DomainRel measures journalistic/misinformation credibility, NOT phishing
    infrastructure.  A news commentary site may have a low score without being
    a credential harvester.
  - This module returns an informational signal only.  The calling code must
    not treat the credibility score as a risk score.

Dataset: backend/intelligence/datasets/legitimate_domains/domainrel_snapshot.jsonl
License: CC-BY 4.0  (https://creativecommons.org/licenses/by/4.0/)
Source:  https://huggingface.co/datasets/credi-net/DomainRel
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Optional


_SNAPSHOT_PATH = Path(__file__).parent.parent / "datasets" / "legitimate_domains" / "domainrel_snapshot.jsonl"


class DomainRelProvider:
    """
    Offline credibility lookup backed by a bundled JSONL snapshot.

    The snapshot is loaded once on first use (lazy initialisation).
    """

    def __init__(self, snapshot_path: Path = _SNAPSHOT_PATH) -> None:
        self._path = snapshot_path
        self._index: Optional[dict[str, float]] = None

    def _load(self) -> None:
        """Lazily load the JSONL snapshot into an in-memory dict."""
        self._index = {}
        if not self._path.exists():
            return
        with open(self._path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                    domain = record.get("domain", "").lower().strip()
                    label = record.get("label")
                    if domain and label is not None:
                        self._index[domain] = float(label)
                except (json.JSONDecodeError, ValueError, TypeError):
                    continue

    def get_credibility_score(self, domain: str) -> Optional[float]:
        """
        Return the DomainRel credibility score for a domain (0.0–1.0), or None.

        A score of 1.0 indicates the highest journalistic credibility in the
        source dataset.  A score of 0.0 indicates low journalistic credibility.

        Missing record returns None — treat as UNKNOWN, not SAFE.

        This score must NOT be directly converted to a phishing risk score.
        """
        if self._index is None:
            self._load()
        domain = domain.lower().strip()
        # Try exact match first, then strip 'www.' prefix
        score = self._index.get(domain)
        if score is None and domain.startswith("www."):
            score = self._index.get(domain[4:])
        return score

    def __len__(self) -> int:
        if self._index is None:
            self._load()
        return len(self._index)


# Module-level singleton
domainrel_provider = DomainRelProvider()

