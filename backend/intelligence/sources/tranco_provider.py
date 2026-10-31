"""
Tranco domain rank provider.

Source: https://tranco-list.eu/ (Le Pochat et al. 2019)
License: CC-BY 4.0 — https://creativecommons.org/licenses/by/4.0/

IMPORTANT: Tranco rank indicates domain popularity, NOT legitimacy.
A high Tranco rank alone does NOT grant VERIFIED_LEGITIMATE status.
"""

from pathlib import Path
from typing import Optional

TRANCO_FILE = Path(__file__).resolve().parent.parent / "datasets" / "legitimate_domains" / "tranco_top25k.txt"


class TrancoProvider:
    def __init__(self):
        self._ranks: dict[str, int] = {}
        self._load()

    def _load(self):
        if not TRANCO_FILE.exists():
            return
        with open(TRANCO_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",", 1)
                if len(parts) == 2:
                    try:
                        rank = int(parts[0])
                        domain = parts[1].lower().strip()
                        self._ranks[domain] = rank
                    except ValueError:
                        pass

    def get_rank(self, domain: str) -> Optional[int]:
        """Return Tranco rank for domain, or None if not in top list.

        NOTE: Rank alone does NOT indicate legitimacy.
        """
        return self._ranks.get(domain.lower())

    def is_in_top_list(self, domain: str) -> bool:
        return domain.lower() in self._ranks


tranco_provider = TrancoProvider()

