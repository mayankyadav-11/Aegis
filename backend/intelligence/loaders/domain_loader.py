"""
Domain registry loader — loads brands.json and official_domains.json at import time.

Sources:
  - backend/intelligence/registry/brands.json
  - backend/intelligence/registry/official_domains.json

License: Internal registry with manually curated entries.
No external data fetched at runtime.
"""

from pathlib import Path
import json
from typing import Optional
from dataclasses import dataclass

REGISTRY_DIR = Path(__file__).resolve().parent.parent / "registry"


@dataclass
class BrandEntry:
    brand_id: str
    brand_name: str
    category: str
    parent_company: str
    official_primary_domain: str
    approved_additional_domains: list[dict]
    authorized_dlt_headers: list[str]
    prohibited_keywords_in_subdomains: list[str]


@dataclass
class OfficialDomainEntry:
    domain: str
    brand_id: str
    brand_name: str
    is_primary: bool
    verification_status: str  # "verified" or "unverified"
    purpose: str


class DomainRegistry:
    def __init__(self):
        self._brands: dict[str, BrandEntry] = {}
        self._official_domains: dict[str, OfficialDomainEntry] = {}
        self._load()

    def _load(self):
        brands_path = REGISTRY_DIR / "brands.json"
        official_path = REGISTRY_DIR / "official_domains.json"

        if brands_path.exists():
            with open(brands_path, encoding="utf-8") as f:
                data = json.load(f)
                for entry in data:
                    brand = BrandEntry(**entry)
                    self._brands[brand.brand_id] = brand

        if official_path.exists():
            with open(official_path, encoding="utf-8") as f:
                data = json.load(f)
                for domain, meta in data.items():
                    self._official_domains[domain.lower()] = OfficialDomainEntry(
                        domain=domain.lower(), **meta
                    )

    def is_primary_domain(self, domain: str) -> bool:
        entry = self._official_domains.get(domain.lower())
        return entry is not None and entry.is_primary and entry.verification_status == "verified"

    def is_approved_secondary(self, domain: str) -> bool:
        entry = self._official_domains.get(domain.lower())
        return entry is not None and not entry.is_primary

    def get_domain_entry(self, domain: str) -> Optional[OfficialDomainEntry]:
        return self._official_domains.get(domain.lower())

    def get_brand(self, brand_id: str) -> Optional[BrandEntry]:
        return self._brands.get(brand_id)

    def get_brand_for_domain(self, domain: str) -> Optional[BrandEntry]:
        entry = self._official_domains.get(domain.lower())
        if entry:
            return self._brands.get(entry.brand_id)
        return None

    def get_prohibited_keywords(self, brand_id: str) -> list[str]:
        brand = self._brands.get(brand_id)
        return brand.prohibited_keywords_in_subdomains if brand else []


# Module-level singleton — loads at import time (pure file read, non-blocking)
domain_registry = DomainRegistry()

