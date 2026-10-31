"""
Message pattern loader for AEGIS intelligence service.

Loads legitimate and scam message templates from JSONL datasets.

Datasets:
  - datasets/legitimate_messages/*.jsonl (synthetic anonymized examples)
  - datasets/scam_messages/*.jsonl (synthetic scam examples)

License: All bundled datasets are CC0 or synthetic internal examples.

IMPORTANT: Template similarity is an inference signal only.
It does NOT verify sender authenticity.
"""

from pathlib import Path
import json
from dataclasses import dataclass

DATASETS_DIR = Path(__file__).resolve().parent.parent / "datasets"


@dataclass
class MessagePattern:
    id: str
    label: str
    category: str
    text: str
    source: str
    license: str
    notes: str


class MessageLoader:
    def __init__(self):
        self._legitimate: list[MessagePattern] = []
        self._scam: list[MessagePattern] = []
        self._load()

    def _load_jsonl(self, path: Path) -> list[dict]:
        results = []
        if not path.exists():
            return results
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return results

    def _load(self):
        legit_dir = DATASETS_DIR / "legitimate_messages"
        if legit_dir.exists():
            for jsonl_file in legit_dir.glob("*.jsonl"):
                for entry in self._load_jsonl(jsonl_file):
                    try:
                        self._legitimate.append(
                            MessagePattern(
                                id=entry["id"],
                                label=entry["label"],
                                category=entry["category"],
                                text=entry["text"],
                                source=entry.get("source", "unknown"),
                                license=entry.get("license", "unknown"),
                                notes=entry.get("notes", ""),
                            )
                        )
                    except KeyError:
                        pass

        scam_dir = DATASETS_DIR / "scam_messages"
        if scam_dir.exists():
            for jsonl_file in scam_dir.glob("*.jsonl"):
                for entry in self._load_jsonl(jsonl_file):
                    try:
                        self._scam.append(
                            MessagePattern(
                                id=entry["id"],
                                label=entry["label"],
                                category=entry["category"],
                                text=entry["text"],
                                source=entry.get("source", "unknown"),
                                license=entry.get("license", "unknown"),
                                notes=entry.get("notes", ""),
                            )
                        )
                    except KeyError:
                        pass

    def get_legitimate_patterns(self) -> list[MessagePattern]:
        return list(self._legitimate)

    def get_scam_patterns(self) -> list[MessagePattern]:
        return list(self._scam)

    def find_similar_patterns(
        self, text: str, label: str = "malicious", top_n: int = 3
    ) -> list[tuple[float, MessagePattern]]:
        """Find patterns similar to text using simple keyword overlap.

        Returns list of (similarity_score, pattern) tuples.

        IMPORTANT: Similarity score is an inference signal only.
        High similarity does NOT verify sender authenticity.
        """
        pool = self._scam if label == "malicious" else self._legitimate
        text_lower = text.lower()
        text_words = set(text_lower.split())

        results = []
        for pattern in pool:
            pattern_words = set(pattern.text.lower().split())
            if not pattern_words:
                continue
            intersection = text_words & pattern_words
            score = len(intersection) / max(len(text_words), len(pattern_words))
            if score > 0.05:
                results.append((score, pattern))

        results.sort(key=lambda x: x[0], reverse=True)
        return results[:top_n]


message_loader = MessageLoader()

