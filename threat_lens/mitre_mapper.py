"""Map CVE descriptions to MITRE ATT&CK Enterprise techniques via keyword matching."""

from __future__ import annotations

import json
import logging
import os
import re
from functools import lru_cache
from typing import Optional

from threat_lens.models import MITRETechnique

logger = logging.getLogger(__name__)

DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "mitre_techniques.json")

MITRE_URL_TEMPLATE = "https://attack.mitre.org/techniques/{tid}/"


class MITREMapper:
    """Load a curated ATT&CK technique set and match CVEs by description keywords."""

    def __init__(self, data_path: Optional[str] = None):
        self._path = data_path or DATA_PATH
        self._techniques: dict[str, dict] = {}
        self._tactic_index: dict[str, list[str]] = {}
        self._load()

    def _load(self) -> None:
        with open(self._path, "r", encoding="utf-8") as fh:
            raw: list[dict] = json.load(fh)

        for entry in raw:
            tid = entry["technique_id"]
            self._techniques[tid] = entry
            for tactic in entry.get("tactics", []):
                self._tactic_index.setdefault(tactic, []).append(tid)

        logger.info("Loaded %d MITRE ATT&CK techniques", len(self._techniques))

    def get_technique(self, technique_id: str) -> Optional[MITRETechnique]:
        """Look up a technique by its ID (e.g. T1059)."""
        entry = self._techniques.get(technique_id.upper())
        if not entry:
            return None
        return self._to_model(entry)

    def list_techniques(self) -> list[MITRETechnique]:
        """Return every loaded technique."""
        return [self._to_model(e) for e in self._techniques.values()]

    def techniques_by_tactic(self, tactic: str) -> list[MITRETechnique]:
        """Return all techniques belonging to a given tactic."""
        normalised = self._normalise_tactic(tactic)
        tids = self._tactic_index.get(normalised, [])
        return [self._to_model(self._techniques[tid]) for tid in tids]

    def list_tactics(self) -> list[str]:
        """Return the set of tactic names present in the loaded data."""
        return sorted(self._tactic_index.keys())

    def map_cve(self, description: str, top_n: int = 5) -> list[MITRETechnique]:
        """Score every technique against a CVE description and return the best matches."""
        if not description:
            return []

        desc_lower = description.lower()
        scored: list[tuple[float, dict]] = []

        for entry in self._techniques.values():
            score = self._match_score(desc_lower, entry)
            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [self._to_model(e) for _, e in scored[:top_n]]

    @staticmethod
    def _match_score(text: str, technique: dict) -> float:
        """Weighted keyword hit count against a technique's keyword list."""
        keywords: list[str] = technique.get("keywords", [])
        if not keywords:
            return 0.0

        hits = 0.0
        for kw in keywords:
            pattern = re.compile(re.escape(kw.lower()))
            matches = pattern.findall(text)
            if matches:
                weight = len(kw.split())
                hits += len(matches) * weight

        name_tokens = technique["name"].lower().split()
        for token in name_tokens:
            if len(token) > 3 and token in text:
                hits += 0.5

        return hits

    def _normalise_tactic(self, tactic: str) -> str:
        """Best-effort normalisation of tactic names to title case."""
        tactic_title = tactic.strip().title()
        for known in self._tactic_index:
            if known.lower() == tactic_title.lower():
                return known
        return tactic_title

    @staticmethod
    def _to_model(entry: dict) -> MITRETechnique:
        tid = entry["technique_id"]
        return MITRETechnique(
            technique_id=tid,
            name=entry["name"],
            tactics=entry.get("tactics", []),
            description=entry.get("description", ""),
            platforms=entry.get("platforms", []),
            detection=entry.get("detection", ""),
            mitigations=entry.get("mitigations", []),
            url=MITRE_URL_TEMPLATE.format(tid=tid.replace(".", "/")),
        )
