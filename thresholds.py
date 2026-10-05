"""Profils de seuils de criticite — absolus ou relatifs au parc.

Le bucket stocke en base reste celui du profil "rapport" (scoring.severity_bucket) :
l'historique n'est jamais reecrit. Les profils sont appliques a la LECTURE, ce qui
permet de commuter sans recollecte et de comparer les deux lectures cote a cote.
"""
from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

import yaml

log = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).with_name("thresholds.yaml")
ORDER = ("critique", "eleve", "modere", "faible")


@lru_cache(maxsize=1)
def _config() -> dict:
    with CONFIG_PATH.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def reload_config() -> None:
    _config.cache_clear()


def profiles() -> dict:
    return _config().get("profils") or {}


def default_profile() -> str:
    return _config().get("actif") or "rapport"


def _percentile(sorted_values: list[float], p: float) -> float:
    """Percentile par interpolation lineaire. Liste supposee triee, non vide."""
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    k = (len(sorted_values) - 1) * (p / 100.0)
    lo, hi = int(k), min(int(k) + 1, len(sorted_values) - 1)
    return float(sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (k - lo))


def resolve(profile: str | None, scores: list[float] | None = None) -> dict:
    """Retourne les seuils effectifs {critique, eleve, modere} pour un profil.

    Pour un profil percentile, `scores` est la population de reference (scores
    non nuls du cycle courant). Si elle est absente ou vide, on retombe sur le
    profil "rapport" plutot que d'inventer des seuils (G5).
    """
    name = profile or default_profile()
    prof = profiles().get(name)
    if prof is None:
        log.warning("Profil de seuils inconnu : %s — retour au profil rapport", name)
        name, prof = "rapport", profiles()["rapport"]

    raw = prof.get("seuils") or {}
    if prof.get("type") == "percentile":
        vals = sorted(s for s in (scores or []) if s is not None)
        if not vals:
            log.warning("Profil %s demande sans population de reference — repli sur rapport", name)
            fallback = profiles()["rapport"]
            return {"profil": "rapport", "label": fallback["label"], "type": "absolu",
                    "seuils": dict(fallback["seuils"]), "repli": True,
                    "justification": fallback.get("justification", "")}
        seuils = {k: round(_percentile(vals, p), 1) for k, p in raw.items()}
        return {"profil": name, "label": prof["label"], "type": "percentile",
                "seuils": seuils, "percentiles": dict(raw), "population": len(vals),
                "justification": prof.get("justification", "")}

    return {"profil": name, "label": prof["label"], "type": "absolu",
            "seuils": {k: float(v) for k, v in raw.items()},
            "justification": prof.get("justification", "")}


def bucket(score: float | None, seuils: dict) -> str:
    if score is None:
        return "non_evalue"
    if score >= seuils.get("critique", float("inf")):
        return "critique"
    if score >= seuils.get("eleve", float("inf")):
        return "eleve"
    if score >= seuils.get("modere", float("inf")):
        return "modere"
    return "faible"
