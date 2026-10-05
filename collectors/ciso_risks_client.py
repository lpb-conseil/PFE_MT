"""
ciso_risks_client.py — Collecteur scénarios de risque CISO Assistant (V2).

Récupère via l'API REST :
  - Les assessments de risque (EBIOS RM)
  - Les scénarios de risque avec leurs actifs supports et mesures liées
  - Les applied controls avec leurs catégories (depuis risk_tuning si non renseigné dans CISO)

Même pattern que ciso_client.py : requests + Token auth, pagination DRF.
"""
from __future__ import annotations

import logging
from typing import Optional

import requests
import urllib3
import yaml

import config

log = logging.getLogger(__name__)

if not config.VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _headers() -> dict:
    return {"Authorization": f"Token {config.CISO_TOKEN}"}


def _get_paged(url: str, params: dict | None = None) -> list[dict]:
    """Fetche toutes les pages d'un endpoint DRF paginé."""
    results = []
    next_url: Optional[str] = url
    extra = params or {}
    while next_url:
        r = requests.get(
            next_url, headers=_headers(), params=extra,
            verify=config.VERIFY_TLS, timeout=config.HTTP_TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        if isinstance(data, list):
            results.extend(data)
            break
        page = data.get("results", [])
        results.extend(page)
        next_url = data.get("next")
        extra = {}   # params seulement sur la première page
    return results


def _extract_names(field_value) -> list[str]:
    """Extrait une liste de noms depuis un champ qui peut être :
      - list[dict] avec clé 'name', 'str', ou 'display_name'
      - list[str]
      - str
    """
    if not field_value:
        return []
    if isinstance(field_value, str):
        return [field_value] if field_value.strip() else []
    names = []
    for item in field_value:
        if isinstance(item, str):
            names.append(item)
        elif isinstance(item, dict):
            name = (item.get("name") or item.get("str") or
                    item.get("display_name") or item.get("__str__") or "")
            if name:
                names.append(name)
    return names


def get_risk_scenarios() -> list[dict]:
    """
    Retourne la liste des scénarios de risque de tous les assessments.

    Chaque dict :
      id (str UUID), name (str), ref (str),
      current_level (str : "high" | "medium" | ...),
      assets (list[str]),
      controls (list[str])   -- existing + additional
    """
    base = config.CISO_URL.rstrip("/")
    scenarios_out: list[dict] = []

    # 1. Récupérer tous les assessments
    try:
        assessments = _get_paged(f"{base}/api/risk-assessments/", {"limit": 100})
    except Exception as e:
        log.error("CISO risks : impossible de lister les assessments : %s", e)
        return []

    for assessment in assessments:
        a_id = assessment.get("id") or assessment.get("uuid", "")
        if not a_id:
            continue

        # 2. Récupérer les scénarios de cet assessment
        try:
            scenarios = _get_paged(
                f"{base}/api/risk-scenarios/",
                {"risk_assessment": a_id, "limit": 200},
            )
        except Exception as e:
            log.warning("CISO risks : assessment %s — scénarios inaccessibles : %s", a_id, e)
            continue

        for s in scenarios:
            s_id   = s.get("id") or s.get("uuid", "")
            name   = s.get("name") or s.get("__str__") or ""
            ref    = s.get("ref") or s.get("reference") or ""

            # Niveau courant — str, dict ou index selon la version de l'API
            raw_level = next(
                (s[k] for k in ("current_level", "current_risk_level", "risk_level")
                 if s.get(k) is not None),
                "",
            )
            level = _normalize_level(raw_level)

            # Actifs supports
            assets_raw = s.get("assets") or s.get("supporting_assets") or []
            asset_names = _extract_names(assets_raw)

            # Mesures : existing_controls + additional_controls
            ctrl_raw = list(s.get("existing_controls") or []) + list(s.get("additional_controls") or [])
            control_names = _extract_names(ctrl_raw)

            if not s_id:
                log.debug("Scénario sans ID ignoré : %s", name)
                continue

            scenarios_out.append({
                "id":           s_id,
                "name":         name,
                "ref":          ref,
                "current_level": level,
                "assets":       asset_names,
                "controls":     control_names,
                "assessment_id": a_id,
            })

    log.info("CISO risks : %d scénarios récupérés", len(scenarios_out))
    return scenarios_out


def _normalize_level(raw) -> str:
    """Normalise le niveau de risque CISO en label minuscule.

    Le champ `current_level` de l'API varie selon les versions :
      - str   : "H", "High", "critical"…
      - dict  : {"name": "High", "abbreviation": "H", "value": 2, ...}
      - int   : index dans l'échelle de la matrice (0 = plus bas)
    """
    if raw is None or raw == "":
        return "unknown"

    if isinstance(raw, dict):
        raw = (raw.get("name") or raw.get("abbreviation")
               or raw.get("label") or raw.get("value"))
        if raw is None:
            return "unknown"

    if isinstance(raw, (int, float)):
        # Index d'échelle (matrice 4 niveaux par défaut) — approximation,
        # à recaler sur l'échelle réelle de la matrice CISO (décision 4 cadrage)
        idx_map = ["low", "medium", "high", "critical"]
        i = int(raw)
        if i < 0:
            return "unknown"          # -1 = non évalué dans CISO
        return idx_map[min(i, len(idx_map) - 1)]

    r = str(raw).strip().lower()
    mapping = {
        "c": "critical", "critical": "critical", "critique": "critical",
        "h": "high",     "high": "high",         "élevé": "high", "eleve": "high",
        "m": "medium",   "medium": "medium",     "modéré": "medium", "modere": "medium",
        "l": "low",      "low": "low",           "faible": "low",
        "n": "negligible","negligible": "negligible",
        "--": "unknown", "": "unknown",
    }
    return mapping.get(r, r)


def get_control_category(control_name: str, tuning: dict) -> Optional[str]:
    """Retourne la catégorie fonctionnelle d'une mesure depuis risk_tuning.
    Retourne None si non catégorisée (G5 : pas de catégorisation silencieuse).
    """
    categories: dict = tuning.get("control_categories", {})
    # Match exact d'abord
    if control_name in categories:
        return categories[control_name]
    # Match partiel sur le début du nom (ex. "M-01 — MFA…" dans CISO)
    for key, cat in categories.items():
        if control_name.startswith(key[:10]) or key.startswith(control_name[:10]):
            return cat
    return None
