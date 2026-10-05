"""Collecteur CISO Assistant — criticités métier C/D/I par actif.

Convention du POC : C = Confidentialité, D = Disponibilité, I = Intégrité,
chacun sur 0-3 (cf. formule, rapport 4.2). Dans CISO Assistant ces valeurs
sont portées par les "security objectives" des assets (confidentiality /
availability / integrity).

Le parseur est volontairement défensif : la structure exacte du champ varie
selon les versions (dict imbriqué "objectives", valeur directe ou {"value": n}).
Au premier run, vérifier le log DEBUG "structure brute" si les C/D/I sortent vides.
"""
from __future__ import annotations

import json
import logging

import requests
import urllib3

import config
from scoring import CDI_MIN, CDI_MAX

log = logging.getLogger(__name__)

if not config.VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_OBJECTIVE_KEYS = {
    "c": ("confidentiality",),
    "d": ("availability",),
    "i": ("integrity",),
}


def _extract_value(node) -> int | None:
    """Accepte 2, {"value": 2}, {"value": 2, "is_enabled": true}…"""
    if node is None:
        return None
    if isinstance(node, (int, float)):
        return int(node)
    if isinstance(node, dict):
        if node.get("is_enabled") is False:
            return None
        v = node.get("value")
        if isinstance(v, (int, float)):
            return int(v)
    return None


def _list_to_dict(lst) -> dict:
    """Convertit [{"confidentiality": 4}, {"integrity": 3}] en {"confidentiality": 4, "integrity": 3}."""
    merged: dict = {}
    if isinstance(lst, list):
        for item in lst:
            if isinstance(item, dict):
                merged.update(item)
    elif isinstance(lst, dict):
        merged = lst.get("objectives", lst)
    return merged


def _parse_objectives(asset: dict) -> dict:
    # Priorité 1 : security_objectives (valeurs cibles)
    # Priorité 2 : security_capabilities (valeurs actuelles) — fallback si objectives vide
    so = asset.get("security_objectives") or []
    objectives = _list_to_dict(so)
    if not objectives:
        sc = asset.get("security_capabilities") or []
        objectives = _list_to_dict(sc)
        if objectives:
            log.debug("Fallback security_capabilities pour %s", asset.get("name"))
    out = {}
    for short, keys in _OBJECTIVE_KEYS.items():
        val = None
        for k in keys:
            val = _extract_value(objectives.get(k))
            if val is not None:
                break
        out[short] = max(CDI_MIN, min(CDI_MAX, val)) if val is not None else None
    return out


def _fetch_detail(asset_id: str, headers: dict) -> dict:
    """Récupère le détail d'un asset (inclut security_capabilities absent de la liste)."""
    url = f"{config.CISO_URL.rstrip('/')}/api/assets/{asset_id}/"
    r = requests.get(url, headers=headers, verify=config.VERIFY_TLS, timeout=config.HTTP_TIMEOUT)
    r.raise_for_status()
    return r.json()


def get_assets_cdi() -> dict[str, dict]:
    """Retourne {nom_asset_lower: {"c": n|None, "d": n|None, "i": n|None, "name": str}}.

    L'endpoint liste ne retourne pas security_capabilities (seulement security_objectives).
    Si security_objectives est vide, on fetche le détail de l'asset pour lire
    security_capabilities — fallback nécessaire quand l'utilisateur a renseigné
    les C/D/I dans la mauvaise section de l'UI CISO Assistant.
    """
    headers = {"Authorization": f"Token {config.CISO_TOKEN}"}
    url = f"{config.CISO_URL.rstrip('/')}/api/assets/"
    results, params = [], {"limit": 200}
    while url:
        r = requests.get(url, headers=headers, params=params,
                         verify=config.VERIFY_TLS, timeout=config.HTTP_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        page = data.get("results", data if isinstance(data, list) else [])
        results.extend(page)
        url, params = data.get("next") if isinstance(data, dict) else None, None

    # ── Passe 1 : parser C/D/I et parents de tous les assets ──
    parsed: dict[str, dict] = {}
    for asset in results:
        name = asset.get("name", "")
        if not name:
            continue
        # Si objectives vides, fetch le détail pour accéder à security_capabilities
        so = asset.get("security_objectives") or []
        if not so:
            try:
                asset = _fetch_detail(asset["id"], headers)
            except Exception as e:
                log.warning("Impossible de récupérer le détail de %s : %s", name, e)
        cdi = _parse_objectives(asset)
        if all(v is None for v in cdi.values()):
            log.debug("CISO : aucune valeur C/D/I pour %s", name)
        parents = asset.get("parent_assets") or []
        parent_names = [p["str"] for p in parents if isinstance(p, dict) and p.get("str")]
        parsed[name.lower()] = {
            "name": name,
            "parents": parent_names,
            **cdi,
        }

    # ── Passe 2 : VM = criticité de la valeur métier portée (formule V1.1) ──
    # VM = max, parmi les actifs primaires parents, de (C+D+I)/3 (échelle 0-4).
    # None si aucun parent évalué → compute_score dégénère en V1 (neutre).
    out = {}
    for key, a in parsed.items():
        vm = None
        for pname in a["parents"]:
            p = parsed.get(pname.lower())
            if p and p["c"] is not None and p["d"] is not None and p["i"] is not None:
                pv = round((p["c"] + p["d"] + p["i"]) / 3.0, 2)
                vm = pv if vm is None else max(vm, pv)
        out[key] = {
            "name": a["name"],
            "parent_activities": json.dumps(a["parents"], ensure_ascii=False) if a["parents"] else None,
            "vm": vm,
            "c": a["c"], "d": a["d"], "i": a["i"],
        }
    log.info("CISO Assistant : %d assets récupérés (%d avec VM)",
             len(out), sum(1 for v in out.values() if v["vm"] is not None))
    return out
