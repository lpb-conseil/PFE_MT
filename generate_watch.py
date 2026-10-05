"""
generate_watch.py — Génération assistée du catalogue de veille (watch.yaml).

Pipeline en 3 étages (cf. JOURNAL 2026-07-16) :
  1. DÉTECTION      : actifs supports CISO Assistant absents de watch.yaml
  2. RÉSOLUTION     : candidats CPE via le dictionnaire officiel NVD
                      (/products/cpes?keywordSearch=) — déterministe
  3. DÉSAMBIGUÏSATION : heuristique de recouvrement de tokens (retenue pour
                      sa simplicité — un LLM en désambiguïsation reste
                      l'évolution documentée pour les cas ambigus)

Garde-fou G5 : toute entrée générée porte `pending_validation: true` et est
IGNORÉE par run_watch tant qu'un humain ne l'a pas validée (retrait du flag).
L'IA/heuristique propose, l'humain dispose.

Usage :
    python generate_watch.py            # propose et append dans watch.yaml
    python generate_watch.py --dry-run  # affiche sans écrire

Quota NVD : mêmes limites que l'API CVE (5 req/30s sans clé) — espacement 6,5 s.
"""
from __future__ import annotations

import argparse
import logging
import re
import sys
import time
from datetime import datetime, timezone

import requests
import yaml

import config

log = logging.getLogger("generate_watch")

CPE_DICT_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
RATE_SLEEP = 1.0 if config.NVD_API_KEY else 6.5
MIN_SCORE = 0.5          # sous ce score de confiance, on propose des keywords

# Tokens organisationnels sans valeur produit (cf. reconciliation.py)
STOPWORDS = {"lpb", "lpc", "vm", "srv", "server", "local", "domain",
             "grc", "conseil", "groupe", "mdm", "itsm", "erp", "crm",
             "m365", "saas"}


def _headers() -> dict:
    h = {"User-Agent": "LPB-Conseil-POC-veille/1.0"}
    if config.NVD_API_KEY:
        h["apiKey"] = config.NVD_API_KEY
    return h


# ─── Étage 1 : détection ─────────────────────────────────────────────────────

def get_ciso_supporting_assets() -> list[dict]:
    """Actifs supports CISO Assistant : [{name, description}]."""
    base = config.CISO_URL.rstrip("/")
    out, url = [], f"{base}/api/assets/?limit=100"
    params = {}
    while url:
        r = requests.get(url, headers={"Authorization": f"Token {config.CISO_TOKEN}"},
                         params=params, verify=config.VERIFY_TLS,
                         timeout=config.HTTP_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        for a in data.get("results", data if isinstance(data, list) else []):
            if (a.get("type") or a.get("asset_type", "")).upper().startswith("SP") \
               or a.get("type") == "Support":
                out.append({"name": a.get("name", ""),
                            "description": a.get("description", "") or ""})
        url, params = (data.get("next"), {}) if isinstance(data, dict) else (None, {})
    return out


def load_watch() -> tuple[dict, set[str]]:
    if not config.WATCH_FILE.exists():
        return {}, set()
    with open(config.WATCH_FILE, encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}
    covered = {i.get("asset", "") for i in cfg.get("items", [])}
    return cfg, covered


# ─── Étage 2 : résolution CPE ────────────────────────────────────────────────

def extract_search_terms(asset_name: str) -> list[str]:
    """Extrait les termes produit candidats d'un nom d'actif CISO,
    du plus probable au moins probable — essayés en cascade contre le
    dictionnaire CPE (le premier qui retourne des résultats gagne).

    'Bitwarden (gestionnaire de mots de passe)' → ['bitwarden', 'gestionnaire…']
    'Sites web vitrines (Netlify)'              → ['sites web vitrines', 'netlify']
    'LPC-VM-OPNSENSE'                           → ['opnsense']
    'Microsoft Teams'                           → ['microsoft teams', 'teams']
    """
    def clean(s: str) -> list[str]:
        return [t for t in re.split(r"[\s/_.,-]+", s.lower())
                if t and t not in STOPWORDS]

    terms: list[str] = []
    m = re.search(r"\(([^)]+)\)", asset_name)
    outer = asset_name[:m.start()].strip() if m else asset_name
    outer_tokens = clean(outer)

    if outer_tokens:
        terms.append(" ".join(outer_tokens))          # nom complet nettoyé
        if len(outer_tokens) > 1:
            terms.append(outer_tokens[-1])            # dernier token (Teams)
    if m:
        inner_tokens = clean(m.group(1))
        if inner_tokens:
            terms.append(" ".join(inner_tokens))      # parenthésé (Netlify)
            if len(inner_tokens) > 1:
                terms.append(inner_tokens[0])

    # Dédupliquer en conservant l'ordre
    seen: set[str] = set()
    return [t for t in terms if not (t in seen or seen.add(t))] or [asset_name.lower()]


def query_cpe_dictionary(term: str) -> list[dict]:
    """Interroge le dictionnaire CPE NVD. Retourne [{cpe_prefix, title, count}]."""
    r = requests.get(CPE_DICT_URL,
                     params={"keywordSearch": term, "resultsPerPage": 100},
                     headers=_headers(), timeout=config.HTTP_TIMEOUT)
    if r.status_code == 403:
        log.warning("NVD 403 (throttling) — pause 30s")
        time.sleep(30)
        r = requests.get(CPE_DICT_URL,
                         params={"keywordSearch": term, "resultsPerPage": 100},
                         headers=_headers(), timeout=config.HTTP_TIMEOUT)
    r.raise_for_status()

    seen: dict[str, dict] = {}
    for p in r.json().get("products", []):
        cpe = p.get("cpe", {})
        name = cpe.get("cpeName", "")
        parts = name.split(":")
        if len(parts) < 6 or parts[2] != "a":     # applications uniquement
            continue
        prefix = ":".join(parts[:5])              # cpe:2.3:a:vendor:product
        titles = cpe.get("titles", [])
        title = next((t["title"] for t in titles if t.get("lang") == "en"),
                     titles[0]["title"] if titles else "")
        entry = seen.setdefault(prefix, {"cpe_prefix": prefix, "title": title, "count": 0})
        entry["count"] += 1                       # nb de versions référencées
    return sorted(seen.values(), key=lambda e: -e["count"])


# ─── Étage 3 : désambiguïsation (heuristique — simplicité) ───────────────────

def score_candidate(asset_name: str, term: str, cand: dict) -> float:
    """Score [0,1] de recouvrement entre l'actif et un candidat CPE."""
    parts = cand["cpe_prefix"].split(":")
    vendor, product = parts[3], parts[4]
    hay = f"{vendor} {product} {cand['title']}".lower().replace("_", " ")
    asset_tokens = {t for t in re.split(r"[\s/_.-]+", asset_name.lower())
                    if t and t not in STOPWORDS}
    asset_tokens.add(term.lower())

    hits = sum(1 for t in asset_tokens if t in hay)
    base = hits / max(len(asset_tokens), 1)
    if term.lower() == product.replace("_", " ") or term.lower() == product:
        base = min(1.0, base + 0.5)               # match exact du produit
    return round(base, 2)


def propose_entry(asset: dict) -> dict:
    """Construit une proposition d'entrée watch.yaml pour un actif non couvert.
    Essaie les termes candidats en cascade contre le dictionnaire CPE."""
    name = asset["name"]
    terms = extract_search_terms(name)
    proposal = {"asset": name, "pending_validation": True}

    for term in terms:
        try:
            candidates = query_cpe_dictionary(term)
        except Exception as e:
            log.warning("CPE dictionary KO pour %s (%s) : %s", name, term, e)
            candidates = []
        time.sleep(RATE_SLEEP)

        if not candidates:
            continue
        scored = [(score_candidate(name, term, c), c) for c in candidates[:10]]
        scored.sort(key=lambda x: (-x[0], -x[1]["count"]))
        best_score, best = scored[0]
        if best_score >= MIN_SCORE:
            proposal["cpe"] = best["cpe_prefix"]
            proposal["confidence"] = best_score
            proposal["matched_term"] = term
            proposal["alternatives"] = [
                f"{c['cpe_prefix']} ({s})" for s, c in scored[1:4] if s > 0
            ]
            return proposal

    # Aucun CPE fiable → repli mots-clés (cas d'usage du futur étage LLM).
    # Préférer le dernier terme mono-mot (souvent le produit entre parenthèses).
    proposal["keywords"] = next(
        (t for t in reversed(terms) if " " not in t), terms[0]
    ).title()
    proposal["confidence"] = 0.0
    proposal["note"] = "aucun CPE fiable — désambiguïsation manuelle (ou LLM) requise"
    return proposal


# ─── Écriture ────────────────────────────────────────────────────────────────

def append_proposals(proposals: list[dict]) -> None:
    """Append en fin de watch.yaml (préserve les commentaires existants)."""
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "",
        f"  # ══ Propositions générées le {stamp} — generate_watch.py ══",
        "  # Valider : vérifier le CPE puis retirer 'pending_validation'.",
        "  # Tant que le flag est présent, l'entrée est IGNORÉE par la veille (G5).",
    ]
    for p in proposals:
        lines.append(f"  - asset: \"{p['asset']}\"")
        if "cpe" in p:
            lines.append(f"    cpe: \"{p['cpe']}\"")
        if "keywords" in p:
            lines.append(f"    keywords: \"{p['keywords']}\"")
        lines.append("    pending_validation: true")
        lines.append(f"    # confiance: {p.get('confidence')}")
        for alt in p.get("alternatives", []):
            lines.append(f"    # alternative: {alt}")
        if p.get("note"):
            lines.append(f"    # {p['note']}")
    with open(config.WATCH_FILE, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                        help="affiche les propositions sans modifier watch.yaml")
    args = parser.parse_args()

    _, covered = load_watch()
    assets = get_ciso_supporting_assets()
    uncovered = [a for a in assets if a["name"] not in covered]

    print(f"Actifs supports CISO : {len(assets)} — couverts : {len(assets) - len(uncovered)}"
          f" — à proposer : {len(uncovered)}")
    if not uncovered:
        print("Catalogue complet — rien à générer.")
        return 0

    proposals = []
    for a in uncovered:
        p = propose_entry(a)
        proposals.append(p)
        tag = p.get("cpe") or f"keywords: {p.get('keywords')}"
        print(f"  → {a['name']}: {tag} (confiance {p.get('confidence')})")

    if args.dry_run:
        print("\n--dry-run : watch.yaml non modifié.")
        return 0

    append_proposals(proposals)
    print(f"\n{len(proposals)} proposition(s) ajoutée(s) à {config.WATCH_FILE.name} "
          f"avec pending_validation: true — à valider puis retirer le flag.")
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    sys.exit(main())
