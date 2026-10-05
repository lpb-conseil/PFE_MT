"""
nvd_watch_client.py — Veille CVE via l'API NVD 2.0 (actifs SaaS et produits).

Principe "subscription par polling delta" :
  - Premier passage  : CVE publiées sur les `first_run_days` derniers jours
  - Passages suivants: lastModStartDate = dernier passage → uniquement le delta

Requêtage :
  - `cpe`      → virtualMatchString (précis, recommandé)
  - `keywords` → keywordSearch (fallback produits sans CPE référencé)

Quota NVD : 5 req/30s sans clé API, 50 req/30s avec (header apiKey).
Le client espace ses requêtes en conséquence (RATE_SLEEP).
"""
from __future__ import annotations

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

import config

log = logging.getLogger(__name__)

RATE_SLEEP = 1.0 if config.NVD_API_KEY else 6.5   # marge sous le quota
MAX_RESULTS_PER_PAGE = 200
DATE_FMT = "%Y-%m-%dT%H:%M:%S.000"


def _headers() -> dict:
    h = {"User-Agent": "LPB-Conseil-POC-veille/1.0"}
    if config.NVD_API_KEY:
        h["apiKey"] = config.NVD_API_KEY
    return h


def _iso_nvd(dt: datetime) -> str:
    """Format ISO-8601 avec offset explicite, attendu par l'API NVD 2.0."""
    return dt.astimezone(timezone.utc).strftime(DATE_FMT) + "+00:00"


def _extract_cvss(cve: dict) -> tuple[Optional[float], str]:
    """Extrait (score, sévérité) en préférant CVSS v3.1 > v3.0 > v4.0 > v2."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            sev = (entries[0].get("baseSeverity")
                   or data.get("baseSeverity") or "").upper()
            return score, sev
    return None, ""


def _extract_summary(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")[:500]
    descs = cve.get("descriptions", [])
    return (descs[0].get("value", "")[:500]) if descs else ""


def fetch_cves(*, cpe: Optional[str] = None, keywords: Optional[str] = None,
               since: Optional[datetime] = None,
               published_since: Optional[datetime] = None) -> list[dict]:
    """Interroge NVD. Retourne une liste de dicts :
       {cve, cvss, severity, summary, published_at, modified_at, url}

    - `since`           → lastModStartDate (mode delta)
    - `published_since` → pubStartDate (premier passage)
    Exactement un des deux doit être fourni ; cpe XOR keywords.
    """
    params: dict = {"resultsPerPage": MAX_RESULTS_PER_PAGE}
    now = datetime.now(timezone.utc)

    if cpe:
        params["virtualMatchString"] = cpe
    elif keywords:
        params["keywordSearch"] = keywords
    else:
        raise ValueError("cpe ou keywords requis")

    if since is not None:
        params["lastModStartDate"] = _iso_nvd(since)
        params["lastModEndDate"] = _iso_nvd(now)
    elif published_since is not None:
        params["pubStartDate"] = _iso_nvd(published_since)
        params["pubEndDate"] = _iso_nvd(now)
    else:
        raise ValueError("since ou published_since requis")

    out: list[dict] = []
    start_index = 0
    while True:
        params["startIndex"] = start_index
        r = requests.get(config.NVD_API_URL, params=params,
                         headers=_headers(), timeout=config.HTTP_TIMEOUT)
        if r.status_code == 403:
            # Throttling NVD — attendre puis retenter une fois
            log.warning("NVD 403 (throttling) — pause 30s puis nouvelle tentative")
            time.sleep(30)
            r = requests.get(config.NVD_API_URL, params=params,
                             headers=_headers(), timeout=config.HTTP_TIMEOUT)
        r.raise_for_status()
        data = r.json()

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            score, sev = _extract_cvss(cve)
            out.append({
                "cve": cve_id,
                "cvss": score,
                "severity": sev,
                "summary": _extract_summary(cve),
                "published_at": cve.get("published"),
                "modified_at": cve.get("lastModified"),
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            })

        total = data.get("totalResults", 0)
        start_index += data.get("resultsPerPage", MAX_RESULTS_PER_PAGE)
        if start_index >= total:
            break
        time.sleep(RATE_SLEEP)

    return out
