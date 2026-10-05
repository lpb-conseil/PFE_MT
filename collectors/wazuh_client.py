"""Collecteur Wazuh — agents et vulnérabilités par agent.

Gestion des tokens (choix documenté au rapport, section 4.3) :
l'API Wazuh délivre des JWT valables 900 s sans mécanisme de refresh.
Stratégie retenue : un token frais est généré au début de chaque cycle de
collecte (l'objet client est instancié par cycle), avec une unique nouvelle
tentative sur 401 à titre défensif.

Compatibilité versions :
- Wazuh <= 4.7 : GET /vulnerability/{agent_id}
- Wazuh >= 4.8 : endpoint supprimé -> interrogation de l'indexeur
  (index wazuh-states-vulnerabilities-*), WAZUH_INDEXER_URL requis.
"""
from __future__ import annotations

import logging

import requests
import urllib3

import config

log = logging.getLogger(__name__)

if not config.VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WazuhError(RuntimeError):
    pass


class WazuhClient:
    def __init__(self):
        self.base = config.WAZUH_API_URL.rstrip("/")
        self.session = requests.Session()
        self.session.verify = config.VERIFY_TLS
        self.token: str | None = None
        self.api_version: str = ""

    # --- authentification -------------------------------------------------
    def authenticate(self) -> None:
        """POST /security/user/authenticate -> JWT (900 s)."""
        r = self.session.post(
            f"{self.base}/security/user/authenticate",
            auth=(config.WAZUH_USER, config.WAZUH_PASSWORD),
            timeout=config.HTTP_TIMEOUT,
        )
        if r.status_code != 200:
            raise WazuhError(f"Authentification Wazuh refusée ({r.status_code}): {r.text[:200]}")
        self.token = r.json()["data"]["token"]
        self.session.headers["Authorization"] = f"Bearer {self.token}"

    def _get(self, path: str, params: dict | None = None) -> dict:
        """GET authentifié, avec une unique ré-authentification sur 401."""
        if self.token is None:
            self.authenticate()
        r = self.session.get(f"{self.base}{path}", params=params, timeout=config.HTTP_TIMEOUT)
        if r.status_code == 401:
            log.info("Token Wazuh expiré — ré-authentification")
            self.authenticate()
            r = self.session.get(f"{self.base}{path}", params=params, timeout=config.HTTP_TIMEOUT)
        r.raise_for_status()
        return r.json()

    # --- endpoints ---------------------------------------------------------
    def get_version(self) -> str:
        data = self._get("/")
        self.api_version = data.get("data", {}).get("api_version", "")
        return self.api_version

    def get_agents(self) -> list[dict]:
        data = self._get("/agents", params={"limit": 500})
        return [
            {"id": a["id"], "name": a["name"], "ip": a.get("ip"), "status": a.get("status")}
            for a in data["data"]["affected_items"]
        ]

    def get_vulnerabilities(self, agent: dict) -> list[dict]:
        """Retourne [{cve, cvss, severity, package}] pour un agent.
        Choisit automatiquement le mode selon la version de l'API."""
        if self._use_indexer():
            return self._vulns_from_indexer(agent["name"])
        return self._vulns_from_api(agent["id"])

    def _use_indexer(self) -> bool:
        if not self.api_version:
            try:
                self.get_version()
            except Exception:
                return False
        try:
            major, minor = (int(x) for x in self.api_version.split(".")[:2])
            return (major, minor) >= (4, 8)
        except ValueError:
            return False

    @staticmethod
    def _parse_cvss(raw) -> float | None:
        """Convertit un score CVSS brut en float, ou None si absent/invalide.
        Wazuh/OpenSearch retourne -1.0 pour les CVEs sans score — traité comme None."""
        if raw in (None, ""):
            return None
        v = float(raw)
        return v if v >= 0 else None

    def _vulns_from_api(self, agent_id: str) -> list[dict]:
        data = self._get(f"/vulnerability/{agent_id}", params={"limit": 1000})
        out = []
        for v in data["data"]["affected_items"]:
            cvss_raw = (
                v.get("cvss3_score")
                or (v.get("cvss") or {}).get("cvss3", {}).get("base_score")
                or v.get("cvss2_score")
            )
            out.append({
                "cve": v.get("cve", "?"),
                "cvss": self._parse_cvss(cvss_raw),
                "severity": (v.get("severity") or "").lower() or None,
                "package": v.get("name") or v.get("package"),
            })
        return out

    def _vulns_from_indexer(self, agent_name: str) -> list[dict]:
        if not config.WAZUH_INDEXER_URL:
            raise WazuhError(
                f"Wazuh {self.api_version} détecté : l'endpoint /vulnerability n'existe plus. "
                "Renseigner WAZUH_INDEXER_URL (port 9200) dans le .env."
            )
        r = requests.post(
            f"{config.WAZUH_INDEXER_URL.rstrip('/')}/wazuh-states-vulnerabilities-*/_search",
            auth=(config.WAZUH_INDEXER_USER, config.WAZUH_INDEXER_PASSWORD),
            verify=config.VERIFY_TLS,
            timeout=config.HTTP_TIMEOUT,
            json={
                # 10 000 = max_result_window par défaut d'OpenSearch ; couvre le
                # volume actuel (max ~6600 CVE/agent). Au-delà, il faudrait paginer
                # (search_after / PIT) — cf. note d'amélioration au rapport.
                "size": 10000,
                "query": {"term": {"agent.name": agent_name}},
                "_source": ["vulnerability", "package.name"],
            },
        )
        r.raise_for_status()
        out = []
        for hit in r.json().get("hits", {}).get("hits", []):
            src = hit.get("_source", {})
            vuln = src.get("vulnerability", {})
            score = (vuln.get("score") or {}).get("base")
            out.append({
                "cve": vuln.get("id", "?"),
                "cvss": self._parse_cvss(score),
                "severity": (vuln.get("severity") or "").lower() or None,
                "package": (src.get("package") or {}).get("name"),
            })
        return out
