"""Orchestration d'un cycle de veille CVE (NVD) sur les actifs de watch.yaml.

Indépendant du cycle de collecte iTop/Wazuh/CISO :
  - tourne à sa propre fréquence (WATCH_INTERVAL_MIN, défaut 60 min)
  - mode delta : ne remonte que les CVE nouvelles/modifiées depuis le dernier poll
  - alimente watch_news (flux d'actualité) et, si create_risk_events,
    risk_events/risk_effects (matrice V2) pour les scénarios dont les actifs
    supports correspondent — repris au prochain compute de positions.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

import config
import db
from collectors import nvd_watch_client

log = logging.getLogger(__name__)


def _load_watch_config() -> dict:
    if not config.WATCH_FILE.exists():
        log.warning("watch.yaml introuvable — veille désactivée")
        return {}
    with open(config.WATCH_FILE, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _load_tuning() -> dict:
    tuning_file = Path(__file__).resolve().parent.parent / "risk_tuning.yaml"
    if not tuning_file.exists():
        return {}
    with open(tuning_file, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _find_scenarios_for_asset(con, asset_name: str) -> list[str]:
    """Scénarios EBIOS dont les actifs supports correspondent (exact puis flou)."""
    rows = con.execute(
        "SELECT DISTINCT scenario_id FROM risk_assets WHERE asset_name = ?",
        (asset_name,)
    ).fetchall()
    if not rows:
        rows = con.execute(
            "SELECT DISTINCT scenario_id FROM risk_assets WHERE LOWER(asset_name) LIKE ?",
            (f"%{asset_name.lower()[:12]}%",)
        ).fetchall()
    return [r["scenario_id"] for r in rows]


def _create_risk_event(con, scenario_id: str, asset_name: str,
                       news: dict, tuning: dict, now: datetime) -> None:
    """Crée un risk_event + risk_effect (type watch_vuln, source nvd) — dédupliqué."""
    already = con.execute(
        "SELECT id FROM risk_events WHERE scenario_id=? AND ref=? AND type='watch_vuln'",
        (scenario_id, news["cve"])
    ).fetchone()
    if already:
        return

    cfg = tuning.get("effects", {}).get("watch_vuln",
          tuning.get("effects", {}).get("new_vuln", {}))
    delta   = cfg.get("delta", 1)
    plateau = cfg.get("plateau_days", 7)
    decay   = cfg.get("decay_days", 30)

    cur = con.execute(
        """INSERT INTO risk_events (scenario_id, type, source, ref, level, occurred_at, detail)
           VALUES (?,?,?,?,?,?,?)""",
        (scenario_id, "watch_vuln", "nvd", news["cve"], news.get("cvss"),
         now.isoformat(),
         json.dumps({"asset": asset_name, "cvss": news.get("cvss"),
                     "severity": news.get("severity"), "url": news.get("url")}))
    )
    con.execute(
        """INSERT INTO risk_effects
             (event_id, scenario_id, axis, delta, curve, starts_at, decays_at, expires_at, active, label)
           VALUES (?,?,?,?,?,?,?,?,1,?)""",
        (cur.lastrowid, scenario_id, "likelihood", delta, "plateau_decay",
         now.isoformat(),
         (now + timedelta(days=plateau)).isoformat(),
         (now + timedelta(days=plateau + decay)).isoformat(),
         f"+{delta} vraisemblance : veille NVD {news['cve']} sur {asset_name} "
         f"(CVSS {news.get('cvss') or '?'})")
    )


def run() -> dict:
    """Exécute un cycle de veille. Retourne {items, news_total, errors}."""
    watch_cfg = _load_watch_config()
    items = watch_cfg.get("items", [])
    if not items:
        return {"items": 0, "news_total": 0, "errors": ["watch.yaml vide ou absent"]}

    gcfg           = watch_cfg.get("global", {})
    default_min    = float(gcfg.get("min_cvss", 7.0))
    first_run_days = int(gcfg.get("first_run_days", 90))
    make_events    = bool(gcfg.get("create_risk_events", True))
    tuning         = _load_tuning() if make_events else {}

    now = datetime.now(timezone.utc)
    news_total, errors = 0, []

    pending = [i for i in items if i.get("pending_validation")]
    if pending:
        log.info("%d entrée(s) en attente de validation ignorée(s) (G5) : %s",
                 len(pending), ", ".join(i.get("asset", "?") for i in pending))

    active = [i for i in items if not i.get("pending_validation")]

    # ── Phase 1 (DB courte) : lire l'état des abonnements ──
    with db.connect() as con:
        states = {r["asset_name"]: r["last_checked"] for r in con.execute(
            "SELECT asset_name, last_checked FROM watch_state").fetchall()}

    # ── Phase 2 (réseau, AUCUNE connexion DB ouverte) : interroger NVD ──
    # Ne jamais tenir la connexion SQLite pendant les appels réseau + pauses
    # quota (6,5 s/item) — sinon la collecte concurrente prend un
    # "database is locked" (incident du 16/07, cf. JOURNAL).
    fetched: list[tuple[dict, list, str]] = []   # (item, news, status)
    for item in active:
        asset = item.get("asset")
        cpe, keywords = item.get("cpe"), item.get("keywords")
        if not asset or not (cpe or keywords):
            errors.append(f"entrée invalide : {item}")
            continue

        last_checked = states.get(asset)
        try:
            if last_checked:
                since = datetime.fromisoformat(last_checked)
                if since.tzinfo is None:
                    since = since.replace(tzinfo=timezone.utc)
                news = nvd_watch_client.fetch_cves(
                    cpe=cpe, keywords=keywords, since=since)
            else:
                news = nvd_watch_client.fetch_cves(
                    cpe=cpe, keywords=keywords,
                    published_since=now - timedelta(days=first_run_days))
            status = "ok"
        except Exception as e:
            log.warning("Veille %s en échec : %s", asset, e)
            errors.append(f"{asset}: {e}")
            news, status = [], f"error: {e}"[:200]

        fetched.append((item, news, status))
        time.sleep(nvd_watch_client.RATE_SLEEP)   # espacement inter-items (quota)

    # ── Phase 3 (DB courte) : persister news, events, états ──
    with db.connect() as con:
        for item, news, status in fetched:
            asset = item["asset"]
            cpe, keywords = item.get("cpe"), item.get("keywords")
            qtype, qval = ("cpe", cpe) if cpe else ("keywords", keywords)
            min_cvss = float(item.get("min_cvss", default_min))

            inserted = 0
            for n in news:
                cur = con.execute(
                    """INSERT OR IGNORE INTO watch_news
                         (asset_name, cve, cvss, severity, summary,
                          published_at, modified_at, url, collected_at)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (asset, n["cve"], n.get("cvss"), n.get("severity"),
                     n.get("summary"), n.get("published_at"),
                     n.get("modified_at"), n.get("url"), now.isoformat())
                )
                if cur.rowcount:
                    inserted += 1
                    # Alimenter la matrice V2 si la CVE dépasse le seuil
                    if make_events and n.get("cvss") and n["cvss"] >= min_cvss:
                        for sid in _find_scenarios_for_asset(con, asset):
                            _create_risk_event(con, sid, asset, n, tuning, now)

            news_total += inserted
            con.execute(
                """INSERT INTO watch_state (asset_name, query_type, query_value,
                                            last_checked, last_status, news_count)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(asset_name) DO UPDATE SET
                     query_type=excluded.query_type, query_value=excluded.query_value,
                     last_checked=CASE WHEN excluded.last_status='ok'
                                       THEN excluded.last_checked ELSE last_checked END,
                     last_status=excluded.last_status,
                     news_count=news_count + ?""",
                (asset, qtype, qval,
                 now.isoformat() if status == "ok" else None,
                 status, inserted, inserted)
            )

    summary = {"items": len(items), "news_total": news_total, "errors": errors}
    log.info("Cycle de veille terminé : %s", summary)
    return summary


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    db.init_db()
    print(run())
