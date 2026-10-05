"""Dashboard de scoring de vulnérabilités — POC PFE LPB Conseil.

FastAPI héberge dans le même processus :
- l'ordonnanceur de collecte (APScheduler, toutes les COLLECT_INTERVAL_MIN minutes)
- l'API de lecture (qui n'interroge QUE la base SQLite — jamais les API sources)
- le front statique (static/index.html)

Lancement local :  uvicorn app:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import json
import logging
import random
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import yaml
from apscheduler.schedulers.background import BackgroundScheduler
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

import config
import db
import exposure
import risk_engine
import thresholds
from collectors import run_collect, run_watch

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("app")

_collect_lock = threading.Lock()
_watch_lock = threading.Lock()


def _do_collect():
    if not _collect_lock.acquire(blocking=False):
        log.info("Collecte déjà en cours — cycle ignoré")
        return
    try:
        run_collect.run()
        with db.connect() as con:
            db.ensure_baseline(con)
            purged = db.purge_old_vulns(con)
            if purged:
                log.info("Purge : %d lignes supprimées de vulnerabilities", purged)
    except Exception:
        log.exception("Cycle de collecte en échec")
    finally:
        _collect_lock.release()


def _do_watch():
    if not _watch_lock.acquire(blocking=False):
        log.info("Veille déjà en cours — cycle ignoré")
        return
    try:
        run_watch.run()
    except Exception:
        log.exception("Cycle de veille en échec")
    finally:
        _watch_lock.release()


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    scheduler = BackgroundScheduler()
    scheduler.add_job(_do_collect, "interval", minutes=config.COLLECT_INTERVAL_MIN,
                      id="collect", coalesce=True, max_instances=1)
    scheduler.add_job(_do_watch, "interval", minutes=config.WATCH_INTERVAL_MIN,
                      id="watch", coalesce=True, max_instances=1)
    scheduler.start()
    if config.COLLECT_ON_STARTUP:
        threading.Thread(target=_do_collect, daemon=True).start()
    if config.WATCH_ON_STARTUP:
        threading.Thread(target=_do_watch, daemon=True).start()
    yield
    scheduler.shutdown(wait=False)


app = FastAPI(title="POC Scoring Vulnérabilités — LPB Conseil", lifespan=lifespan)


def _run_or_404(con):
    run = db.latest_finished_run(con)
    if run is None:
        raise HTTPException(404, "Aucune collecte terminée — patienter ou déclencher POST /api/collect")
    return run


@app.get("/api/meta")
def meta():
    with db.connect() as con:
        run = db.latest_finished_run(con)
        return {
            "interval_min": config.COLLECT_INTERVAL_MIN,
            "collecting": _collect_lock.locked(),
            "last_run": dict(run) if run else None,
        }


@app.post("/api/collect")
def trigger_collect():
    if _collect_lock.locked():
        return {"started": False, "reason": "collecte déjà en cours"}
    threading.Thread(target=_do_collect, daemon=True).start()
    return {"started": True}


@app.post("/api/baseline")
def pin_baseline(run_id: Optional[int] = None):
    """Épingle un run comme baseline de comparaison.
    Sans paramètre, utilise le dernier run OK."""
    with db.connect() as con:
        if run_id is not None:
            row = con.execute(
                "SELECT * FROM collect_runs WHERE id=? AND status='ok'", (run_id,)
            ).fetchone()
            if row is None:
                raise HTTPException(404, "Run introuvable ou non terminé avec succès")
        else:
            row = db.latest_finished_run(con)
            if row is None:
                raise HTTPException(404, "Aucun run terminé disponible")
        db.set_baseline(con, row["id"])
        return {"baseline_run_id": row["id"], "finished_at": row["finished_at"]}


@app.get("/api/progress")
def progress():
    """Diff entre la baseline épinglée et le dernier run OK.
    Retourne CVEs résolues (présentes en baseline, absentes aujourd'hui)
    et CVEs nouvelles (absentes en baseline, présentes aujourd'hui)."""
    with db.connect() as con:
        baseline = db.get_baseline_run(con)
        current = db.latest_finished_run(con)

        if baseline is None or current is None:
            return {"baseline": None, "current": dict(current) if current else None,
                    "delta": None, "resolved": [], "new_cves": []}

        baseline_id = baseline["id"]
        current_id = current["id"]

        if baseline_id == current_id:
            kpi = con.execute(
                "SELECT ROUND(SUM(score),1) AS total FROM vulnerabilities WHERE run_id=?",
                (current_id,)
            ).fetchone()
            score_val = kpi["total"] or 0.0
            return {
                "baseline": dict(baseline), "current": dict(current),
                "delta": {"resolved_count": 0, "new_count": 0,
                          "score_baseline": score_val, "score_current": score_val,
                          "delta_score": 0.0, "delta_pct": 0.0},
                "resolved": [], "new_cves": [],
            }

        bl_rows = con.execute(
            """SELECT a.itop_name AS asset, v.cve, v.cvss, v.package, v.score, v.bucket
               FROM vulnerabilities v JOIN assets a ON a.id=v.asset_id
               WHERE v.run_id=?""", (baseline_id,)
        ).fetchall()

        curr_rows = con.execute(
            """SELECT a.itop_name AS asset, v.cve, v.cvss, v.package, v.score, v.bucket
               FROM vulnerabilities v JOIN assets a ON a.id=v.asset_id
               WHERE v.run_id=?""", (current_id,)
        ).fetchall()

        if not bl_rows:
            return {
                "baseline": dict(baseline), "current": dict(current),
                "delta": None, "resolved": [], "new_cves": [],
                "warning": "Détails de la baseline non disponibles (données purgées).",
            }

        bl_set = {(r["asset"], r["cve"]) for r in bl_rows}
        curr_set = {(r["asset"], r["cve"]) for r in curr_rows}

        resolved_keys = bl_set - curr_set
        new_keys = curr_set - bl_set

        resolved = [dict(r) for r in bl_rows if (r["asset"], r["cve"]) in resolved_keys]
        new_cves = [dict(r) for r in curr_rows if (r["asset"], r["cve"]) in new_keys]

        score_baseline = sum(r["score"] or 0 for r in bl_rows)
        score_current = sum(r["score"] or 0 for r in curr_rows)
        delta_score = round(score_current - score_baseline, 1)
        delta_pct = round(delta_score / score_baseline * 100, 1) if score_baseline else 0.0

        return {
            "baseline": dict(baseline),
            "current": dict(current),
            "delta": {
                "resolved_count": len(resolved_keys),
                "new_count": len(new_keys),
                "score_baseline": round(score_baseline, 1),
                "score_current": round(score_current, 1),
                "delta_score": delta_score,
                "delta_pct": delta_pct,
            },
            "resolved": resolved[:500],
            "new_cves": new_cves[:500],
        }


@app.get("/api/summary")
def summary():
    with db.connect() as con:
        run = _run_or_404(con)
        kpi = con.execute(
            """SELECT COUNT(*) AS vulns, COUNT(score) AS scored,
                      MAX(score) AS max_score, ROUND(AVG(score),1) AS avg_score
               FROM vulnerabilities WHERE run_id=?""", (run["id"],)).fetchone()
        buckets = {r["bucket"]: r["n"] for r in con.execute(
            "SELECT bucket, COUNT(*) AS n FROM vulnerabilities WHERE run_id=? GROUP BY bucket",
            (run["id"],))}
        assets = con.execute(
            """SELECT COUNT(*) AS total,
                      SUM(CASE WHEN wazuh_agent IS NOT NULL THEN 1 ELSE 0 END) AS monitored,
                      SUM(CASE WHEN c IS NOT NULL AND d IS NOT NULL AND i IS NOT NULL THEN 1 ELSE 0 END) AS evaluated
               FROM assets""").fetchone()
        return {"run": dict(run), "kpi": dict(kpi), "buckets": buckets, "assets": dict(assets)}


def _exposure_map(con) -> dict:
    """{asset_id: (facteur, palier)} — resolu depuis exposure.yaml."""
    return {r["id"]: exposure.resolve(r["itop_name"], r["ip"])
            for r in con.execute("SELECT id, itop_name, ip FROM assets")}


def _effective_thresholds(con, run_id: int, profile: Optional[str], with_exposure: bool) -> dict:
    """Seuils effectifs pour ce cycle. La population de reference du profil
    percentile suit le mode d'affichage : seuils calcules sur les scores
    reellement affiches, sinon la comparaison n'a pas de sens."""
    exp = _exposure_map(con) if with_exposure else {}
    pop = []
    for r in con.execute(
            "SELECT asset_id, score FROM vulnerabilities WHERE run_id=? AND score IS NOT NULL",
            (run_id,)):
        s = r["score"]
        if with_exposure:
            s = round(s * exp.get(r["asset_id"], (1.0, "inconnu"))[0], 1)
        pop.append(s)
    return thresholds.resolve(profile, pop)


@app.get("/api/thresholds")
def get_thresholds(profile: Optional[str] = None, exposition: bool = False):
    """Profils de seuils disponibles + seuils effectifs et distribution obtenue.

    Sert la slide de calibrage : les deux lectures cote a cote, chacune avec sa
    justification, sans qu'aucune ne soit imposee.
    """
    with db.connect() as con:
        run = _run_or_404(con)
        exp = _exposure_map(con)
        scores = [(r["asset_id"], r["score"]) for r in con.execute(
            "SELECT asset_id, score FROM vulnerabilities WHERE run_id=? AND score IS NOT NULL",
            (run["id"],))]
        out = {"run_id": run["id"], "actif": profile or thresholds.default_profile(),
               "exposition": exposition, "profils": []}
        for name, prof in thresholds.profiles().items():
            for with_exp in (False, True):
                pop = [round(s * exp.get(aid, (1.0, ""))[0], 1) if with_exp else s
                       for aid, s in scores]
                eff = thresholds.resolve(name, pop)
                dist = {}
                for s in pop:
                    b = thresholds.bucket(s, eff["seuils"])
                    dist[b] = dist.get(b, 0) + 1
                out["profils"].append({**eff, "exposition": with_exp,
                                       "distribution": dist, "total": len(pop)})
        return out


@app.get("/api/scores")
def scores(profile: Optional[str] = None):
    """Vue principale : lignes actif × CVE, triables côté front.

    Chaque ligne porte les deux lectures : score V1.1 (sans exposition, tel que
    stocke) et score V1.2 (avec le facteur d'exposition reseau), plus le bucket
    correspondant au profil de seuils demande. Rien n'est recalcule en base.
    """
    with db.connect() as con:
        run = _run_or_404(con)
        exp = _exposure_map(con)
        eff_base = _effective_thresholds(con, run["id"], profile, with_exposure=False)
        eff_exp = _effective_thresholds(con, run["id"], profile, with_exposure=True)
        rows = con.execute(
            """SELECT v.id, a.id AS asset_id, a.itop_name AS asset, a.wazuh_agent, a.ip,
                      a.c, a.d, a.i, a.vm, a.parent_activities,
                      v.cve, v.cvss, v.severity_wazuh, v.package, v.score, v.bucket
               FROM vulnerabilities v JOIN assets a ON a.id = v.asset_id
               WHERE v.run_id=? ORDER BY v.score DESC NULLS LAST""", (run["id"],)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            factor, tier = exp.get(d["asset_id"], (1.0, "inconnu"))
            d["exposure"] = factor
            d["exposure_tier"] = tier
            d["exposure_label"] = exposure.label(tier)
            d["score_exp"] = round(d["score"] * factor, 1) if d["score"] is not None else None
            d["bucket_profil"] = thresholds.bucket(d["score"], eff_base["seuils"])
            d["bucket_exp"] = thresholds.bucket(d["score_exp"], eff_exp["seuils"])
            out.append(d)
        return {"seuils": {"sans_exposition": eff_base, "avec_exposition": eff_exp},
                "lignes": out}


@app.get("/api/assets")
def assets():
    with db.connect() as con:
        run = _run_or_404(con)
        rows = con.execute(
            """SELECT a.id, a.itop_name, a.wazuh_agent, a.ip, a.org, a.host, a.c, a.d, a.i, a.vm,
                      s.vuln_count, s.max_score, s.avg_score, s.sum_score
               FROM assets a LEFT JOIN snapshots s ON s.asset_id = a.id AND s.run_id=?
               ORDER BY s.max_score DESC NULLS LAST, a.itop_name""", (run["id"],)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            factor, tier = exposure.resolve(d["itop_name"], d["ip"])
            d["exposure"] = factor
            d["exposure_tier"] = tier
            d["exposure_label"] = exposure.label(tier)
            for col in ("max_score", "avg_score", "sum_score"):
                d[f"{col}_exp"] = round(d[col] * factor, 1) if d[col] is not None else None
            out.append(d)
        out.sort(key=lambda d: (d["max_score_exp"] is None, -(d["max_score_exp"] or 0)))
        return out


@app.get("/api/assets/{asset_id}")
def asset_detail(asset_id: int):
    with db.connect() as con:
        run = _run_or_404(con)
        asset = con.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone()
        if asset is None:
            raise HTTPException(404, "Actif inconnu")
        vulns = con.execute(
            """SELECT cve, cvss, severity_wazuh, package, score, bucket
               FROM vulnerabilities WHERE run_id=? AND asset_id=? ORDER BY score DESC NULLS LAST""",
            (run["id"], asset_id)).fetchall()
        return {"asset": dict(asset), "vulnerabilities": [dict(v) for v in vulns]}


@app.get("/api/history")
def history():
    """Tendance : agrégats globaux par run terminé."""
    with db.connect() as con:
        rows = con.execute(
            """SELECT r.id, r.finished_at, r.status, r.is_baseline,
                      SUM(s.vuln_count) AS vulns, MAX(s.max_score) AS max_score,
                      ROUND(AVG(s.avg_score),1) AS avg_score, ROUND(SUM(s.sum_score),1) AS sum_score
               FROM collect_runs r JOIN snapshots s ON s.run_id = r.id
               WHERE r.status != 'running'
               GROUP BY r.id ORDER BY r.id""").fetchall()
        return [dict(r) for r in rows]


# ─── V2 : Matrice de risques dynamique ───────────────────────────────────────

@app.get("/api/risks")
def risks():
    """Liste les scénarios avec position d'origine, courante, plancher, delta (G1, G5)."""
    with db.connect() as con:
        run = db.latest_finished_run(con)
        run_id = run["id"] if run else None

        rows = con.execute(
            "SELECT id, name, ref, likelihood_origin, gravity_origin, "
            "       vg_inferred, current_level FROM risk_scenarios ORDER BY ref"
        ).fetchall()

        if not rows:
            return {"warning": "Aucun scénario de risque — lancer une collecte", "scenarios": []}

        out = []
        for s in rows:
            sid = s["id"]

            # Position courante depuis le dernier run
            pos = None
            if run_id:
                pos = con.execute(
                    "SELECT likelihood_current, gravity_current, floor_applied, "
                    "       floor_value, incomplete FROM risk_positions "
                    "WHERE run_id=? AND scenario_id=?",
                    (run_id, sid)
                ).fetchone()

            # Actifs supports
            assets = [r["asset_name"] for r in con.execute(
                "SELECT asset_name FROM risk_assets WHERE scenario_id=? ORDER BY asset_name",
                (sid,)
            ).fetchall()]

            # Nombre d'effets actifs
            active_effects = con.execute(
                "SELECT COUNT(*) AS n FROM risk_effects WHERE scenario_id=? AND active=1",
                (sid,)
            ).fetchone()["n"]

            out.append({
                "id": sid, "name": s["name"], "ref": s["ref"],
                "likelihood_origin": s["likelihood_origin"],
                "gravity_origin":    s["gravity_origin"],
                "vg_inferred":       bool(s["vg_inferred"]),
                "current_level":     s["current_level"],
                "assets":            assets,
                "active_effects":    active_effects,
                **(dict(pos) if pos else {
                    "likelihood_current": None, "gravity_current": None,
                    "floor_applied": False, "floor_value": None, "incomplete": True,
                }),
            })
        return {"scenarios": out, "run_id": run_id}


@app.get("/api/risks/{scenario_id}/journal")
def risk_journal(scenario_id: str):
    """Journal daté des effets — traçabilité G1."""
    with db.connect() as con:
        scen = con.execute(
            "SELECT id, name, ref FROM risk_scenarios WHERE id=?", (scenario_id,)
        ).fetchone()
        if not scen:
            raise HTTPException(404, "Scénario inconnu")

        effects = con.execute(
            """SELECT e.id, e.axis, e.delta, e.curve, e.starts_at, e.decays_at,
                      e.expires_at, e.active, e.label,
                      ev.type, ev.source, ev.ref AS event_ref, ev.level, ev.occurred_at, ev.detail
               FROM risk_effects e JOIN risk_events ev ON ev.id = e.event_id
               WHERE e.scenario_id=?
               ORDER BY ev.occurred_at DESC""",
            (scenario_id,)
        ).fetchall()

        return {
            "scenario": dict(scen),
            "journal": [dict(r) for r in effects],
        }


@app.get("/api/risks/{scenario_id}/trajectory")
def risk_trajectory(scenario_id: str):
    """Positions historisées par run — traîne de la bulle."""
    with db.connect() as con:
        scen = con.execute(
            "SELECT id, name, ref, likelihood_origin, gravity_origin FROM risk_scenarios WHERE id=?",
            (scenario_id,)
        ).fetchone()
        if not scen:
            raise HTTPException(404, "Scénario inconnu")

        traj = con.execute(
            """SELECT p.run_id, r.finished_at, p.likelihood_current, p.gravity_current,
                      p.floor_applied, p.floor_value, p.incomplete
               FROM risk_positions p JOIN collect_runs r ON r.id = p.run_id
               WHERE p.scenario_id=? ORDER BY p.run_id""",
            (scenario_id,)
        ).fetchall()

        return {
            "scenario": dict(scen),
            "trajectory": [dict(r) for r in traj],
        }


# ─── Veille CVE NVD ──────────────────────────────────────────────────────────

@app.get("/api/watch")
def watch_news(limit: int = 200, unseen_only: bool = False):
    """Flux d'actualité CVE des actifs surveillés, plus récentes d'abord."""
    with db.connect() as con:
        q = """SELECT id, asset_name, cve, cvss, severity, summary,
                      published_at, modified_at, url, collected_at, seen
               FROM watch_news"""
        if unseen_only:
            q += " WHERE seen=0"
        q += " ORDER BY published_at DESC LIMIT ?"
        rows = con.execute(q, (min(limit, 1000),)).fetchall()

        unseen = con.execute(
            "SELECT COUNT(*) AS n FROM watch_news WHERE seen=0").fetchone()["n"]
        return {"news": [dict(r) for r in rows], "unseen": unseen}


@app.get("/api/watch/status")
def watch_status():
    """État des abonnements : requête, dernier poll, statut, volume par actif."""
    with db.connect() as con:
        rows = con.execute(
            """SELECT s.asset_name, s.query_type, s.query_value,
                      s.last_checked, s.last_status, s.news_count,
                      (SELECT COUNT(*) FROM watch_news w
                        WHERE w.asset_name = s.asset_name AND w.seen=0) AS unseen
               FROM watch_state s ORDER BY s.asset_name"""
        ).fetchall()
        return {"items": [dict(r) for r in rows],
                "interval_min": config.WATCH_INTERVAL_MIN,
                "watching": _watch_lock.locked()}


@app.post("/api/watch/run")
def trigger_watch():
    """Déclenche un cycle de veille manuellement."""
    if _watch_lock.locked():
        return {"started": False, "reason": "veille déjà en cours"}
    threading.Thread(target=_do_watch, daemon=True).start()
    return {"started": True}


@app.post("/api/watch/seen")
def mark_seen(news_id: Optional[int] = None):
    """Marque une news (ou toutes) comme lue(s)."""
    with db.connect() as con:
        if news_id is not None:
            con.execute("UPDATE watch_news SET seen=1 WHERE id=?", (news_id,))
        else:
            con.execute("UPDATE watch_news SET seen=1")
        return {"ok": True}


@app.get("/api/tuning")
def get_tuning():
    """Expose risk_tuning.yaml en JSON pour affichage règles de calcul (G3)."""
    tuning_file = Path(__file__).resolve().parent / "risk_tuning.yaml"
    if not tuning_file.exists():
        return {}
    with open(tuning_file, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


# ─── Mode démo ───────────────────────────────────────────────────────────────
# Injections marquées source='demo' (events) et url='#demo' (news) : isolées
# des données réelles, purgées par /api/demo/reset. G4 respecté : la position
# d'origine n'est jamais touchée — seuls des effets s'ajoutent/se retirent.

def _recompute_scenario(con, sid: str) -> None:
    """Recalcule la position courante d'un scénario pour le dernier run."""
    run = db.latest_finished_run(con)
    if run is None:
        return
    s = con.execute("SELECT * FROM risk_scenarios WHERE id=?", (sid,)).fetchone()
    if s is None:
        return

    rows = con.execute(
        """SELECT id, event_id, scenario_id, axis, delta, curve,
                  starts_at, full_at, decays_at, expires_at, active, label
           FROM risk_effects WHERE scenario_id=? AND active=1""", (sid,)
    ).fetchall()
    effects = [risk_engine.EffectData(
        id=r["id"], event_id=r["event_id"], scenario_id=r["scenario_id"],
        axis=r["axis"], delta=r["delta"], curve=r["curve"],
        starts_at=r["starts_at"], full_at=r["full_at"],
        decays_at=r["decays_at"], expires_at=r["expires_at"],
        active=bool(r["active"]), label=r["label"] or "",
    ) for r in rows]

    tuning = get_tuning()

    max_score = None
    for ar in con.execute(
            "SELECT asset_name FROM risk_assets WHERE scenario_id=?", (sid,)).fetchall():
        for a in con.execute(
                "SELECT id FROM assets WHERE LOWER(itop_name) LIKE ?",
                (f"%{ar['asset_name'].lower()[:12]}%",)).fetchall():
            r = con.execute(
                "SELECT MAX(score) AS ms FROM vulnerabilities WHERE asset_id=? AND run_id=?",
                (a["id"], run["id"])).fetchone()
            if r and r["ms"] is not None:
                max_score = max(max_score or 0, r["ms"])

    scen = risk_engine.ScenarioData(
        id=sid, name=s["name"],
        likelihood_origin=s["likelihood_origin"], gravity_origin=s["gravity_origin"],
        vg_inferred=bool(s["vg_inferred"]),
    )
    now = datetime.now(timezone.utc)
    pos = risk_engine.compute_position(scen, effects, tuning.get("floor", []), max_score, now)
    con.execute("""
        INSERT INTO risk_positions
            (run_id, scenario_id, likelihood_current, gravity_current,
             floor_applied, floor_value, incomplete, computed_at)
        VALUES (?,?,?,?,?,?,?,?)
        ON CONFLICT(run_id, scenario_id) DO UPDATE SET
            likelihood_current=excluded.likelihood_current,
            gravity_current=excluded.gravity_current,
            floor_applied=excluded.floor_applied,
            floor_value=excluded.floor_value,
            incomplete=excluded.incomplete,
            computed_at=excluded.computed_at
    """, (run["id"], sid, pos["likelihood_current"], pos["gravity_current"],
          int(pos["floor_applied"]), pos["floor_value"],
          int(pos["incomplete"]), now.isoformat()))


@app.post("/api/demo/inject")
def demo_inject(scenario_id: Optional[str] = None):
    """Injecte une fausse CVE critique sur un scénario (matrice + veille)."""
    now = datetime.now(timezone.utc)
    with db.connect() as con:
        if scenario_id:
            s = con.execute(
                "SELECT id, name, ref FROM risk_scenarios WHERE id=?",
                (scenario_id,)).fetchone()
        else:
            s = con.execute(
                """SELECT rs.id, rs.name, rs.ref FROM risk_scenarios rs
                   WHERE EXISTS (SELECT 1 FROM risk_assets ra WHERE ra.scenario_id=rs.id)
                   ORDER BY rs.ref LIMIT 1""").fetchone() \
                or con.execute(
                "SELECT id, name, ref FROM risk_scenarios ORDER BY ref LIMIT 1").fetchone()
        if s is None:
            raise HTTPException(404, "Aucun scénario de risque — lancer une collecte d'abord")

        arow = con.execute(
            "SELECT asset_name FROM risk_assets WHERE scenario_id=? ORDER BY asset_name LIMIT 1",
            (s["id"],)).fetchone()
        asset = arow["asset_name"] if arow else "actif de démonstration"

        cve = f"CVE-2026-{random.randint(10000, 99999)}"
        tuning = get_tuning()
        cfg = tuning.get("effects", {}).get("watch_vuln", {})
        delta   = cfg.get("delta", 1)
        plateau = cfg.get("plateau_days", 14)
        decay   = cfg.get("decay_days", 45)

        cur = con.execute(
            """INSERT INTO risk_events (scenario_id, type, source, ref, level, occurred_at, detail)
               VALUES (?,?,?,?,?,?,?)""",
            (s["id"], "watch_vuln", "demo", cve, 9.8, now.isoformat(),
             json.dumps({"asset": asset, "demo": True})))
        con.execute(
            """INSERT INTO risk_effects
                 (event_id, scenario_id, axis, delta, curve, starts_at, decays_at, expires_at, active, label)
               VALUES (?,?,?,?,?,?,?,?,1,?)""",
            (cur.lastrowid, s["id"], "likelihood", delta, "plateau_decay",
             now.isoformat(),
             (now + timedelta(days=plateau)).isoformat(),
             (now + timedelta(days=plateau + decay)).isoformat(),
             f"🎬 DÉMO — +{delta} vraisemblance : {cve} (CVSS 9.8) sur {asset}"))
        con.execute(
            """INSERT OR IGNORE INTO watch_news
                 (asset_name, cve, cvss, severity, summary,
                  published_at, modified_at, url, collected_at, seen)
               VALUES (?,?,?,?,?,?,?,?,?,0)""",
            (asset, cve, 9.8, "CRITICAL",
             "Exécution de code à distance sans authentification (injection de DÉMONSTRATION — "
             "cette CVE n'existe pas, elle illustre le flux veille → matrice de risques).",
             now.isoformat(), now.isoformat(), "#demo", now.isoformat()))

        _recompute_scenario(con, s["id"])
        return {"ok": True, "scenario_id": s["id"], "ref": s["ref"],
                "name": s["name"], "asset": asset, "cve": cve}


@app.post("/api/demo/patch")
def demo_patch():
    """Simule le correctif vérifié par le scan : désactive les effets démo."""
    with db.connect() as con:
        sids = [r["scenario_id"] for r in con.execute(
            "SELECT DISTINCT scenario_id FROM risk_events WHERE source='demo'").fetchall()]
        if not sids:
            return {"ok": False, "reason": "aucune injection démo active"}
        con.execute(
            "UPDATE risk_effects SET active=0 "
            "WHERE event_id IN (SELECT id FROM risk_events WHERE source='demo')")
        con.execute("UPDATE watch_news SET seen=1 WHERE url='#demo'")
        for sid in sids:
            _recompute_scenario(con, sid)
        return {"ok": True, "scenarios": len(sids)}


@app.post("/api/demo/reset")
def demo_reset():
    """Purge toute trace de la démo (events, effets, news) et recalcule."""
    with db.connect() as con:
        sids = [r["scenario_id"] for r in con.execute(
            "SELECT DISTINCT scenario_id FROM risk_events WHERE source='demo'").fetchall()]
        con.execute(
            "DELETE FROM risk_effects "
            "WHERE event_id IN (SELECT id FROM risk_events WHERE source='demo')")
        con.execute("DELETE FROM risk_events WHERE source='demo'")
        con.execute("DELETE FROM watch_news WHERE url='#demo'")
        for sid in sids:
            _recompute_scenario(con, sid)
        return {"ok": True, "scenarios": len(sids)}


# --- Front statique ---
STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def index():
    return FileResponse(STATIC_DIR / "index.html")
