"""Orchestration d'un cycle de collecte complet.

Chaîne : iTop (inventaire, pivot) -> CISO Assistant (C/D/I) -> Wazuh (CVEs)
-> réconciliation -> scoring -> persistance (run + vulnérabilités + snapshot).

Tolérance de panne : chaque source est collectée indépendamment ; un échec
partiel produit un run 'partial' et le front continue d'afficher le dernier
relevé complet.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

import config
import db
import risk_engine
from scoring import compute_score, severity_bucket
from collectors import itop_client, ciso_client
from collectors.wazuh_client import WazuhClient
from collectors import ciso_risks_client
from reconciliation import resolve

log = logging.getLogger(__name__)


def _load_tuning() -> dict:
    """Charge risk_tuning.yaml depuis le dossier dashboard/."""
    tuning_file = Path(__file__).resolve().parent.parent / "risk_tuning.yaml"
    if not tuning_file.exists():
        log.warning("risk_tuning.yaml introuvable — moteur de risques désactivé")
        return {}
    with open(tuning_file, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _collect_risks(con, run_id: int, tuning: dict) -> None:
    """Collecte V2 : scénarios CISO → events → effects → positions."""
    if not tuning:
        log.info("risk_tuning.yaml absent — collecte risques ignorée")
        return

    now     = datetime.now(timezone.utc)
    floor_t = tuning.get("floor", [])
    adm     = tuning.get("admission", {})
    vuln_min = adm.get("vuln_min_score", 60)
    eff_cfg  = tuning.get("effects", {})
    lvl_map  = tuning.get("level_to_vg", {})

    scenarios = ciso_risks_client.get_risk_scenarios()
    if not scenarios:
        log.info("Aucun scénario de risque CISO — collecte V2 ignorée")
        return

    for s in scenarios:
        sid   = s["id"]
        level = s.get("current_level", "unknown")

        # ── Upsert risk_scenario (G4 : ne pas écraser si vg_inferred=0 déjà renseigné) ──
        existing = con.execute(
            "SELECT likelihood_origin, gravity_origin, vg_inferred FROM risk_scenarios WHERE id=?",
            (sid,)
        ).fetchone()

        if existing and existing["vg_inferred"] == 0 and existing["likelihood_origin"] is not None:
            # G4 : valeur saisie manuellement, ne pas toucher
            lo, go, inferred = existing["likelihood_origin"], existing["gravity_origin"], False
        else:
            # Déduire V/G depuis le niveau textuel (vg_inferred=1)
            vg    = lvl_map.get(level, lvl_map.get("medium", {"v": 2, "g": 2}))
            lo, go, inferred = vg.get("v", 2), vg.get("g", 2), True

        con.execute("""
            INSERT INTO risk_scenarios (id, name, ref, likelihood_origin, gravity_origin,
                                        vg_inferred, current_level, assessment_id, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET
                name=excluded.name, ref=excluded.ref,
                current_level=excluded.current_level, assessment_id=excluded.assessment_id,
                updated_at=excluded.updated_at,
                likelihood_origin=CASE WHEN vg_inferred=0 THEN likelihood_origin ELSE excluded.likelihood_origin END,
                gravity_origin   =CASE WHEN vg_inferred=0 THEN gravity_origin    ELSE excluded.gravity_origin    END,
                vg_inferred      =CASE WHEN vg_inferred=0 THEN 0                 ELSE excluded.vg_inferred       END
        """, (sid, s["name"], s.get("ref",""), lo, go, int(inferred),
              level, s.get("assessment_id"), now.isoformat()))

        # ── Upsert risk_assets ──
        for aname in s.get("assets", []):
            con.execute(
                "INSERT OR IGNORE INTO risk_assets (scenario_id, asset_name) VALUES (?,?)",
                (sid, aname)
            )

        # ── Chercher les actifs supports instrumentés dans la DB ──
        asset_rows = []
        for aname in s.get("assets", []):
            rows = con.execute(
                "SELECT id, itop_name FROM assets WHERE LOWER(itop_name) LIKE ?",
                (f"%{aname.lower()[:12]}%",)
            ).fetchall()
            asset_rows.extend(rows)

        if not asset_rows:
            log.debug("Scénario %s — aucun actif instrumenté trouvé", s["name"][:40])

        # ── Score vuln max sur les actifs supports (pour plancher G2) ──
        max_score = None
        for ar in asset_rows:
            row = con.execute(
                """SELECT MAX(v.score) AS ms FROM vulnerabilities v
                   JOIN collect_runs r ON r.id=v.run_id
                   WHERE v.asset_id=? AND r.status='ok'
                   ORDER BY r.id DESC LIMIT 1""",
                (ar["id"],)
            ).fetchone()
            if row and row["ms"] is not None:
                max_score = max(max_score or 0, row["ms"])

        # ── Créer risk_events pour les nouvelles CVE critiques ──
        for ar in asset_rows:
            vuln_rows = con.execute(
                """SELECT v.cve, v.score FROM vulnerabilities v
                   JOIN collect_runs r ON r.id=v.run_id
                   WHERE v.asset_id=? AND v.score >= ? AND r.id=?""",
                (ar["id"], vuln_min, run_id)
            ).fetchall()

            for vrow in vuln_rows:
                # Dédupliquer : ne pas recréer un event si déjà présent pour ce scenario+cve
                already = con.execute(
                    "SELECT id FROM risk_events WHERE scenario_id=? AND ref=? AND type='new_vuln'",
                    (sid, vrow["cve"])
                ).fetchone()
                if already:
                    continue

                cfg = eff_cfg.get("new_vuln", {})
                plateau = cfg.get("plateau_days", 7)
                decay   = cfg.get("decay_days", 30)
                delta   = cfg.get("delta", 1)

                cur = con.execute("""
                    INSERT INTO risk_events (scenario_id, type, source, ref, level, occurred_at, detail)
                    VALUES (?,?,?,?,?,?,?)
                """, (sid, "new_vuln", "wazuh", vrow["cve"], vrow["score"],
                      now.isoformat(),
                      json.dumps({"asset": ar["itop_name"], "score": vrow["score"]})))
                event_id = cur.lastrowid

                decays_at  = (now + timedelta(days=plateau)).isoformat()
                expires_at = (now + timedelta(days=plateau + decay)).isoformat()
                label = f"+{delta} vraisemblance : CVE {vrow['cve']} sur {ar['itop_name']} (score {vrow['score']:.0f})"
                con.execute("""
                    INSERT INTO risk_effects
                        (event_id, scenario_id, axis, delta, curve, starts_at, decays_at, expires_at, active, label)
                    VALUES (?,?,?,?,?,?,?,?,1,?)
                """, (event_id, sid, "likelihood", delta, "plateau_decay",
                      now.isoformat(), decays_at, expires_at, label))

        # ── Compute position ──
        effect_rows = con.execute(
            """SELECT id, event_id, scenario_id, axis, delta, curve,
                      starts_at, full_at, decays_at, expires_at, active, label
               FROM risk_effects WHERE scenario_id=? AND active=1""",
            (sid,)
        ).fetchall()

        effects = [
            risk_engine.EffectData(
                id=r["id"], event_id=r["event_id"], scenario_id=r["scenario_id"],
                axis=r["axis"], delta=r["delta"], curve=r["curve"],
                starts_at=r["starts_at"], full_at=r["full_at"],
                decays_at=r["decays_at"], expires_at=r["expires_at"],
                active=bool(r["active"]), label=r["label"] or "",
            )
            for r in effect_rows
        ]

        scen = risk_engine.ScenarioData(
            id=sid, name=s["name"],
            likelihood_origin=lo, gravity_origin=go,
            vg_inferred=inferred,
        )

        pos = risk_engine.compute_position(scen, effects, floor_t, max_score, now)

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
        """, (run_id, sid,
              pos["likelihood_current"], pos["gravity_current"],
              int(pos["floor_applied"]), pos["floor_value"],
              int(pos["incomplete"]), now.isoformat()))

    log.info("Collecte V2 terminée : %d scénarios positionnés", len(scenarios))


def _load_mapping() -> tuple[dict, dict]:
    with open(config.MAPPING_FILE, encoding="utf-8") as f:
        m = yaml.safe_load(f) or {}
    return m.get("itop_to_wazuh") or {}, m.get("ciso_aliases") or {}


def run() -> dict:
    """Exécute un cycle. Retourne un résumé {run_id, status, counts...}."""
    itop_to_wazuh, ciso_aliases = _load_mapping()
    itop_ok = wazuh_ok = ciso_ok = False
    errors: list[str] = []

    # --- 1. iTop : inventaire (pivot) ---
    vms: list[dict] = []
    try:
        vms = itop_client.get_vms()
        itop_ok = True
    except Exception as e:
        log.exception("Échec collecte iTop")
        errors.append(f"iTop: {e}")

    # --- 2. CISO Assistant : C/D/I ---
    cdi_by_name: dict = {}
    try:
        cdi_by_name = ciso_client.get_assets_cdi()
        ciso_ok = True
    except Exception as e:
        log.exception("Échec collecte CISO Assistant")
        errors.append(f"CISO: {e}")

    # --- 3. Wazuh : agents + vulnérabilités (token frais pour ce cycle) ---
    agents_by_name: dict = {}
    wazuh = WazuhClient()
    try:
        wazuh.authenticate()
        agents_by_name = {a["name"]: a for a in wazuh.get_agents()}
        wazuh_ok = True
    except Exception as e:
        log.exception("Échec collecte Wazuh")
        errors.append(f"Wazuh: {e}")

    # --- 3bis. Arbitrage des collisions d'agents -----------------------------
    # Plusieurs entrées iTop peuvent se résoudre vers le MÊME agent Wazuh (cas
    # constaté : PB-VM-PORTAINER et lpb-srv-portainer-azure). Sans arbitrage,
    # les mêmes CVE sont comptées deux fois et tous les agrégats sont gonflés.
    # Règle : le nom iTop identique au nom de l'agent gagne ; sinon le premier
    # par ordre alphabétique (déterministe). Les perdants sont inventoriés et
    # remontés dans les erreurs du cycle — jamais écartés silencieusement (G5).
    agent_owner: dict[str, str] = {}
    resolved_agents: dict[str, str | None] = {}
    for vm in vms:
        name = vm.get("name")
        if not name:
            continue
        agent_name = resolve(
            name, list(agents_by_name), overrides=itop_to_wazuh, context="itop→wazuh"
        )
        resolved_agents[name] = agent_name
        if not agent_name:
            continue
        incumbent = agent_owner.get(agent_name)
        if incumbent is None:
            agent_owner[agent_name] = name
        elif name.lower() == agent_name.lower():
            agent_owner[agent_name] = name          # correspondance exacte prioritaire
        elif incumbent.lower() != agent_name.lower() and name < incumbent:
            agent_owner[agent_name] = name          # départage déterministe

    for agent_name, winner in agent_owner.items():
        losers = [n for n, a in resolved_agents.items() if a == agent_name and n != winner]
        if losers:
            msg = (f"collision agent {agent_name} : {winner} retenu, "
                   f"{', '.join(sorted(losers))} ignoré(s) pour éviter le double comptage")
            log.warning(msg)
            errors.append(msg)

    # --- 4. Réconciliation + scoring + persistance ---
    n_vulns = n_scored = 0
    with db.connect() as con:
        run_id = db.start_run(con)

        for vm in vms:
            name = vm["name"]
            if not name:
                continue
            agent_name = resolved_agents.get(name)
            if agent_name and agent_owner.get(agent_name) != name:
                agent_name = None       # agent déjà consommé par un autre actif iTop
            ciso_key = resolve(
                name, list(cdi_by_name),
                overrides={k: v.lower() for k, v in ciso_aliases.items()},
                context="itop→ciso",
            ) or name.lower()
            cdi = cdi_by_name.get(ciso_key, {})
            asset_id = db.upsert_asset(
                con, name,
                ip=vm.get("ip"), org=vm.get("org"), host=vm.get("host"),
                wazuh_agent=agent_name,
                c=cdi.get("c"), d=cdi.get("d"), i=cdi.get("i"),
                vm=cdi.get("vm"),
                parent_activities=cdi.get("parent_activities"),
            )

            agent = agents_by_name.get(agent_name) if agent_name else None
            if not (wazuh_ok and agent):
                continue

            try:
                vulns = wazuh.get_vulnerabilities(agent)
            except Exception as e:
                log.warning("Vulnérabilités indisponibles pour %s : %s", agent_name, e)
                errors.append(f"vulns {agent_name}: {e}")
                continue

            scores = []
            for v in vulns:
                score = None
                try:
                    score = compute_score(v["cvss"], cdi.get("c"), cdi.get("d"), cdi.get("i"),
                                          vm=cdi.get("vm"))
                except ValueError as e:
                    log.warning("Score invalide %s/%s : %s", name, v["cve"], e)
                con.execute(
                    "INSERT INTO vulnerabilities (run_id, asset_id, cve, cvss, severity_wazuh, package, score, bucket)"
                    " VALUES (?,?,?,?,?,?,?,?)",
                    (run_id, asset_id, v["cve"], v["cvss"], v["severity"], v["package"],
                     score, severity_bucket(score)),
                )
                n_vulns += 1
                if score is not None:
                    scores.append(score)
                    n_scored += 1

            con.execute(
                "INSERT INTO snapshots (run_id, asset_id, vuln_count, max_score, avg_score, sum_score)"
                " VALUES (?,?,?,?,?,?)",
                (run_id, asset_id, len(vulns),
                 max(scores) if scores else None,
                 round(sum(scores) / len(scores), 1) if scores else None,
                 round(sum(scores), 1) if scores else None),
            )

        # --- 5. V2 : matrice de risques dynamique ---
        try:
            tuning = _load_tuning()
            _collect_risks(con, run_id, tuning)
        except Exception as e:
            log.exception("Échec collecte V2 risques (non bloquant)")
            errors.append(f"risks_v2: {e}")

        db.finish_run(con, run_id, itop_ok=itop_ok, wazuh_ok=wazuh_ok, ciso_ok=ciso_ok,
                      message=" | ".join(errors)[:1000])

    summary = {
        "run_id": run_id,
        "itop_ok": itop_ok, "wazuh_ok": wazuh_ok, "ciso_ok": ciso_ok,
        "vms": len(vms), "vulnerabilites": n_vulns, "scores_calcules": n_scored,
        "erreurs": errors,
    }
    log.info("Cycle terminé : %s", summary)
    return summary


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    db.init_db()
    print(run())
