"""Persistance SQLite — relevés horodatés (snapshots) pour vue courante + historique."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

from config import DB_PATH

SCHEMA = """
CREATE TABLE IF NOT EXISTS collect_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL DEFAULT 'running',  -- running | ok | partial | error
    itop_ok     INTEGER DEFAULT 0,
    wazuh_ok    INTEGER DEFAULT 0,
    ciso_ok     INTEGER DEFAULT 0,
    is_baseline INTEGER DEFAULT 0,
    message     TEXT
);

CREATE TABLE IF NOT EXISTS assets (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    itop_name           TEXT NOT NULL UNIQUE,
    wazuh_agent         TEXT,
    ip                  TEXT,
    org                 TEXT,
    host                TEXT,               -- noeud Proxmox (virtualhost)
    c                   INTEGER,            -- criticité Confidentialité (0-4)
    d                   INTEGER,            -- criticité Disponibilité (0-4)
    i                   INTEGER,            -- criticité Intégrité (0-4)
    vm                  REAL,               -- criticité valeur métier portée (0-4) — formule V1.1
    parent_activities   TEXT,               -- JSON: activités primaires CISO portées par cet actif
    updated_at          TEXT
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id    INTEGER NOT NULL REFERENCES collect_runs(id),
    asset_id  INTEGER NOT NULL REFERENCES assets(id),
    cve       TEXT NOT NULL,
    cvss      REAL,
    severity_wazuh TEXT,
    package   TEXT,
    score     REAL,                  -- NULL si C/D/I non évalués ou CVSS absent
    bucket    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_vulns_run ON vulnerabilities(run_id);

CREATE TABLE IF NOT EXISTS snapshots (
    run_id      INTEGER NOT NULL REFERENCES collect_runs(id),
    asset_id    INTEGER NOT NULL REFERENCES assets(id),
    vuln_count  INTEGER NOT NULL,
    max_score   REAL,
    avg_score   REAL,
    sum_score   REAL,
    PRIMARY KEY (run_id, asset_id)
);

-- ─── V2 : Matrice de risques dynamique ───────────────────────────────────────

CREATE TABLE IF NOT EXISTS risk_scenarios (
    id                   TEXT PRIMARY KEY,   -- UUID CISO Assistant
    name                 TEXT NOT NULL,
    ref                  TEXT,
    likelihood_origin    INTEGER,            -- 1-4, NULL si non renseigné (G5)
    gravity_origin       INTEGER,            -- 1-4, NULL si non renseigné (G5)
    vg_inferred          INTEGER DEFAULT 0,  -- 1 si déduit du niveau textuel, pas saisi
    current_level        TEXT,               -- "high" | "medium" | ...
    assessment_id        TEXT,
    updated_at           TEXT
);

CREATE TABLE IF NOT EXISTS risk_assets (
    scenario_id  TEXT NOT NULL REFERENCES risk_scenarios(id),
    asset_name   TEXT NOT NULL,
    PRIMARY KEY (scenario_id, asset_name)
);

CREATE TABLE IF NOT EXISTS risk_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_id  TEXT NOT NULL REFERENCES risk_scenarios(id),
    type         TEXT NOT NULL,  -- new_vuln | siem_alert | control_active | control_closed | remediation_verified | incident_closed
    source       TEXT,           -- "wazuh" | "ciso" | "manual"
    ref          TEXT,           -- CVE id, control id, etc.
    level        REAL,           -- CVSS ou niveau alerte
    occurred_at  TEXT NOT NULL,
    detail       TEXT            -- JSON libre
);

CREATE TABLE IF NOT EXISTS risk_effects (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     INTEGER NOT NULL REFERENCES risk_events(id),
    scenario_id  TEXT NOT NULL REFERENCES risk_scenarios(id),
    axis         TEXT NOT NULL,    -- "likelihood" | "gravity"
    delta        INTEGER NOT NULL,
    curve        TEXT NOT NULL DEFAULT 'plateau_decay',
    starts_at    TEXT NOT NULL,
    full_at      TEXT,
    decays_at    TEXT,
    expires_at   TEXT,
    active       INTEGER DEFAULT 1,
    label        TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_effects_scenario ON risk_effects(scenario_id, active);

CREATE TABLE IF NOT EXISTS risk_positions (
    run_id               INTEGER NOT NULL REFERENCES collect_runs(id),
    scenario_id          TEXT NOT NULL REFERENCES risk_scenarios(id),
    likelihood_current   INTEGER,
    gravity_current      INTEGER,
    floor_applied        INTEGER DEFAULT 0,
    floor_value          INTEGER,
    incomplete           INTEGER DEFAULT 0,
    computed_at          TEXT NOT NULL,
    PRIMARY KEY (run_id, scenario_id)
);

-- ─── Veille CVE NVD (actifs SaaS et produits) ────────────────────────────────

CREATE TABLE IF NOT EXISTS watch_state (
    asset_name    TEXT PRIMARY KEY,   -- nom CISO Assistant (clé de watch.yaml)
    query_type    TEXT NOT NULL,      -- 'cpe' | 'keywords'
    query_value   TEXT NOT NULL,
    last_checked  TEXT,               -- dernier poll réussi (borne du mode delta)
    last_status   TEXT,               -- 'ok' | 'error: ...'
    news_count    INTEGER DEFAULT 0   -- total de news collectées (info)
);

CREATE TABLE IF NOT EXISTS watch_news (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_name    TEXT NOT NULL,
    cve           TEXT NOT NULL,
    cvss          REAL,
    severity      TEXT,
    summary       TEXT,
    published_at  TEXT,
    modified_at   TEXT,
    url           TEXT,
    collected_at  TEXT NOT NULL,
    seen          INTEGER DEFAULT 0,
    UNIQUE (asset_name, cve)
);
CREATE INDEX IF NOT EXISTS idx_watch_news_asset ON watch_news(asset_name, seen);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connect():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    # timeout=30 : attendre le verrou au lieu d'échouer immédiatement
    # WAL : lectures concurrentes pendant les écritures (collecte + veille + API)
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA journal_mode = WAL")
    con.execute("PRAGMA busy_timeout = 30000")
    try:
        yield con
        con.commit()
    except Exception:
        con.rollback()
        raise
    finally:
        con.close()


def _migrate(con: sqlite3.Connection) -> None:
    """Migrations progressives — idempotentes."""
    run_cols = {r[1] for r in con.execute("PRAGMA table_info(collect_runs)").fetchall()}
    if "is_baseline" not in run_cols:
        con.execute("ALTER TABLE collect_runs ADD COLUMN is_baseline INTEGER DEFAULT 0")

    asset_cols = {r[1] for r in con.execute("PRAGMA table_info(assets)").fetchall()}
    if "parent_activities" not in asset_cols:
        con.execute("ALTER TABLE assets ADD COLUMN parent_activities TEXT")
    if "vm" not in asset_cols:
        con.execute("ALTER TABLE assets ADD COLUMN vm REAL")

    # V2 — tables créées via SCHEMA (CREATE TABLE IF NOT EXISTS), migration colonnes si besoin
    tables = {r[0] for r in con.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    ).fetchall()}
    if "risk_scenarios" not in tables:
        con.executescript("""
CREATE TABLE IF NOT EXISTS risk_scenarios (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, ref TEXT,
    likelihood_origin INTEGER, gravity_origin INTEGER,
    vg_inferred INTEGER DEFAULT 0, current_level TEXT,
    assessment_id TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS risk_assets (
    scenario_id TEXT NOT NULL REFERENCES risk_scenarios(id),
    asset_name TEXT NOT NULL, PRIMARY KEY (scenario_id, asset_name)
);
CREATE TABLE IF NOT EXISTS risk_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scenario_id TEXT NOT NULL REFERENCES risk_scenarios(id),
    type TEXT NOT NULL, source TEXT, ref TEXT, level REAL,
    occurred_at TEXT NOT NULL, detail TEXT
);
CREATE TABLE IF NOT EXISTS risk_effects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES risk_events(id),
    scenario_id TEXT NOT NULL REFERENCES risk_scenarios(id),
    axis TEXT NOT NULL, delta INTEGER NOT NULL,
    curve TEXT NOT NULL DEFAULT 'plateau_decay',
    starts_at TEXT NOT NULL, full_at TEXT, decays_at TEXT, expires_at TEXT,
    active INTEGER DEFAULT 1, label TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_effects_scenario ON risk_effects(scenario_id, active);
CREATE TABLE IF NOT EXISTS risk_positions (
    run_id INTEGER NOT NULL REFERENCES collect_runs(id),
    scenario_id TEXT NOT NULL REFERENCES risk_scenarios(id),
    likelihood_current INTEGER, gravity_current INTEGER,
    floor_applied INTEGER DEFAULT 0, floor_value INTEGER,
    incomplete INTEGER DEFAULT 0, computed_at TEXT NOT NULL,
    PRIMARY KEY (run_id, scenario_id)
);
        """)


def init_db() -> None:
    with connect() as con:
        con.executescript(SCHEMA)
        _migrate(con)


def start_run(con: sqlite3.Connection) -> int:
    cur = con.execute(
        "INSERT INTO collect_runs (started_at) VALUES (?)", (utcnow(),)
    )
    return cur.lastrowid


def finish_run(con, run_id: int, *, itop_ok: bool, wazuh_ok: bool, ciso_ok: bool, message: str = "") -> None:
    flags = [itop_ok, wazuh_ok, ciso_ok]
    status = "ok" if all(flags) else ("partial" if any(flags) else "error")
    con.execute(
        "UPDATE collect_runs SET finished_at=?, status=?, itop_ok=?, wazuh_ok=?, ciso_ok=?, message=? WHERE id=?",
        (utcnow(), status, int(itop_ok), int(wazuh_ok), int(ciso_ok), message, run_id),
    )


def upsert_asset(con, itop_name: str, **fields) -> int:
    """Insère ou met à jour un actif (pivot = nom iTop). Ne remet pas à NULL un champ non fourni."""
    con.execute(
        "INSERT INTO assets (itop_name, updated_at) VALUES (?, ?) ON CONFLICT(itop_name) DO NOTHING",
        (itop_name, utcnow()),
    )
    sets, vals = ["updated_at=?"], [utcnow()]
    for col in ("wazuh_agent", "ip", "org", "host", "c", "d", "i", "vm", "parent_activities"):
        if col in fields and fields[col] is not None:
            sets.append(f"{col}=?")
            vals.append(fields[col])
    vals.append(itop_name)
    con.execute(f"UPDATE assets SET {', '.join(sets)} WHERE itop_name=?", vals)
    row = con.execute("SELECT id FROM assets WHERE itop_name=?", (itop_name,)).fetchone()
    return row["id"]


def latest_finished_run(con) -> sqlite3.Row | None:
    return con.execute(
        "SELECT * FROM collect_runs WHERE status != 'running' ORDER BY id DESC LIMIT 1"
    ).fetchone()


def set_baseline(con, run_id: int) -> None:
    con.execute("UPDATE collect_runs SET is_baseline=0")
    con.execute("UPDATE collect_runs SET is_baseline=1 WHERE id=?", (run_id,))


def get_baseline_run(con) -> sqlite3.Row | None:
    return con.execute(
        "SELECT * FROM collect_runs WHERE is_baseline=1"
    ).fetchone()


def ensure_baseline(con) -> None:
    """Épingle le premier run OK comme baseline si aucune baseline n'existe."""
    if get_baseline_run(con) is None:
        run = con.execute(
            "SELECT id FROM collect_runs WHERE status='ok' ORDER BY id LIMIT 1"
        ).fetchone()
        if run:
            set_baseline(con, run["id"])


def purge_old_vulns(con) -> int:
    """Supprime le détail des vulnérabilités des runs non essentiels.
    Conserve : baseline + dernier run OK + premier run de chaque jour calendaire.
    Les snapshots (courbe de tendance) ne sont jamais supprimés.
    Retourne le nombre de lignes supprimées."""
    keep_ids: set[int] = set()

    bl = get_baseline_run(con)
    if bl:
        keep_ids.add(bl["id"])

    last_ok = con.execute(
        "SELECT id FROM collect_runs WHERE status='ok' ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if last_ok:
        keep_ids.add(last_ok["id"])

    daily = con.execute(
        "SELECT MIN(id) AS id FROM collect_runs WHERE status='ok' GROUP BY DATE(started_at)"
    ).fetchall()
    for r in daily:
        if r["id"] is not None:
            keep_ids.add(r["id"])

    if not keep_ids:
        return 0

    placeholders = ",".join("?" * len(keep_ids))
    cur = con.execute(
        f"DELETE FROM vulnerabilities WHERE run_id NOT IN ({placeholders})",
        list(keep_ids),
    )
    return cur.rowcount
