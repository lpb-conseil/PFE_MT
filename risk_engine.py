"""
risk_engine.py — Moteur de calcul des positions EBIOS RM (V2).

Pur, sans I/O, testable unitairement. Conforme aux garde-fous G1–G5.

API principale :
    compute_position(scenario, effects, floor_table, max_vuln_score, now)
        -> dict {likelihood_current, gravity_current, floor_applied, breakdown, ...}
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


# ─── Data structures ─────────────────────────────────────────────────────────

@dataclass
class ScenarioData:
    id: str
    name: str
    likelihood_origin: Optional[int]   # 1-4, None si non renseigné (G5)
    gravity_origin: Optional[int]       # 1-4, None si non renseigné (G5)
    vg_inferred: bool = False           # True si déduit du niveau textuel CISO, pas saisi explicitement


@dataclass
class EffectData:
    id: int
    event_id: int
    scenario_id: str
    axis: str            # "likelihood" | "gravity"
    delta: int           # signé (+1 / -1 / etc.)
    curve: str           # "ramp" | "plateau_decay" | "instant"
    starts_at: datetime
    full_at: Optional[datetime]
    decays_at: Optional[datetime]
    expires_at: Optional[datetime]
    active: bool = True
    label: str = ""      # description lisible pour G1 (journal)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _parse_dt(v) -> Optional[datetime]:
    """Parse une date ISO depuis str/datetime, assure timezone UTC."""
    if v is None:
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    try:
        dt = datetime.fromisoformat(str(v))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _effect_weight(eff: EffectData, now: datetime) -> float:
    """Retourne le coefficient [0.0, 1.0] de l'effet à l'instant `now`.

    Trois régimes selon la courbe :
    - 'ramp'          : montée linéaire de starts_at → full_at, puis plateau indéfini
    - 'plateau_decay' : plateau jusqu'à decays_at, puis décroissance linéaire → expires_at
    - 'instant'       : poids 1.0 tant qu'actif et non expiré
    """
    if not eff.active:
        return 0.0

    expires_at = _parse_dt(eff.expires_at)
    if expires_at and now > expires_at:
        return 0.0

    starts_at = _parse_dt(eff.starts_at) or now
    full_at   = _parse_dt(eff.full_at)
    decays_at = _parse_dt(eff.decays_at)

    if eff.curve == "ramp":
        if full_at and now < full_at:
            elapsed = (now - starts_at).total_seconds()
            total   = (full_at - starts_at).total_seconds()
            return max(0.0, min(1.0, elapsed / total)) if total > 0 else 1.0
        return 1.0

    if eff.curve == "plateau_decay":
        # Rampe montante éventuelle (si full_at renseigné)
        if full_at and now < full_at:
            elapsed = (now - starts_at).total_seconds()
            total   = (full_at - starts_at).total_seconds()
            return max(0.0, min(1.0, elapsed / total)) if total > 0 else 1.0
        # Décroissance
        if decays_at and now > decays_at:
            if expires_at:
                elapsed = (now - decays_at).total_seconds()
                total   = (expires_at - decays_at).total_seconds()
                return max(0.0, 1.0 - elapsed / total) if total > 0 else 0.0
            return 0.0
        return 1.0

    # "instant" ou valeur inconnue
    return 1.0


def _compute_floor(max_vuln_score: Optional[float], floor_table: list[dict]) -> Optional[int]:
    """G2 : retourne le plancher de vraisemblance selon le score vuln max des actifs supports."""
    if max_vuln_score is None:
        return None
    for rule in sorted(floor_table, key=lambda r: r["vuln_score_gte"], reverse=True):
        if max_vuln_score >= rule["vuln_score_gte"]:
            return rule["likelihood_min"]
    return None


# ─── Fonction principale ──────────────────────────────────────────────────────

def compute_position(
    scenario: ScenarioData,
    effects: list[EffectData],
    floor_table: list[dict],
    max_vuln_score: Optional[float],
    now: Optional[datetime] = None,
) -> dict:
    """
    Calcule la position courante d'un scénario de risque EBIOS RM.

    Respecte G1 (traçabilité), G2 (plancher), G4 (ancrage sacré), G5 (incomplet).

    Args:
        scenario      : données du scénario (ancrage + méta)
        effects       : effets actifs en base pour ce scénario
        floor_table   : table du plancher G2 (depuis risk_tuning.yaml)
        max_vuln_score: score vuln max des actifs supports (pour G2)
        now           : instant de calcul (défaut : utcnow)

    Returns dict:
        likelihood_origin, gravity_origin  — ancrage G4
        likelihood_current, gravity_current — position courante (None si incomplet)
        floor_applied (bool), floor_value (int|None)
        incomplete (bool)   — G5
        vg_inferred (bool)  — vraisemblance/gravité déduite, pas saisie
        breakdown (list)    — contributions G1
    """
    now = now or datetime.now(timezone.utc)

    # G5 — données manquantes → incomplet, jamais comblé silencieusement
    if scenario.likelihood_origin is None or scenario.gravity_origin is None:
        return {
            "likelihood_origin":  scenario.likelihood_origin,
            "gravity_origin":     scenario.gravity_origin,
            "likelihood_current": None,
            "gravity_current":    None,
            "floor_applied":      False,
            "floor_value":        None,
            "incomplete":         True,
            "vg_inferred":        scenario.vg_inferred,
            "breakdown":          [],
        }

    breakdown = []
    delta_l = 0.0
    delta_g = 0.0

    for eff in effects:
        w = _effect_weight(eff, now)
        if w == 0.0:
            continue
        contribution = eff.delta * w
        if eff.axis == "likelihood":
            delta_l += contribution
        elif eff.axis == "gravity":
            delta_g += contribution
        breakdown.append({
            "effect_id":    eff.id,
            "event_id":     eff.event_id,
            "axis":         eff.axis,
            "delta":        eff.delta,
            "weight":       round(w, 2),
            "contribution": round(contribution, 2),
            "label":        eff.label,
        })

    l_raw = scenario.likelihood_origin + delta_l
    g_raw = scenario.gravity_origin + delta_g

    # G2 — plancher de vraisemblance
    floor_val     = _compute_floor(max_vuln_score, floor_table)
    floor_applied = floor_val is not None and l_raw < floor_val
    l_final       = max(l_raw, floor_val) if floor_val is not None else l_raw

    # Clamp sur l'échelle 1-4 (matrice EBIOS RM 4×4)
    l_final = max(1, min(4, round(l_final)))
    g_final = max(1, min(4, round(g_raw)))

    return {
        "likelihood_origin":  scenario.likelihood_origin,
        "gravity_origin":     scenario.gravity_origin,
        "likelihood_current": l_final,
        "gravity_current":    g_final,
        "floor_applied":      floor_applied,
        "floor_value":        floor_val,
        "incomplete":         False,
        "vg_inferred":        scenario.vg_inferred,
        "breakdown":          breakdown,
    }


def risk_level_label(likelihood: int, gravity: int) -> str:
    """Calcule le niveau de risque EBIOS RM sur matrice 4×4.
    Retourne : 'critical' | 'high' | 'medium' | 'low' | 'negligible'
    """
    score = likelihood * gravity
    if score >= 12:   return "critical"
    if score >= 6:    return "high"
    if score >= 3:    return "medium"
    if score >= 2:    return "low"
    return "negligible"
