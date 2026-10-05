"""Logique métier du scoring.

V1.1 — Score = CVSS × (W_CDI × (C + D + I) + W_VM × VM)

CVSS : score brut de la CVE issu de Wazuh (0-10, CVSS v3).
C/D/I : criticité de l'ACTIF SUPPORT (0-4 chacun), issue de CISO Assistant.
VM   : criticité de la VALEUR MÉTIER portée par l'actif (0-4) — moyenne
       (C+D+I)/3 maximale parmi les actifs primaires CISO parents.

Pondérations (W_CDI=0.7, W_VM=0.9) choisies pour que :
  - le score maximal reste 120 : 10 × (0.7×12 + 0.9×4) = 120
    → les seuils de criticité V1 restent valables sans recalibrage ;
  - si VM est inconnue, on pose VM = (C+D+I)/3 (hypothèse neutre) et la
    formule redonne EXACTEMENT la V1 : CVSS × (C+D+I). La donnée manquante
    est neutre, jamais comblée arbitrairement (esprit G5).

Historique : V1 = CVSS × (C+D+I) — conservée comme cas dégradé.
"""
from __future__ import annotations

CDI_MIN, CDI_MAX = 0, 4
VM_MIN, VM_MAX = 0.0, 4.0

W_CDI = 0.7   # poids criticité de l'actif support
W_VM = 0.9    # poids criticité de la valeur métier portée

# Seuils POC — à valider avec Fadel Ghamlouche (UAT)
SEVERITY_THRESHOLDS = [
    (60, "critique"),
    (40, "eleve"),
    (20, "modere"),
    (0, "faible"),
]


def compute_score(cvss: float | None, c: int | None, d: int | None, i: int | None,
                  vm: float | None = None) -> float | None:
    """Calcule le score métier V1.1. Retourne None si CVSS ou C/D/I manquent
    (actif non évalué dans CISO Assistant, ou CVE sans score CVSS).

    `vm` (0-4) : criticité de la valeur métier. Si None, hypothèse neutre
    VM = (C+D+I)/3 → la formule dégénère en V1 (CVSS × (C+D+I))."""
    if cvss is None or c is None or d is None or i is None:
        return None
    if not (0 <= cvss <= 10):
        raise ValueError(f"CVSS hors bornes [0-10] : {cvss}")
    for name, v in (("C", c), ("D", d), ("I", i)):
        if not (CDI_MIN <= v <= CDI_MAX):
            raise ValueError(f"{name} hors bornes [{CDI_MIN}-{CDI_MAX}] : {v}")

    cdi = c + d + i
    if vm is None:
        vm = cdi / 3.0                       # neutre → V1 exacte
    if not (VM_MIN <= vm <= VM_MAX):
        raise ValueError(f"VM hors bornes [{VM_MIN}-{VM_MAX}] : {vm}")

    return round(cvss * (W_CDI * cdi + W_VM * vm), 1)


def severity_bucket(score: float | None) -> str:
    """Classe un score dans une tranche de criticité (seuils POC)."""
    if score is None:
        return "non_evalue"
    for threshold, label in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return label
    return "faible"
