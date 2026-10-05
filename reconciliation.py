"""
Réconciliation floue des noms d'actifs entre iTop, Wazuh et CISO Assistant.

Problème : les trois outils utilisent des conventions de nommage différentes.
  iTop     : LPC-VM-BASTION, LPC-VM-SUPERVISION, LPC-VM-ADMIN-RDP
  Wazuh    : srv-bastion,    lpb-zabbix,          lpb-srv-admin-rdp
  CISO     : LPC-VM-BASTIO,  LPC-VM-ZABBIX,       lpb-srv-admin-rdp

Algorithme en trois étapes :
  1. Override manuel (mapping.yaml) → priorité absolue, pour les cas sans lien lexical
     (ex. supervision ↔ zabbix — deux noms d'outils sans mot commun).
  2. Auto-match par recouvrement de tokens si score ≥ CONFIDENCE_THRESHOLD.
  3. Score insuffisant → warning loggué, retourne None.

Scoring des tokens :
  +2  match exact          (bastion == bastion)
  +1  relation préfixe     (bastio ⊆ bastion — troncature CISO)
  +1  relation sous-chaîne (wazuh  ⊆ srvwazuh — mot composé sans séparateur)

Score normalisé : Σ / (2 × max(|tokens_A|, |tokens_B|)) ∈ [0, 1]

Stopwords : tokens trop génériques pour discriminer les actifs LPB/LPC.
  lpb, lpc, srv, vm, server, local, domain
"""
from __future__ import annotations

import logging
import re
from typing import Optional

log = logging.getLogger(__name__)

# Tokens sans pouvoir discriminant dans le contexte LPB/LPC
_STOPWORDS: frozenset[str] = frozenset({
    "lpb", "lpc", "srv", "vm", "server", "local", "domain",
})

# Seuil de confiance : en dessous, l'auto-match est refusé et un warning est loggué.
# Valeur calibrée sur le périmètre LPB : les noms cohérents scorent ≥ 0.5,
# les noms incohérents (supervision/zabbix) scorent 0.0.
CONFIDENCE_THRESHOLD: float = 0.4


def tokenize(name: str) -> frozenset[str]:
    """Découpe un nom d'hôte en tokens significatifs.

    - Séparateurs : tiret, underscore, point, espace.
    - Filtre : tokens < 3 caractères ou dans les stopwords.
    - Casse normalisée en minuscules.

    >>> sorted(tokenize("LPC-VM-BASTION"))
    ['bastion']
    >>> sorted(tokenize("lpb-srv-admin-rdp"))
    ['admin', 'rdp']
    >>> sorted(tokenize("lpb-srv-portainer-azure"))
    ['azure', 'portainer']
    """
    parts = re.split(r"[-_.\s]+", name.lower())
    return frozenset(p for p in parts if p and p not in _STOPWORDS and len(p) >= 3)


def _token_score(x: str, y: str) -> int:
    """Score brut entre deux tokens individuels."""
    if x == y:
        return 2          # match exact
    if x.startswith(y) or y.startswith(x):
        return 1          # relation préfixe : bastio ⊆ bastion
    if x in y or y in x:
        return 1          # sous-chaîne : wazuh ⊆ srvwazuh
    return 0


def similarity(a: str, b: str) -> float:
    """Similarité token-overlap normalisée entre deux noms d'actifs (0.0–1.0).

    Exemples sur le périmètre LPB :
      LPC-VM-BASTION  / srv-bastion        → 1.0  (bastion == bastion)
      LPC-VM-ADMIN-RDP/ lpb-srv-admin-rdp  → 1.0  (admin + rdp)
      LPC-VM-BASTION  / LPC-VM-BASTIO      → 0.5  (bastio préfixe de bastion)
      LPC-VM-WAZUH    / srvwazuh           → 0.5  (wazuh sous-chaîne de srvwazuh)
      LPC-VM-SUPERVISION / lpb-zabbix      → 0.0  (aucune relation lexicale)
    """
    ta, tb = tokenize(a), tokenize(b)
    if not ta or not tb:
        return 0.0
    raw = sum(_token_score(x, y) for x in ta for y in tb)
    return raw / (2 * max(len(ta), len(tb)))


def resolve(
    itop_name: str,
    candidates: list[str],
    overrides: dict[str, str] | None = None,
    context: str = "",
) -> Optional[str]:
    """Retourne le meilleur match pour itop_name parmi candidates.

    Priorité de résolution :
      1. Override manuel dans mapping.yaml  → retourne overrides[itop_name]
      2. Auto-match si score ≥ 0.4          → retourne le candidat, logge en DEBUG
      3. Score < seuil                       → logge un WARNING, retourne None

    Args:
        itop_name:  Nom de l'actif tel qu'il apparaît dans iTop.
        candidates: Noms disponibles côté cible (agents Wazuh ou assets CISO).
        overrides:  Correspondances manuelles issues de mapping.yaml.
                    Clé = nom iTop, valeur = nom cible. Priorité absolue.
        context:    Libellé pour les logs ("itop→wazuh" ou "itop→ciso").

    Returns:
        Nom résolu (str), ou None si aucun match fiable.
    """
    # 1. Override manuel
    if overrides and itop_name in overrides:
        resolved = overrides[itop_name]
        log.debug("Override manuel [%s] '%s' → '%s'", context, itop_name, resolved)
        return resolved

    # 2. Auto-match : chercher le meilleur candidat
    best: Optional[str] = None
    best_score = 0.0
    for candidate in candidates:
        s = similarity(itop_name, candidate)
        if s > best_score:
            best_score, best = s, candidate

    if best and best_score >= CONFIDENCE_THRESHOLD:
        log.debug(
            "Auto-match [%s] '%s' → '%s' (score=%.2f)",
            context, itop_name, best, best_score,
        )
        return best

    # 3. Pas de match fiable
    if best and best_score > 0:
        log.warning(
            "Correspondance incertaine [%s] '%s' → '%s' (score=%.2f < seuil=%.2f). "
            "Ajoutez une entrée dans mapping.yaml pour forcer la correspondance.",
            context, itop_name, best, best_score, CONFIDENCE_THRESHOLD,
        )
    else:
        log.info(
            "Aucune correspondance [%s] pour '%s' — actif sans agent ni asset cible.",
            context, itop_name,
        )
    return None
