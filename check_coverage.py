"""
Vérifie que chaque agent Wazuh a un match dans iTop et CISO Assistant.
Usage : python check_coverage.py (depuis le répertoire dashboard/)
"""
from __future__ import annotations

import sys
import logging
import yaml

logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(message)s")

import config
from collectors.wazuh_client import WazuhClient
from collectors.itop_client import get_vms
from collectors.ciso_client import get_assets_cdi
from reconciliation import resolve, similarity

# --- Chargement du mapping manuel ---
with open(config.MAPPING_FILE, encoding="utf-8") as f:
    _mapping = yaml.safe_load(f)
itop_to_wazuh_overrides: dict = _mapping.get("itop_to_wazuh", {})
ciso_aliases: dict = _mapping.get("ciso_aliases", {})

# ── 1. Fetch ──────────────────────────────────────────────────────────────────
print("Fetching Wazuh agents…")
wc = WazuhClient()
wazuh_agents = wc.get_agents()
wazuh_names = [a["name"] for a in wazuh_agents]
print(f"  -> {len(wazuh_agents)} agent(s) : {wazuh_names}\n")

print("Fetching iTop VMs...")
itop_vms = get_vms()
itop_names = [v["name"] for v in itop_vms]
print(f"  -> {len(itop_vms)} VM(s) : {itop_names}\n")

print("Fetching CISO Assistant assets...")
ciso_assets = get_assets_cdi()
ciso_names = list(ciso_assets.keys())
print(f"  -> {len(ciso_assets)} asset(s) : {ciso_names}\n")

# ── 2. Couverture : chaque agent Wazuh → iTop + CISO ─────────────────────────
#
# La logique applicative fait : iTop → resolve → Wazuh.
# Ici on fait la vérification dans les deux sens :
#   (a) Wazuh → iTop  : quel VM iTop correspond à cet agent ?
#   (b) Wazuh → CISO  : via le nom iTop résolu, existe-t-il un asset CISO ?

# Index inversé Wazuh pour retrouver l'iTop rapidement.
# On garde le match avec le MEILLEUR score quand deux VMs iTop prétendent au même agent
# (ex: lpb-srv-portainer-azure ET PB-VM-PORTAINER matchent toutes les deux sur "portainer").
wazuh_to_itop: dict[str, str | None] = {}
wazuh_to_itop_score: dict[str, float] = {}

from reconciliation import similarity

for vm in itop_vms:
    # Override manuel → priorité absolue (score fictif 2.0 > tout auto-match)
    if vm["name"] in itop_to_wazuh_overrides:
        agent_name = itop_to_wazuh_overrides[vm["name"]]
        if agent_name in wazuh_names:
            wazuh_to_itop[agent_name] = vm["name"]
            wazuh_to_itop_score[agent_name] = 2.0
        continue

    best_agent, best_score = None, 0.0
    for agent_name in wazuh_names:
        s = similarity(vm["name"], agent_name)
        if s > best_score:
            best_score, best_agent = s, agent_name

    if best_agent and best_score >= 0.4:
        existing_score = wazuh_to_itop_score.get(best_agent, 0.0)
        if best_score > existing_score:
            wazuh_to_itop[best_agent] = vm["name"]
            wazuh_to_itop_score[best_agent] = best_score

# Pour chaque agent Wazuh, résolution CISO via le nom iTop
COL = 28
print("=" * 80)
print(f"{'Agent Wazuh':<{COL}} {'iTop VM':<{COL}} {'CISO asset':<{COL}} {'État'}")
print("-" * 80)

all_ok = True
for agent in sorted(wazuh_agents, key=lambda a: a["name"]):
    name = agent["name"]
    itop_match = wazuh_to_itop.get(name)

    # Résolution CISO : depuis le nom iTop si dispo, sinon directement depuis Wazuh
    ciso_ref = itop_match or name
    ciso_match_key = resolve(
        ciso_ref,
        ciso_names,
        overrides={k: v.lower() for k, v in ciso_aliases.items()},
        context="itop→ciso",
    )
    ciso_display = ciso_assets[ciso_match_key]["name"] if ciso_match_key else None

    if itop_match and ciso_display:
        state = "OK"
    else:
        state = " ".join(filter(None, [
            "MANQUE_ITOP" if not itop_match else None,
            "MANQUE_CISO" if not ciso_display else None,
        ]))
        all_ok = False

    print(
        f"{name:<{COL}} "
        f"{(itop_match or '—'):<{COL}} "
        f"{(ciso_display or '—'):<{COL}} "
        f"{state}"
    )

print("=" * 80)
print()

# ── 3. iTop VMs sans agent Wazuh connu ───────────────────────────────────────
unmatched_itop = [
    v["name"] for v in itop_vms
    if v["name"] not in wazuh_to_itop.values()
]
if unmatched_itop:
    print(f"VMs iTop sans agent Wazuh ({len(unmatched_itop)}) :")
    for n in unmatched_itop:
        print(f"  - {n}")
    print()

# ── 4. CISO assets sans agent Wazuh connu ────────────────────────────────────
matched_ciso_keys = set()
for agent in wazuh_agents:
    ciso_ref = wazuh_to_itop.get(agent["name"]) or agent["name"]
    k = resolve(
        ciso_ref,
        ciso_names,
        overrides={k: v.lower() for k, v in ciso_aliases.items()},
        context="itop→ciso",
    )
    if k:
        matched_ciso_keys.add(k)

unmatched_ciso = [v["name"] for k, v in ciso_assets.items() if k not in matched_ciso_keys]
if unmatched_ciso:
    print(f"Assets CISO sans agent Wazuh ({len(unmatched_ciso)}) :")
    for n in unmatched_ciso:
        print(f"  - {n}")
    print()

if all_ok:
    print("Tous les agents Wazuh ont un match iTop ET CISO.")
else:
    print("Des correspondances sont manquantes — voir tableau ci-dessus.")

sys.exit(0 if all_ok else 1)
