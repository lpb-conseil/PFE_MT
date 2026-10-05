"""Collecteur iTop — inventaire des machines virtuelles (pivot du POC).

Particularité documentée au rapport (5.1.3) : les filtres OQL imbriqués sur
l'organisation retournent zéro résultat ; le filtre org est donc appliqué
côté Python sur org_id_friendlyname.
"""
from __future__ import annotations

import json
import logging

import requests
import urllib3

import config

log = logging.getLogger(__name__)

if not config.VERIFY_TLS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ItopError(RuntimeError):
    pass


def _first(fields: dict, *keys: str) -> str | None:
    """Retourne la première valeur non vide parmi plusieurs clés candidates
    (le nom des attributs varie selon les datamodels iTop)."""
    for k in keys:
        v = fields.get(k)
        if v not in (None, "", 0, "0"):
            return str(v)
    return None


def get_vms() -> list[dict]:
    """Retourne [{name, ip, org, host}] pour toutes les VMs (filtrées par org si configuré)."""
    payload = {
        "operation": "core/get",
        "class": "VirtualMachine",
        "key": "SELECT VirtualMachine",
        "output_fields": "*",
    }
    r = requests.post(
        f"{config.ITOP_URL.rstrip('/')}/webservices/rest.php",
        params={"version": config.ITOP_API_VERSION},
        data={
            "auth_user": config.ITOP_USER,
            "auth_pwd": config.ITOP_PASSWORD,
            "json_data": json.dumps(payload),
        },
        verify=config.VERIFY_TLS,
        timeout=config.HTTP_TIMEOUT,
    )
    r.raise_for_status()
    data = r.json()
    if data.get("code") != 0:
        raise ItopError(f"Erreur iTop : {data.get('message')}")

    vms = []
    for obj in (data.get("objects") or {}).values():
        f = obj.get("fields", {})
        org = f.get("org_id_friendlyname") or f.get("organization_name")
        if config.ITOP_ORG_FILTER and org not in config.ITOP_ORG_FILTER:
            continue  # filtre org côté Python — cf. docstring
        vms.append({
            "name": f.get("name"),
            "ip": _first(f, "managementip", "managementip_id_friendlyname"),
            "org": org,
            "host": _first(f, "virtualhost_id_friendlyname", "virtualhost_name"),
        })
    log.info("iTop : %d VMs récupérées", len(vms))
    return vms
