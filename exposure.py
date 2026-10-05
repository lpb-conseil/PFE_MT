"""Facteur d'exposition reseau (E) — V1.2.

Resout un facteur d'exposition pour un actif a partir de exposure.yaml.
Aucun coefficient en dur ici (garde-fou G3) : tout vient du YAML.
Exposition inconnue -> facteur neutre 1.0 -> la V1.2 redonne la V1.1 (G5).
"""
from __future__ import annotations

import ipaddress
import logging
from functools import lru_cache
from pathlib import Path

import yaml

log = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).with_name("exposure.yaml")


@lru_cache(maxsize=1)
def _config() -> dict:
    with CONFIG_PATH.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def reload_config() -> None:
    """Vide le cache — a appeler apres modification du YAML."""
    _config.cache_clear()


def resolve(asset_name: str | None, ip: str | None) -> tuple[float, str]:
    """Retourne (facteur, palier) pour un actif.

    Priorite : surcharge nominative > sous-reseau > defaut neutre.
    """
    cfg = _config()
    tiers = cfg.get("tiers") or {}
    default = float(cfg.get("default", 1.0))

    def _tier(name: str) -> tuple[float, str] | None:
        t = tiers.get(name)
        if not t:
            log.warning("Palier d'exposition inconnu dans exposure.yaml : %s", name)
            return None
        return float(t["factor"]), name

    if asset_name:
        override = (cfg.get("assets") or {}).get(asset_name)
        if override and (r := _tier(override)):
            return r

    if ip:
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            log.warning("IP illisible pour %s : %r", asset_name, ip)
        else:
            for rule in cfg.get("subnets") or []:
                try:
                    net = ipaddress.ip_network(rule["cidr"], strict=False)
                except ValueError:
                    log.warning("CIDR invalide dans exposure.yaml : %r", rule.get("cidr"))
                    continue
                if addr in net and (r := _tier(rule["tier"])):
                    return r

    return default, "inconnu"


def label(tier: str) -> str:
    if tier == "inconnu":
        return "Exposition non renseignee — facteur neutre"
    t = (_config().get("tiers") or {}).get(tier) or {}
    return t.get("label", tier)
