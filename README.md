# POC — Dashboard de scoring de vulnérabilités

**Score = CVSS × (C + D + I)** — corrélation iTop (CMDB) · Wazuh (SIEM) · CISO Assistant (GRC).
PFE Mattéo Trémisi — LPB Conseil / CESI Strasbourg 2026.

## Architecture

```
APScheduler (15 min) ──> collecteurs (itop / ciso / wazuh)
                            │  réconciliation mapping.yaml + scoring
                            ▼
                         SQLite (runs horodatés = historique)
                            ▲
FastAPI /api/* ── lit UNIQUEMENT la base ──> static/index.html (Tailwind + Chart.js)
```

L'UI ne parle jamais aux API sources : affichage instantané, tolérance aux pannes
(dernier relevé conservé), historique gratuit.

## Lancement local (poste + VPN OPNsense)

```bash
cd dashboard
python -m venv .venv && .venv\Scripts\activate     # Windows
pip install -r requirements.txt
copy .env.example .env                              # puis compléter les credentials
uvicorn app:app --host 0.0.0.0 --port 8000
```

→ http://localhost:8000 — une collecte part au démarrage (`COLLECT_ON_STARTUP=1`),
puis toutes les 15 min. Bouton « Collecter » pour forcer un cycle.

Test d'un cycle seul, sans serveur :

```bash
python -m collectors.run_collect
```

## Déploiement (Portainer ou VM Proxmox)

```bash
docker compose up -d
```

Le `.env` est monté via `env_file`, la base persiste dans le volume `poc_data`.
Sur Portainer : stack → coller le compose → variables dans l'onglet env.

## Points d'attention

- **Tokens Wazuh** : JWT 900 s, pas de refresh → token frais à chaque cycle + retry unique sur 401 (`wazuh_client.py`).
- **Wazuh ≥ 4.8** : l'endpoint `GET /vulnerability/{agent_id}` a été **supprimé** ;
  le client détecte la version et bascule sur l'indexeur (`WAZUH_INDEXER_URL`, port 9200, index `wazuh-states-vulnerabilities-*`).
  Vérifier la version réelle du manager dès le premier run.
- **OQL iTop** : filtres org imbriqués KO → filtre Python sur `org_id_friendlyname` (cf. rapport 5.1.3).
- **C/D/I manquants** : score `NULL` → badge « Non évalué ». Les 19 assets existent déjà
  dans CISO Assistant ; il reste à valider les objectifs de sécurité avec Fadel.
- **mapping.yaml** : la ligne `LPC-VM-WAZUH: srvwazuh` est à vérifier (nom iTop exact).
- TLS auto-signé interne : `VERIFY_TLS=0` (assumé pour le POC, à documenter).

## Fichiers

| Fichier | Rôle |
|---|---|
| `app.py` | FastAPI + scheduler + API lecture |
| `collectors/run_collect.py` | orchestration d'un cycle |
| `collectors/{wazuh,itop,ciso}_client.py` | un collecteur par source |
| `scoring.py` | formule + tranches de criticité (seuils POC à valider en UAT) |
| `db.py` | schéma SQLite (runs, assets, vulnerabilities, snapshots) |
| `mapping.yaml` | réconciliation iTop ↔ Wazuh ↔ CISO |
| `static/index.html` | front sombre SOC, fichier unique |
