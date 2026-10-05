"""Configuration centralisée — lue depuis les variables d'environnement (.env)."""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

# --- Wazuh ---
WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://192.168.10.161:55000")
WAZUH_USER = os.getenv("WAZUH_USER", "wazuh")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD", "")
# Indexeur (requis uniquement si Wazuh >= 4.8 — l'endpoint /vulnerability a été supprimé)
WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "")  # ex: https://192.168.10.161:9200
WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD", "")

# --- iTop ---
ITOP_URL = os.getenv("ITOP_URL", "https://cdsdev.nuage-lpb.com/itop")
ITOP_USER = os.getenv("ITOP_USER", "")
ITOP_PASSWORD = os.getenv("ITOP_PASSWORD", "")
ITOP_API_VERSION = os.getenv("ITOP_API_VERSION", "1.3")
# Filtre organisation appliqué côté Python (les filtres OQL imbriqués ne fonctionnent pas — cf. rapport 5.1.3)
ITOP_ORG_FILTER = [o.strip() for o in os.getenv("ITOP_ORG_FILTER", "").split(",") if o.strip()]

# --- CISO Assistant ---
CISO_URL = os.getenv("CISO_URL", "https://ciso-lpbgroupe.nuage-lpb.com")
CISO_TOKEN = os.getenv("CISO_TOKEN", "")

# --- Veille NVD (CVE watch sur les actifs SaaS/produits) ---
NVD_API_URL = os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")           # optionnelle — 5 req/30s sans, 50 avec
WATCH_INTERVAL_MIN = int(os.getenv("WATCH_INTERVAL_MIN", "60"))
WATCH_ON_STARTUP = os.getenv("WATCH_ON_STARTUP", "1") == "1"
WATCH_FILE = BASE_DIR / "watch.yaml"

# --- Application ---
DB_PATH = Path(os.getenv("DB_PATH", str(BASE_DIR / "data" / "poc.sqlite3")))
COLLECT_INTERVAL_MIN = int(os.getenv("COLLECT_INTERVAL_MIN", "15"))
COLLECT_ON_STARTUP = os.getenv("COLLECT_ON_STARTUP", "1") == "1"
MAPPING_FILE = BASE_DIR / "mapping.yaml"
HTTP_TIMEOUT = int(os.getenv("HTTP_TIMEOUT", "30"))
# Certificats auto-signés sur le réseau interne LPB
VERIFY_TLS = os.getenv("VERIFY_TLS", "0") == "1"
