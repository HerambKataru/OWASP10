import os
import base64
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

DB_PATH = BASE_DIR / "sentinelx.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

UPLOADS_DIR = BASE_DIR / "uploads"
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

SECRET_KEY = os.getenv("SENTINELX_SECRET_KEY", "sentinelx_secret_master_vapt_key_2026")

# Threat Intel Default API Keys (Can also be configured via Settings UI/DB)
DEFAULT_VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
DEFAULT_ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
DEFAULT_SHODAN_KEY = os.getenv("SHODAN_API_KEY", "")

def simple_encrypt(text: str) -> str:
    if not text:
        return ""
    try:
        # Simple reversible obfuscation for local SQLite storage
        encoded = base64.b64encode(text.encode()).decode()
        return f"enc_{encoded}"
    except Exception:
        return text

def simple_decrypt(enc_text: str) -> str:
    if not enc_text:
        return ""
    try:
        if enc_text.startswith("enc_"):
            raw = enc_text[4:]
            return base64.b64decode(raw.encode()).decode()
        return enc_text
    except Exception:
        return enc_text
