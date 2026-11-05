import os

# ==============================================================================
# 2N ACCESS UNIT M - KONFIGURACE A PŘIHLAŠOVACÍ ÚDAJE K API
#
# Nastavení se načítá z prostředí (v Dockeru ze souboru .env).
# ==============================================================================

# IP adresa nebo hostname výchozí 2N jednotky
DEVICE_IP = os.getenv("DEVICE_IP", "")

# Port webového rozhraní (výchozí 80 pro HTTP, nebo 443 pro HTTPS)
DEVICE_PORT = int(os.getenv("DEVICE_PORT", "80"))

# Protokol ("http" nebo "https")
DEVICE_PROTOCOL = os.getenv("DEVICE_PROTOCOL", "http").lower()

# Uživatelské jméno API účtu vytvořeného v 2N jednotce (Služby -> HTTP API)
API_USERNAME = os.getenv("API_USERNAME", "")

# Heslo API účtu
API_PASSWORD = os.getenv("API_PASSWORD", "")

# Used only to create the first administrator in a new database.
INITIAL_ADMIN_PASSWORD = os.getenv("INITIAL_ADMIN_PASSWORD", "")

# Typ autentizace: "digest" (doporučeno pro moderní 2N firmware) nebo "basic"
AUTH_TYPE = os.getenv("AUTH_TYPE", "digest").lower()

# Číslo spínače (obvykle 1 pro hlavní relé / zámek)
SWITCH_ID = int(os.getenv("SWITCH_ID", "1"))

# Akce spínače ("trigger" sepne spínač na nastavený čas v administraci 2N, např. 5s)
SWITCH_ACTION = os.getenv("SWITCH_ACTION", "trigger")

# Ověření SSL certifikátu při HTTPS (pro lokální samopodepsané certifikáty nechte False)
VERIFY_SSL = os.getenv("VERIFY_SSL", "false").lower() in ("true", "1", "yes")

# Timeout pro HTTP požadavek (v sekundách)
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "6"))

# Port, na kterém naslouchá interní Flask server v kontejneru
PORT = int(os.getenv("PORT", "5000"))

# Časové okno pro ověření autentizace po stisku / dotyku před odesláním notifikace (v sekundách)
DOORBELL_AUTH_WINDOW_SECONDS = float(os.getenv("DOORBELL_AUTH_WINDOW_SECONDS", "1.5"))

# Minimální prodleva mezi dvěma notifikacemi zvonku (ochrana proti zahlcení / debounce v sekundách)
DOORBELL_COOLDOWN_SECONDS = float(os.getenv("DOORBELL_COOLDOWN_SECONDS", "5.0"))

# Povolené IP podsítě pro síť Sesule (čárkou oddělený seznam CIDR notací vč. veřejné IP WAN sítě Sesule)
ALLOWED_SUBNETS = os.getenv("ALLOWED_SUBNETS", "")

# ==============================================================================
# BEZPEČNOST A SPRÁVA RELACÍ / DATABÁZE
# ==============================================================================

# Cesta k datové složce pro SQLite a klíče
DATA_DIR = os.getenv("DATA_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
os.makedirs(DATA_DIR, exist_ok=True)

DATABASE_PATH = os.getenv("DATABASE_PATH", os.path.join(DATA_DIR, "door_unlocker.db"))

def get_secret_key() -> str:
    """
    Bezpečné načtení SECRET_KEY z prostředí, persistentního souboru nebo kryptografické vygenerování.
    Nikdy nepoužívá statický fallback v kódu.
    """
    import secrets
    import logging
    env_secret = os.getenv("SECRET_KEY")
    if env_secret:
        return env_secret

    secret_file = os.path.join(DATA_DIR, "secret_key")
    if os.path.exists(secret_file):
        try:
            with open(secret_file, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    return content
        except Exception as e:
            logging.getLogger(__name__).warning("Nelze přečíst secret_key soubor: %s", e)

    # Vygenerovat nový kryptograficky bezpečný klíč a uložit do souboru
    new_secret = secrets.token_hex(32)
    try:
        with open(secret_file, "w", encoding="utf-8") as f:
            f.write(new_secret)
        logging.getLogger(__name__).info("Vygenerován a uložen nový kryptografický SECRET_KEY.")
    except Exception as e:
        logging.getLogger(__name__).warning("Generován pouze dočasný SECRET_KEY v paměti: %s", e)
    return new_secret

SECRET_KEY = get_secret_key()

# Konfigurace cookies pro Flask Session
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "door_session")
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "Lax")
SESSION_COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() in ("true", "1", "yes")
SESSION_LIFETIME_DAYS = int(os.getenv("SESSION_LIFETIME_DAYS", "3"))
REMEMBER_ME_DAYS = int(os.getenv("REMEMBER_ME_DAYS", "90"))
PERMANENT_SESSION_LIFETIME_MINUTES = int(os.getenv("SESSION_LIFETIME_MINUTES", str(SESSION_LIFETIME_DAYS * 24 * 60)))

# Bezpečnostní limity autentizace
MAX_FAILED_LOGIN_ATTEMPTS = int(os.getenv("MAX_FAILED_LOGIN_ATTEMPTS", "5"))
ACCOUNT_LOCKOUT_MINUTES = int(os.getenv("ACCOUNT_LOCKOUT_MINUTES", "15"))
IP_RATE_LIMIT_ATTEMPTS = int(os.getenv("IP_RATE_LIMIT_ATTEMPTS", "10"))
IP_RATE_LIMIT_MINUTES = int(os.getenv("IP_RATE_LIMIT_MINUTES", "15"))

# ==============================================================================
# VAPID KLÍČE PRO PUSH NOTIFIKACE (Web Push)
# ==============================================================================

def get_vapid_keys() -> dict:
    """
    Načte nebo vygeneruje VAPID klíče pro Web Push notifikace.
    Klíče se ukládají do DATA_DIR/vapid_private.pem a vapid_public.txt.
    """
    import base64
    import logging
    from py_vapid import Vapid
    from cryptography.hazmat.primitives import serialization

    private_path = os.path.join(DATA_DIR, "vapid_private.pem")
    public_path = os.path.join(DATA_DIR, "vapid_public.txt")

    if os.path.exists(private_path) and os.path.exists(public_path):
        try:
            with open(private_path, "r", encoding="utf-8") as f:
                private_key = f.read().strip()
            with open(public_path, "r", encoding="utf-8") as f:
                public_key = f.read().strip()
            if private_key and public_key:
                return {"private_key": private_key, "public_key": public_key}
        except Exception as e:
            logging.getLogger(__name__).warning("Nelze přečíst VAPID klíče: %s", e)

    # Generace nových VAPID klíčů
    try:
        vapid = Vapid()
        vapid.generate_keys()
        private_key = vapid.private_pem().decode("utf-8").strip()
        raw_public = vapid.public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
        public_key = base64.urlsafe_b64encode(raw_public).decode("utf-8").rstrip("=")

        with open(private_path, "w", encoding="utf-8") as f:
            f.write(private_key)
        with open(public_path, "w", encoding="utf-8") as f:
            f.write(public_key)

        logging.getLogger(__name__).info("Vygenerovány a uloženy nové VAPID klíče pro push notifikace.")
        return {"private_key": private_key, "public_key": public_key}
    except Exception as e:
        logging.getLogger(__name__).error("Nelze vygenerovat VAPID klíče: %s", e)
        return {"private_key": "", "public_key": ""}


VAPID_KEYS = get_vapid_keys()
VAPID_PRIVATE_KEY = VAPID_KEYS["private_key"]
VAPID_PUBLIC_KEY = VAPID_KEYS["public_key"]
VAPID_PRIVATE_KEY_PATH = os.path.join(DATA_DIR, "vapid_private.pem")
VAPID_CLAIMS_EMAIL = os.getenv("VAPID_EMAIL", "mailto:admin@sesule.local")

# ==============================================================================
# WEBAUTHN / FIDO2 KONFIGURACE (biometrické přihlášení)
# ==============================================================================

# RP ID = doména nebo IP adresa, bez portu
WEBAUTHN_RP_ID = os.getenv("WEBAUTHN_RP_ID", "")
WEBAUTHN_RP_NAME = os.getenv("WEBAUTHN_RP_NAME", "Odemykání dveří Šešule")
# Origin musí přesně odpovídat tomu, co prohlížeč vidí (např. "https://door.sesule.local:8443")
WEBAUTHN_ORIGIN = os.getenv("WEBAUTHN_ORIGIN", "")

# Webhook secret pro 2N jednotku (volitelné)
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")
