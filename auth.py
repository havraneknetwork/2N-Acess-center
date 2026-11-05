import os
import re
import json
import sqlite3
import logging
from contextlib import nullcontext
from datetime import datetime, timedelta, timezone
import hmac

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
    _hasher = PasswordHasher(
        time_cost=3,
        memory_cost=65536,  # 64 MB RAM
        parallelism=4,
        hash_len=32,
        salt_len=16
    )
    _USE_ARGON2 = True
except ImportError:
    class VerifyMismatchError(Exception): pass
    class VerificationError(Exception): pass
    class InvalidHashError(Exception): pass
    import werkzeug.security as wz_security
    _USE_ARGON2 = False

import config
import permissions_config

logger = logging.getLogger(__name__)

# TODO(security): Consider OAuth 2.0 / OIDC provider integration for enterprise SSO.
# TODO(security): Consider implementing TOTP / WebAuthn MFA to harden authentication.
# TODO(security): Consider integration with HaveIBeenPwned API for leaked password detection.
# TODO(security): Time-limited one-time token password reset flow can be connected via email/SMS gateway.


def hash_password(password: str) -> str:
    """Hashování hesla pomocí Argon2id nebo Scrypt s vysokou paměťovou náročností."""
    if _USE_ARGON2:
        return _hasher.hash(password)
    else:
        return wz_security.generate_password_hash(password, method="scrypt:32768:8:1")


def verify_password(hash_str: str, password: str) -> bool:
    """Konstantně-časové ověření shody hesla a hashe."""
    if not hash_str or not password:
        return False
    try:
        if _USE_ARGON2 and hash_str.startswith("$argon2"):
            return _hasher.verify(hash_str, password)
        elif _USE_ARGON2 and not hash_str.startswith("$argon2"):
            # Fallback pokud v DB existuje starý scrypt/pbkdf2 hash
            import werkzeug.security as wz_security
            return wz_security.check_password_hash(hash_str, password)
        else:
            import werkzeug.security as wz_security
            return wz_security.check_password_hash(hash_str, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception as e:
        logger.error(f"Chyba při ověřování hesla: {e}")
        return False


# Fiktivní hash pro ochranu proti útokům postranním kanálem (Timing attacks)
DUMMY_HASH = hash_password("dummy_constant_time_pass_34982")


def get_db_connection() -> sqlite3.Connection:
    """Vrací spojení do SQLite databáze s nastavením Row factory."""
    os.makedirs(os.path.dirname(config.DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(config.DATABASE_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    """Inicializace databázového schématu a vytvoření výchozího admin účtu."""
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TIMESTAMP NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TIMESTAMP DEFAULT NULL,
                last_login_at TIMESTAMP DEFAULT NULL,
                network_bypass INTEGER NOT NULL DEFAULT 0
            )
        """)

        # Migrace: ověřit existenci sloupců pro starší databáze
        cursor = conn.execute("PRAGMA table_info(users)")
        columns = [row["name"] for row in cursor.fetchall()]
        if "network_bypass" not in columns:
            try:
                conn.execute("ALTER TABLE users ADD COLUMN network_bypass INTEGER NOT NULL DEFAULT 0")
                conn.commit()
                logger.info("Migrace DB: Přidán sloupec 'network_bypass' do tabulky users.")
            except Exception:
                pass  # sloupec již existuje (jiný worker ho přidal dříve)

        if "permanent_unlock_allowed" not in columns:
            try:
                conn.execute("ALTER TABLE users ADD COLUMN permanent_unlock_allowed INTEGER NOT NULL DEFAULT 0")
                conn.commit()
                logger.info("Migrace DB: Přidán sloupec 'permanent_unlock_allowed' do tabulky users.")
            except Exception:
                pass  # sloupec již existuje (jiný worker ho přidal dříve)

        if "permanent_unlock_max_duration" not in columns:
            try:
                conn.execute("ALTER TABLE users ADD COLUMN permanent_unlock_max_duration INTEGER NOT NULL DEFAULT 60")
                conn.commit()
                logger.info("Migrace DB: Přidán sloupec 'permanent_unlock_max_duration' do tabulky users.")
            except Exception:
                pass  # sloupec již existuje (jiný worker ho přidal dříve)

        new_user_columns = [
            ("can_unlock", "INTEGER NOT NULL DEFAULT 1"),
            ("time_restricted", "INTEGER NOT NULL DEFAULT 0"),
            ("allowed_time_from", "TEXT DEFAULT '06:00'"),
            ("allowed_time_to", "TEXT DEFAULT '22:00'"),
            ("allowed_days", "TEXT DEFAULT 'all'"),
            ("user_note", "TEXT DEFAULT ''"),
            ("is_disabled", "INTEGER NOT NULL DEFAULT 0"),
            ("sidebar_menu", "TEXT DEFAULT NULL"),
            ("can_manage_users", "INTEGER DEFAULT NULL"),
            ("user_management_permissions", "TEXT DEFAULT NULL")
        ]
        for cname, cdef in new_user_columns:
            if cname not in columns:
                try:
                    conn.execute(f"ALTER TABLE users ADD COLUMN {cname} {cdef}")
                    conn.commit()
                    logger.info(f"Migrace DB: Přidán sloupec '{cname}' do tabulky users.")
                except Exception:
                    pass

        conn.execute("""
            CREATE TABLE IF NOT EXISTS permanent_unlock_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                is_active INTEGER NOT NULL DEFAULT 0,
                activated_by_id INTEGER,
                activated_by_username TEXT,
                duration_minutes INTEGER DEFAULT 0,
                started_at TIMESTAMP,
                expires_at TIMESTAMP
            )
        """)
        conn.execute("INSERT OR IGNORE INTO permanent_unlock_state (id, is_active, duration_minutes) VALUES (1, 0, 0)")
        conn.commit()

        conn.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                attempt_time TIMESTAMP NOT NULL,
                success INTEGER NOT NULL DEFAULT 0
            )
        """)

        conn.execute("CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time ON login_attempts(ip_address, attempt_time)")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_schedule (
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                schedule_json TEXT NOT NULL DEFAULT '{}',
                updated_at TIMESTAMP NOT NULL
            )
        """)

        # A fresh database must be provisioned with an administrator secret from the environment.
        cursor = conn.execute("SELECT id FROM users WHERE username = ?", ("admin",))
        admin_user = cursor.fetchone()
        if not admin_user:
            initial_admin_password = config.INITIAL_ADMIN_PASSWORD
            if not initial_admin_password:
                raise RuntimeError(
                    "INITIAL_ADMIN_PASSWORD must be set in the environment to initialize a new database."
                )
            now = datetime.utcnow().isoformat()
            hashed_admin = hash_password(initial_admin_password)
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at, network_bypass, permanent_unlock_allowed, permanent_unlock_max_duration) VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("admin", hashed_admin, "admin", now, 1, 1, 240)
            )
            conn.commit()
            logger.info("Initial administrator account was created from environment configuration.")
        else:
            # Ujistit se, že admin má permanent_unlock_allowed = 1
            conn.execute("UPDATE users SET permanent_unlock_allowed = 1 WHERE username = 'admin' AND permanent_unlock_allowed = 0")
            conn.commit()


def validate_username(username: str) -> tuple[bool, str]:
    """Validace uživatelského jména (3-32 znaků, bezpečné alfanumerické znaky)."""
    if not username or not isinstance(username, str):
        return False, "Uživatelské jméno je povinné."
    username = username.strip()
    if len(username) < 3 or len(username) > 32:
        return False, "Uživatelské jméno musí mít 3 až 32 znaků."
    if not re.match(r"^[a-zA-Z0-9_.-]+$", username):
        return False, "Uživatelské jméno může obsahovat pouze písmena, čísla, tečku, pomlčku nebo podtržítko."
    return True, ""


def validate_password(password: str) -> tuple[bool, str]:
    """Validace síly hesla podle konfiguračního souboru permissions_config."""
    if not password or not isinstance(password, str):
        return False, "Heslo je povinné."
    min_len = permissions_config.SECURITY_POLICIES.get("min_password_length", 8)
    if len(password) < min_len:
        return False, f"Heslo musí obsahovat alespoň {min_len} znaků."
    if len(password) > 256:
        return False, "Heslo je příliš dlouhé (max 256 znaků)."
    return True, ""


def is_ip_rate_limited(ip_address: str) -> bool:
    """Kontrola, zda daná IP adresa nepřekročila limit neúspěšných pokusů."""
    cutoff = (datetime.utcnow() - timedelta(minutes=config.IP_RATE_LIMIT_MINUTES)).isoformat()
    with get_db_connection() as conn:
        cursor = conn.execute(
            "SELECT COUNT(*) as cnt FROM login_attempts WHERE ip_address = ? AND attempt_time >= ? AND success = 0",
            (ip_address, cutoff)
        )
        row = cursor.fetchone()
        count = row["cnt"] if row else 0
        return count >= config.IP_RATE_LIMIT_ATTEMPTS


def record_login_attempt(ip_address: str, success: bool) -> None:
    """Zaznamenání pokusu o přihlášení pro rate limiting."""
    now = datetime.utcnow().isoformat()
    try:
        with get_db_connection() as conn:
            conn.execute(
                "INSERT INTO login_attempts (ip_address, attempt_time, success) VALUES (?, ?, ?)",
                (ip_address, now, 1 if success else 0)
            )
            # Čištění starých záznamů starších než 2 dny
            old_cutoff = (datetime.utcnow() - timedelta(days=2)).isoformat()
            conn.execute("DELETE FROM login_attempts WHERE attempt_time < ?", (old_cutoff,))
            conn.commit()
    except Exception as e:
        logger.error(f"Chyba při zápisu login pokusu: {e}")


def authenticate_user(username: str, password: str, ip_address: str) -> tuple[bool, dict | None, str]:
    """
    Ověření uživatele s ochranou proti brute-force, timing útokům a generickými chybovými hláškami.
    Nikdy nevrací podrobnosti o tom, zda existuje jméno.
    """
    # 1. IP Rate limit
    if is_ip_rate_limited(ip_address):
        logger.warning(f"IP {ip_address} překročila limit neúspěšných pokusů o přihlášení.")
        return False, None, "Příliš mnoho neúspěšných pokusů. Počkejte prosím 15 minut."

    now_dt = datetime.utcnow()
    now_iso = now_dt.isoformat()

    with get_db_connection() as conn:
        cursor = conn.execute(
            "SELECT id, username, password_hash, role, failed_attempts, locked_until, network_bypass, is_disabled FROM users WHERE username = ?",
            (username.strip() if username else "",)
        )
        user = cursor.fetchone()

        if user:
            # 2. Kontrola uzamčení nebo deaktivace účtu
            if "is_disabled" in user.keys() and user["is_disabled"]:
                logger.warning(f"Pokus o přihlášení k deaktivovanému účtu '{username}' z IP {ip_address}.")
                record_login_attempt(ip_address, success=False)
                return False, None, "Váš účet byl deaktivován. Obraťte se na správce systému."

            locked_until_str = user["locked_until"]
            if locked_until_str:
                try:
                    locked_until_dt = datetime.fromisoformat(locked_until_str)
                    if now_dt < locked_until_dt:
                        remaining_min = max(1, int((locked_until_dt - now_dt).total_seconds() / 60))
                        logger.warning(f"Pokus o přihlášení k uzamčenému účtu '{username}' z IP {ip_address}.")
                        record_login_attempt(ip_address, success=False)
                        return False, None, f"Účet je dočasně uzamčen. Zkuste to prosím za {remaining_min} min."
                except ValueError:
                    pass

            # 3. Konstantně-časové ověření hesla
            is_valid = verify_password(user["password_hash"], password)

            if is_valid:
                # Úspěšné přihlášení: reset selhání
                conn.execute(
                    "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?",
                    (now_iso, user["id"])
                )
                conn.commit()
                record_login_attempt(ip_address, success=True)
                bypass_val = bool(user["network_bypass"]) if "network_bypass" in user.keys() else False
                return True, {
                    "id": user["id"],
                    "username": user["username"],
                    "role": user["role"],
                    "network_bypass": bypass_val
                }, ""
            else:
                # Neúspěšné přihlášení: inkrementace selhání
                new_failed = user["failed_attempts"] + 1
                new_lockout = None
                if new_failed >= config.MAX_FAILED_LOGIN_ATTEMPTS:
                    lockout_dt = now_dt + timedelta(minutes=config.ACCOUNT_LOCKOUT_MINUTES)
                    new_lockout = lockout_dt.isoformat()
                    logger.warning(f"Účet '{username}' byl uzamčen na {config.ACCOUNT_LOCKOUT_MINUTES} minut kvůli neúspěšným pokusům.")

                conn.execute(
                    "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                    (new_failed, new_lockout, user["id"])
                )
                conn.commit()
                record_login_attempt(ip_address, success=False)
                return False, None, "Neplatné uživatelské jméno nebo heslo."
        else:
            # Timing attack mitigation: spustit fiktivní hash porovnání
            verify_password(DUMMY_HASH, password)
            record_login_attempt(ip_address, success=False)
            return False, None, "Neplatné uživatelské jméno nebo heslo."


def _row_to_user_dict(r: sqlite3.Row) -> dict:
    """Převede řádek tabulky users na normalizovaný slovník včetně menu a správy uživatelů."""
    keys = r.keys()
    now_utc = datetime.utcnow()
    is_locked = bool(r["locked_until"] and datetime.fromisoformat(r["locked_until"]) > now_utc)
    role = str(r["role"] or "user").strip().lower()

    # Položky bočního menu (pokud není uloženo, použít výchozí pro roli)
    raw_menu = r["sidebar_menu"] if "sidebar_menu" in keys else None
    if raw_menu:
        sidebar_menu = permissions_config.sanitize_sidebar_menu(raw_menu)
    else:
        sidebar_menu = permissions_config.get_default_sidebar_menu_for_role(role)

    # Právo spravovat uživatele (pokud je v DB NULL, použije se výchozí hodnota pro roli)
    raw_can_manage = r["can_manage_users"] if "can_manage_users" in keys else None
    if raw_can_manage is not None:
        can_manage = bool(raw_can_manage)
    else:
        can_manage = permissions_config.can_user_manage_users(role)

    # Vlastní oprávnění pro editaci jiných uživatelů
    raw_perms = r["user_management_permissions"] if "user_management_permissions" in keys else None
    custom_mgmt_perms = None
    if raw_perms:
        try:
            custom_mgmt_perms = json.loads(raw_perms) if isinstance(raw_perms, str) else raw_perms
        except Exception:
            custom_mgmt_perms = None

    return {
        "id": r["id"],
        "username": r["username"],
        "role": role,
        "created_at": r["created_at"] if "created_at" in keys else None,
        "last_login_at": r["last_login_at"] if "last_login_at" in keys else None,
        "is_locked": is_locked,
        "locked_until": r["locked_until"] if is_locked else None,
        "network_bypass": bool(r["network_bypass"]) if "network_bypass" in keys else False,
        "permanent_unlock_allowed": bool(r["permanent_unlock_allowed"]) if "permanent_unlock_allowed" in keys else False,
        "permanent_unlock_max_duration": int(r["permanent_unlock_max_duration"] or 60) if "permanent_unlock_max_duration" in keys else 60,
        "can_unlock": bool(r["can_unlock"]) if "can_unlock" in keys else True,
        "time_restricted": bool(r["time_restricted"]) if "time_restricted" in keys else False,
        "allowed_time_from": str(r["allowed_time_from"] or "06:00") if "allowed_time_from" in keys else "06:00",
        "allowed_time_to": str(r["allowed_time_to"] or "22:00") if "allowed_time_to" in keys else "22:00",
        "allowed_days": str(r["allowed_days"] or "all") if "allowed_days" in keys else "all",
        "user_note": str(r["user_note"] or "") if "user_note" in keys else "",
        "is_disabled": bool(r["is_disabled"]) if "is_disabled" in keys else False,
        "sidebar_menu": sidebar_menu,
        "can_manage_users": can_manage,
        "user_management_permissions": custom_mgmt_perms
    }


def get_all_users() -> list[dict]:
    """Získání seznamu všech uživatelů pro administrátory a správce."""
    with get_db_connection() as conn:
        cursor = conn.execute("SELECT * FROM users ORDER BY id ASC")
        return [_row_to_user_dict(r) for r in cursor.fetchall()]


def create_user(username: str, password: str, role: str, network_bypass: bool = False, permanent_unlock_allowed: bool = False, permanent_unlock_max_duration: int = 60, sidebar_menu: list = None, can_manage_users: bool = None) -> tuple[bool, str]:
    """Vytvoření nového uživatele administrátorem či oprávněnou rolí."""
    valid_u, err_u = validate_username(username)
    if not valid_u:
        return False, err_u

    valid_p, err_p = validate_password(password)
    if not valid_p:
        return False, err_p

    if role not in permissions_config.ROLES:
        return False, f"Neplatná role (povoleno: {', '.join(permissions_config.ROLES)})."

    username = username.strip()
    hashed = hash_password(password)
    now = datetime.utcnow().isoformat()

    # Výchozí položky menu pro roli pokud nejsou zadány
    if sidebar_menu is not None:
        cleaned_menu = permissions_config.sanitize_sidebar_menu(sidebar_menu)
    else:
        cleaned_menu = permissions_config.get_default_sidebar_menu_for_role(role)
    menu_json = json.dumps(cleaned_menu)

    # Výchozí can_manage_users pokud není zadáno
    if can_manage_users is None:
        can_manage_users_val = 1 if permissions_config.can_user_manage_users(role) else 0
    else:
        can_manage_users_val = 1 if can_manage_users else 0

    try:
        with get_db_connection() as conn:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, created_at, network_bypass, permanent_unlock_allowed, permanent_unlock_max_duration, sidebar_menu, can_manage_users) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (username, hashed, role, now, 1 if network_bypass else 0, 1 if permanent_unlock_allowed else 0, int(permanent_unlock_max_duration or 60), menu_json, can_manage_users_val)
            )
            conn.commit()
            return True, f"Uživatel '{username}' byl úspěšně vytvořen."
    except sqlite3.IntegrityError:
        return False, "Uživatel s tímto jménem již existuje."
    except Exception as e:
        logger.error(f"Chyba při vytváření uživatele: {e}")
        return False, "Došlo k chybě při vytváření uživatele."


def get_user_permanent_unlock_permission(user_id: int) -> dict:
    """Získá oprávnění uživatele k trvalému odemčení a maximální povolenou dobu."""
    try:
        with get_db_connection() as conn:
            cursor = conn.execute("SELECT permanent_unlock_allowed, permanent_unlock_max_duration FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            if row:
                return {
                    "allowed": bool(row["permanent_unlock_allowed"]),
                    "max_duration": int(row["permanent_unlock_max_duration"] or 60)
                }
    except Exception as e:
        logger.error(f"Chyba při čtení permanent_unlock oprávnění: {e}")
    return {"allowed": False, "max_duration": 60}


def set_user_permanent_unlock_permission(user_id: int, allowed: bool, max_duration: int) -> tuple[bool, str]:
    """Nastaví oprávnění uživatele k trvalému odemčení a maximální dobu (v minutách)."""
    try:
        max_duration = max(1, min(1440, int(max_duration)))
        with get_db_connection() as conn:
            cursor = conn.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            if not user:
                return False, "Uživatel nebyl nalezen."
            if user["username"].lower() == "admin":
                return False, "Hlavní účet admin je chráněn."

            conn.execute(
                "UPDATE users SET permanent_unlock_allowed = ?, permanent_unlock_max_duration = ? WHERE id = ?",
                (1 if allowed else 0, max_duration, user_id)
            )
            conn.commit()
            state_str = f"povoleno (limit {max_duration} min)" if allowed else "zakázáno"
            return True, f"Trvalé odemčení pro uživatele '{user['username']}' bylo {state_str}."
    except Exception as e:
        logger.error(f"Chyba při ukládání permanent_unlock pro uživatele {user_id}: {e}")
        return False, "Chyba databáze při ukládání oprávnění."


def get_permanent_unlock_state() -> dict:
    """Získá globální stav trvalého odemčení."""
    try:
        with get_db_connection() as conn:
            cursor = conn.execute("SELECT * FROM permanent_unlock_state WHERE id = 1")
            row = cursor.fetchone()
            if not row:
                return {
                    "active": False,
                    "is_active": False,
                    "activated_by_id": None,
                    "activated_by_username": "",
                    "duration_minutes": 0,
                    "started_at": None,
                    "expires_at": None,
                    "remaining_seconds": 0
                }

            is_active = bool(row["is_active"])
            expires_at_str = row["expires_at"]
            remaining_seconds = 0

            if is_active and expires_at_str:
                try:
                    # Normalizace ISO stringu bez ohledu na Z suffix
                    clean_str = expires_at_str.rstrip("Z")
                    expires_at_dt = datetime.fromisoformat(clean_str).replace(tzinfo=timezone.utc)
                    now_dt = datetime.now(timezone.utc)
                    diff = int((expires_at_dt - now_dt).total_seconds())
                    remaining_seconds = max(0, diff)
                    if remaining_seconds <= 0:
                        is_active = False
                except Exception as ex:
                    logger.error(f"Chyba při parsování expires_at '{expires_at_str}': {ex}")

            expires_out = None
            if row["expires_at"]:
                expires_out = row["expires_at"] if row["expires_at"].endswith("Z") else (row["expires_at"] + "Z")

            return {
                "active": is_active,
                "is_active": is_active,
                "activated_by_id": row["activated_by_id"],
                "activated_by_username": row["activated_by_username"] or "",
                "duration_minutes": row["duration_minutes"] or 0,
                "started_at": row["started_at"],
                "expires_at": expires_out,
                "remaining_seconds": remaining_seconds
            }
    except Exception as e:
        logger.error(f"Chyba při čtení permanent_unlock_state: {e}")
        return {
            "active": False,
            "is_active": False,
            "activated_by_id": None,
            "activated_by_username": "",
            "duration_minutes": 0,
            "started_at": None,
            "expires_at": None,
            "remaining_seconds": 0
        }


def set_permanent_unlock_state(is_active: bool, user_id: int = None, username: str = None, duration_minutes: int = 0) -> dict:
    """Aktualizuje globální stav trvalého odemčení."""
    now_dt = datetime.now(timezone.utc)
    now_iso = now_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    expires_iso = None
    remaining_seconds = 0

    if is_active and duration_minutes > 0:
        expires_dt = now_dt + timedelta(minutes=duration_minutes)
        expires_iso = expires_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        remaining_seconds = duration_minutes * 60

    try:
        with get_db_connection() as conn:
            conn.execute("""
                UPDATE permanent_unlock_state
                SET is_active = ?,
                    activated_by_id = ?,
                    activated_by_username = ?,
                    duration_minutes = ?,
                    started_at = ?,
                    expires_at = ?
                WHERE id = 1
            """, (
                1 if is_active else 0,
                user_id if is_active else None,
                username if is_active else None,
                duration_minutes if is_active else 0,
                now_iso if is_active else None,
                expires_iso if is_active else None
            ))
            conn.commit()
    except Exception as e:
        logger.error(f"Chyba při aktualizaci permanent_unlock_state: {e}")

    return {
        "active": is_active,
        "is_active": is_active,
        "activated_by_id": user_id if is_active else None,
        "activated_by_username": username if is_active else "",
        "duration_minutes": duration_minutes if is_active else 0,
        "started_at": now_iso if is_active else None,
        "expires_at": expires_iso,
        "remaining_seconds": remaining_seconds
    }


def set_user_network_bypass(user_id: int, bypass: bool) -> tuple[bool, str]:
    """Nastaví nebo zruší bypass sítě Sesule pro daného uživatele."""
    try:
        with get_db_connection() as conn:
            cursor = conn.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
            user = cursor.fetchone()
            if not user:
                return False, "Uživatel nebyl nalezen."
            if user["username"].lower() == "admin":
                return False, "Hlavní účet admin je chráněn."

            conn.execute("UPDATE users SET network_bypass = ? WHERE id = ?", (1 if bypass else 0, user_id))
            conn.commit()
            state_str = "povolen" if bypass else "vypnut"
            return True, f"Bypass sítě Sesule pro uživatele '{user['username']}' byl {state_str}."
    except Exception as e:
        logger.error(f"Chyba při aktualizaci network_bypass uživatele {user_id}: {e}")
        return False, "Chyba databáze při ukládání nastavení bypassu."


def update_user_role(user_id: int, new_role: str, current_user_id: int) -> tuple[bool, str]:
    """Změna role uživatele (admin / user)."""
    if new_role not in ("admin", "user", "správce"):
        return False, "Neplatná role. Povoleno: 'user', 'správce', 'admin'."

    with get_db_connection() as conn:
        cursor = conn.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,))
        target = cursor.fetchone()
        if not target:
            return False, "Uživatel nebyl nalezen."

        if target["username"].lower() == "admin":
            return False, "Hlavní účet admin je chráněn."

        if target["role"] == "admin" and new_role != "admin":
            admin_count = conn.execute("SELECT COUNT(*) as cnt FROM users WHERE role = 'admin'").fetchone()["cnt"]
            if admin_count <= 1:
                return False, "Nelze odebrat roli jedinému zbývajícímu administrátorovi."

        conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
        conn.commit()
        return True, f"Role uživatele '{target['username']}' byla změněna na '{new_role}'."


def is_user_network_bypassed(user_id: int) -> bool:
    """Zjistí, zda má uživatel aktivní network bypass v DB."""
    try:
        with get_db_connection() as conn:
            cursor = conn.execute("SELECT network_bypass FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            if row and "network_bypass" in row.keys():
                return bool(row["network_bypass"])
            return False
    except Exception as e:
        logger.error(f"Chyba při zjišťování bypassu uživatele {user_id}: {e}")
        return False


def delete_user(user_id: int, current_user_id: int, caller_role: str = "") -> tuple[bool, str]:
    """Smazání uživatele s ochranou proti smazání účtu admin, sebe sama nebo posledního admina."""
    if user_id == current_user_id:
        return False, "Nelze smazat vlastní právě přihlášený účet."

    with get_db_connection() as conn:
        cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        target_row = cursor.fetchone()
        if not target_row:
            return False, "Uživatel nebyl nalezen."

        target = _row_to_user_dict(target_row)
        caller_user = get_user_by_id(current_user_id) if current_user_id else None
        eff_role = caller_role or (caller_user["role"] if caller_user else "user")

        if permissions_config.is_user_protected(target["username"]):
            return False, f"Uživatelský účet '{target['username']}' je chráněn konfigurací a nelze jej smazat."

        # Kontrola práva mazat uživatele podle permissions_config
        can_del, err_del = permissions_config.can_caller_edit_field(
            eff_role, current_user_id, target, "can_delete_users", caller_user
        )
        if not can_del:
            return False, err_del

        if target["role"] == "admin":
            admin_count = conn.execute("SELECT COUNT(*) as cnt FROM users WHERE role = 'admin'").fetchone()["cnt"]
            if admin_count <= 1:
                return False, "Nelze smazat jediného zbývajícího administrátora."

        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        return True, f"Uživatel '{target['username']}' byl úspěšně smazán."


def change_password(user_id: int, current_password: str, new_password: str) -> tuple[bool, str]:
    """Změna hesla přihlášeného uživatele po ověření stávajícího hesla."""
    if not current_password:
        return False, "Zadejte současné heslo."

    valid_p, err_p = validate_password(new_password)
    if not valid_p:
        return False, err_p

    with get_db_connection() as conn:
        cursor = conn.execute("SELECT id, username, password_hash FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if not user:
            return False, "Uživatel nebyl nalezen."

        if not verify_password(user["password_hash"], current_password):
            return False, "Současné heslo není správné."

        if current_password == new_password:
            return False, "Nové heslo se musí lišit od stávajícího hesla."

        new_hash = hash_password(new_password)
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
        conn.commit()
        return True, "Heslo bylo úspěšně změněno."


# ==============================================================================
# PUSH NOTIFIKACE - SPRÁVA SUBSCRIPTIONS
# ==============================================================================

def init_push_tables() -> None:
    """Inicializace tabulek pro push subscriptions."""
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS push_subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                endpoint TEXT NOT NULL UNIQUE,
                p256dh TEXT NOT NULL,
                auth_key TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_push_sub_user ON push_subscriptions(user_id)")
        conn.commit()


def save_push_subscription(user_id: int, endpoint: str, p256dh: str, auth_key: str) -> tuple[bool, str]:
    """Uloží push subscription pro uživatele."""
    now = datetime.utcnow().isoformat()
    try:
        with get_db_connection() as conn:
            # Upsert: pokud endpoint existuje, aktualizovat klíče
            existing = conn.execute("SELECT id FROM push_subscriptions WHERE endpoint = ?", (endpoint,)).fetchone()
            if existing:
                conn.execute(
                    "UPDATE push_subscriptions SET user_id = ?, p256dh = ?, auth_key = ?, created_at = ? WHERE endpoint = ?",
                    (user_id, p256dh, auth_key, now, endpoint)
                )
            else:
                conn.execute(
                    "INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth_key, created_at) VALUES (?, ?, ?, ?, ?)",
                    (user_id, endpoint, p256dh, auth_key, now)
                )
            conn.commit()
            return True, "Push notifikace aktivovány."
    except Exception as e:
        logger.error(f"Chyba při ukládání push subscription: {e}")
        return False, "Chyba při ukládání nastavení notifikací."


def remove_push_subscription(endpoint: str) -> tuple[bool, str]:
    """Odebere push subscription podle endpointu."""
    try:
        with get_db_connection() as conn:
            conn.execute("DELETE FROM push_subscriptions WHERE endpoint = ?", (endpoint,))
            conn.commit()
            return True, "Push notifikace deaktivovány."
    except Exception as e:
        logger.error(f"Chyba při odstraňování push subscription: {e}")
        return False, "Chyba při odstraňování nastavení notifikací."


def has_push_subscription(user_id: int) -> bool:
    """Zjistí, zda má uživatel aktivní push subscription."""
    try:
        with get_db_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM push_subscriptions WHERE user_id = ?", (user_id,)
            ).fetchone()
            return row["cnt"] > 0 if row else False
    except Exception:
        return False


def get_all_push_subscriptions() -> list[dict]:
    """Vrací všechny aktivní push subscriptions."""
    try:
        with get_db_connection() as conn:
            rows = conn.execute("SELECT endpoint, p256dh, auth_key FROM push_subscriptions").fetchall()
            return [{"endpoint": r["endpoint"], "keys": {"p256dh": r["p256dh"], "auth": r["auth_key"]}} for r in rows]
    except Exception as e:
        logger.error(f"Chyba při načítání push subscriptions: {e}")
        return []


# ==============================================================================
# WEBAUTHN / FIDO2 - SPRÁVA CREDENTIALS
# ==============================================================================

def init_webauthn_tables() -> None:
    """Inicializace tabulek pro WebAuthn credentials."""
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS webauthn_credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                credential_id TEXT NOT NULL UNIQUE,
                public_key TEXT NOT NULL,
                sign_count INTEGER NOT NULL DEFAULT 0,
                created_at TIMESTAMP NOT NULL,
                name TEXT DEFAULT 'Otisk prstu',
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_webauthn_user ON webauthn_credentials(user_id)")
        conn.commit()


def save_webauthn_credential(user_id: int, credential_id: str, public_key: str, sign_count: int = 0) -> tuple[bool, str]:
    """Uloží WebAuthn credential pro uživatele."""
    now = datetime.utcnow().isoformat()
    try:
        with get_db_connection() as conn:
            conn.execute(
                "INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count, created_at) VALUES (?, ?, ?, ?, ?)",
                (user_id, credential_id, public_key, sign_count, now)
            )
            conn.commit()
            return True, "Biometrické přihlášení bylo úspěšně zaregistrováno."
    except sqlite3.IntegrityError:
        return False, "Toto zařízení je již zaregistrováno."
    except Exception as e:
        logger.error(f"Chyba při ukládání WebAuthn credential: {e}")
        return False, "Chyba při registraci biometrického přihlášení."


def get_webauthn_credentials(user_id: int) -> list[dict]:
    """Vrací WebAuthn credentials uživatele."""
    try:
        with get_db_connection() as conn:
            rows = conn.execute(
                "SELECT credential_id, public_key, sign_count FROM webauthn_credentials WHERE user_id = ?",
                (user_id,)
            ).fetchall()
            return [{"credential_id": r["credential_id"], "public_key": r["public_key"], "sign_count": r["sign_count"]} for r in rows]
    except Exception as e:
        logger.error(f"Chyba při načítání WebAuthn credentials: {e}")
        return []


def get_webauthn_credentials_by_credential_id(credential_id: str) -> dict | None:
    """Najde WebAuthn credential podle credential_id."""
    try:
        with get_db_connection() as conn:
            row = conn.execute(
                "SELECT wc.credential_id, wc.public_key, wc.sign_count, wc.user_id, u.username, u.role, u.network_bypass, u.is_disabled "
                "FROM webauthn_credentials wc JOIN users u ON wc.user_id = u.id WHERE wc.credential_id = ?",
                (credential_id,)
            ).fetchone()
            if row:
                return {
                    "credential_id": row["credential_id"],
                    "public_key": row["public_key"],
                    "sign_count": row["sign_count"],
                    "user_id": row["user_id"],
                    "username": row["username"],
                    "role": row["role"],
                    "network_bypass": bool(row["network_bypass"]),
                    "is_disabled": bool(row["is_disabled"]) if "is_disabled" in row.keys() else False
                }
            return None
    except Exception as e:
        logger.error(f"Chyba při hledání WebAuthn credential: {e}")
        return None


def update_webauthn_sign_count(credential_id: str, new_count: int) -> None:
    """Aktualizuje sign_count pro WebAuthn credential."""
    try:
        with get_db_connection() as conn:
            conn.execute(
                "UPDATE webauthn_credentials SET sign_count = ? WHERE credential_id = ?",
                (new_count, credential_id)
            )
            conn.commit()
    except Exception as e:
        logger.error(f"Chyba při aktualizaci sign_count: {e}")


def has_webauthn_credentials(user_id: int) -> bool:
    """Zjistí, zda má uživatel registrované WebAuthn credentials."""
    try:
        with get_db_connection() as conn:
            row = conn.execute(
                "SELECT COUNT(*) as cnt FROM webauthn_credentials WHERE user_id = ?", (user_id,)
            ).fetchone()
            return row["cnt"] > 0 if row else False
    except Exception:
        return False


def delete_webauthn_credentials(user_id: int) -> tuple[bool, str]:
    """Smaže všechny WebAuthn credentials uživatele."""
    try:
        with get_db_connection() as conn:
            conn.execute("DELETE FROM webauthn_credentials WHERE user_id = ?", (user_id,))
            conn.commit()
            return True, "Biometrické přihlášení bylo deaktivováno."
    except Exception as e:
        logger.error(f"Chyba při mazání WebAuthn credentials: {e}")
        return False, "Chyba při deaktivaci biometrického přihlášení."


def get_user_by_id(user_id: int) -> dict | None:
    """Získá uživatele podle ID včetně všech parametrů a oprávnění."""
    try:
        with get_db_connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            if row:
                return _row_to_user_dict(row)
            return None
    except Exception as e:
        logger.error(f"Chyba při get_user_by_id({user_id}): {e}")
        return None


def update_user_permissions(
    user_id: int,
    permissions: dict,
    caller_user_id: int,
    caller_role: str,
    connection: sqlite3.Connection | None = None,
) -> tuple[bool, str]:
    """Komplexní aktualizace oprávnění a nastavení uživatele administrátorem nebo oprávněnou rolí."""
    try:
        db_context = get_db_connection() if connection is None else nullcontext(connection)
        with db_context as conn:
            cursor = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            target_row = cursor.fetchone()
            if not target_row:
                return False, "Uživatel nebyl nalezen."

            target_dict = _row_to_user_dict(target_row)
            target_username = target_dict["username"]
            is_main_admin = permissions_config.is_user_protected(target_username)
            caller_user = get_user_by_id(caller_user_id) if caller_user_id else None

            # Kontrola práv volajícího (správce vs admin vs role) pomocí permissions_config
            can_manage, err_manage = permissions_config.can_caller_manage_target(
                caller_role, caller_user_id, target_dict, caller_user
            )
            if not can_manage:
                return False, err_manage

            # 1. Role
            new_role = permissions.get("role")
            if new_role and new_role != target_dict["role"]:
                can_r, err_r = permissions_config.can_caller_edit_field(
                    caller_role, caller_user_id, target_dict, "can_change_role", caller_user
                )
                if not can_r:
                    return False, err_r

                new_role = str(new_role).strip().lower()
                if new_role not in permissions_config.ROLES:
                    return False, f"Neplatná role. Povolené: {', '.join(permissions_config.ROLES)}"
                if is_main_admin and new_role != "admin":
                    return False, "Hlavnímu chráněnému účtu nelze změnit roli."
                if caller_role != "admin" and new_role == "admin":
                    return False, "Nemáte oprávnění přiřadit administrátorskou roli."
                if target_dict["role"] == "admin" and new_role != "admin":
                    admin_cnt = conn.execute("SELECT COUNT(*) as cnt FROM users WHERE role = 'admin'").fetchone()["cnt"]
                    if admin_cnt <= 1:
                        return False, "Nelze odebrat roli jedinému zbývajícímu administrátorovi."
                conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))

            # 2. Network Bypass
            if "network_bypass" in permissions:
                new_byp = bool(permissions["network_bypass"])
                if new_byp != bool(target_dict["network_bypass"]):
                    can_byp, err_byp = permissions_config.can_caller_edit_field(
                        caller_role, caller_user_id, target_dict, "can_edit_network_bypass", caller_user
                    )
                    if not can_byp:
                        return False, err_byp
                    bypass_val = 1 if (is_main_admin or new_byp) else 0
                    conn.execute("UPDATE users SET network_bypass = ? WHERE id = ?", (bypass_val, user_id))

            # 3. Can Unlock (povolení odemykat)
            if "can_unlock" in permissions:
                new_unl = bool(permissions["can_unlock"])
                if new_unl != bool(target_dict["can_unlock"]):
                    can_unl, err_unl = permissions_config.can_caller_edit_field(
                        caller_role, caller_user_id, target_dict, "can_edit_unlock_permission", caller_user
                    )
                    if not can_unl:
                        return False, err_unl
                    can_unlock_val = 1 if (is_main_admin or new_unl) else 0
                    conn.execute("UPDATE users SET can_unlock = ? WHERE id = ?", (can_unlock_val, user_id))

            # 4. Trvalé odemčení (limity podle permissions_config)
            if "permanent_unlock_allowed" in permissions or "permanent_unlock_max_duration" in permissions:
                new_perm_allowed = bool(permissions.get("permanent_unlock_allowed", target_dict["permanent_unlock_allowed"]))
                new_perm_dur = permissions.get("permanent_unlock_max_duration", target_dict["permanent_unlock_max_duration"])
                if new_perm_allowed != bool(target_dict["permanent_unlock_allowed"]) or int(new_perm_dur) != int(target_dict["permanent_unlock_max_duration"]):
                    can_perm, err_perm = permissions_config.can_caller_edit_field(
                        caller_role, caller_user_id, target_dict, "can_edit_permanent_unlock", caller_user
                    )
                    if not can_perm:
                        return False, err_perm
                    perm_allowed = 1 if new_perm_allowed else 0
                    max_dur = permissions_config.clamp_permanent_unlock_duration(new_perm_dur, caller_role)
                    conn.execute(
                        "UPDATE users SET permanent_unlock_allowed = ?, permanent_unlock_max_duration = ? WHERE id = ?",
                        (perm_allowed, max_dur, user_id)
                    )

            # 5. Časové omezení
            if "time_restricted" in permissions or "allowed_time_from" in permissions or "allowed_days" in permissions:
                new_time_rest = bool(permissions.get("time_restricted", target_dict["time_restricted"]))
                new_from = str(permissions.get("allowed_time_from", target_dict["allowed_time_from"]) or "06:00").strip()
                new_to = str(permissions.get("allowed_time_to", target_dict["allowed_time_to"]) or "22:00").strip()
                new_days = str(permissions.get("allowed_days", target_dict["allowed_days"]) or "all").strip().lower()
                if (new_time_rest != bool(target_dict["time_restricted"]) or
                    new_from != str(target_dict["allowed_time_from"]) or
                    new_to != str(target_dict["allowed_time_to"]) or
                    new_days != str(target_dict["allowed_days"])):
                    can_time, err_time = permissions_config.can_caller_edit_field(
                        caller_role, caller_user_id, target_dict, "can_edit_time_restrictions", caller_user
                    )
                    if not can_time:
                        return False, err_time
                    if new_days not in ("all", "weekdays", "weekend"):
                        new_days = "all"
                    conn.execute(
                        "UPDATE users SET time_restricted = ?, allowed_time_from = ?, allowed_time_to = ?, allowed_days = ? WHERE id = ?",
                        (1 if new_time_rest else 0, new_from, new_to, new_days, user_id)
                    )

            # 6. Položky bočního menu (sidebar_menu)
            if "sidebar_menu" in permissions:
                cleaned_menu = permissions_config.sanitize_sidebar_menu(permissions["sidebar_menu"])
                if set(cleaned_menu) != set(target_dict.get("sidebar_menu", [])):
                    can_side, err_side = permissions_config.can_caller_edit_field(
                        caller_role, caller_user_id, target_dict, "can_edit_sidebar_menu", caller_user
                    )
                    if not can_side:
                        return False, err_side
                    conn.execute(
                        "UPDATE users SET sidebar_menu = ? WHERE id = ?",
                        (json.dumps(cleaned_menu), user_id)
                    )

            # 7. Oprávnění ke správě jiných uživatelů (can_manage_users, user_management_permissions)
            if "can_manage_users" in permissions or "user_management_permissions" in permissions:
                can_mgmt, err_mgmt = permissions_config.can_caller_edit_field(
                    caller_role, caller_user_id, target_dict, "can_edit_management_rights", caller_user
                )
                if not can_mgmt:
                    return False, err_mgmt

                c_manage_val = 1 if permissions.get("can_manage_users") else 0
                custom_perms_val = permissions.get("user_management_permissions")
                if custom_perms_val and isinstance(custom_perms_val, dict):
                    custom_perms_json = json.dumps(custom_perms_val)
                elif isinstance(custom_perms_val, str) and custom_perms_val.strip():
                    custom_perms_json = custom_perms_val.strip()
                else:
                    custom_perms_json = None
                conn.execute(
                    "UPDATE users SET can_manage_users = ?, user_management_permissions = ? WHERE id = ?",
                    (c_manage_val, custom_perms_json, user_id)
                )

            # 8. Interní poznámka
            if "user_note" in permissions:
                note = str(permissions["user_note"] or "").strip()[:500]
                if note != str(target_dict["user_note"]):
                    can_note, err_note = permissions_config.can_caller_edit_field(
                        caller_role, caller_user_id, target_dict, "can_edit_user_note", caller_user
                    )
                    if not can_note:
                        return False, err_note
                    conn.execute("UPDATE users SET user_note = ? WHERE id = ?", (note, user_id))

            # 9. Aktivní / Deaktivovaný účet (is_disabled)
            if "is_disabled" in permissions:
                new_dis = bool(permissions["is_disabled"])
                if new_dis != bool(target_dict["is_disabled"]):
                    can_dis, err_dis = permissions_config.can_caller_edit_field(
                        caller_role, caller_user_id, target_dict, "can_toggle_account_disabled", caller_user
                    )
                    if not can_dis:
                        return False, err_dis
                    dis_val = 0 if is_main_admin else (1 if new_dis else 0)
                    conn.execute("UPDATE users SET is_disabled = ? WHERE id = ?", (dis_val, user_id))

            # 10. Reset hesla (pokud je zadáno)
            new_password = permissions.get("new_password")
            if new_password and str(new_password).strip():
                can_pwd, err_pwd = permissions_config.can_caller_edit_field(
                    caller_role, caller_user_id, target_dict, "can_reset_password", caller_user
                )
                if not can_pwd:
                    return False, err_pwd
                valid_p, err_p = validate_password(str(new_password).strip())
                if not valid_p:
                    return False, f"Neplatné heslo: {err_p}"
                new_hash = hash_password(str(new_password).strip())
                conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))

            # 11. Odemknout uzamčený účet
            if permissions.get("unlock_account"):
                can_unl_acc, err_unl_acc = permissions_config.can_caller_edit_field(
                    caller_role, caller_user_id, target_dict, "can_unlock_account", caller_user
                )
                if not can_unl_acc:
                    return False, err_unl_acc
                conn.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))

            if connection is None:
                conn.commit()
            return True, f"Oprávnění uživatele '{target_username}' byla úspěšně uložena."
    except Exception as e:
        logger.error(f"Chyba při aktualizaci oprávnění uživatele {user_id}: {e}")
        return False, "Chyba databáze při ukládání oprávnění."


def get_user_by_username(username: str) -> dict | None:
    """Získá uživatele podle jména včetně všech parametrů a oprávnění."""
    try:
        with get_db_connection() as conn:
            row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if row:
                return _row_to_user_dict(row)
            return None
    except Exception as e:
        logger.error(f"Chyba při get_user_by_username({username}): {e}")
        return None



def get_user_schedule(user_id: int) -> dict:
    """Načte rozvrh odemykání pro daného uživatele (slovník {day: [hours]})."""
    try:
        with get_db_connection() as conn:
            row = conn.execute(
                "SELECT schedule_json FROM user_schedule WHERE user_id = ?", (user_id,)
            ).fetchone()
            if row and row["schedule_json"]:
                return json.loads(row["schedule_json"])
            return {}
    except Exception as e:
        logger.error(f"Chyba při get_user_schedule({user_id}): {e}")
        return {}


def set_user_schedule(user_id: int, schedule: dict) -> tuple[bool, str]:
    """Uloží rozvrh odemykání pro daného uživatele.
    schedule: {day_index: [hour, ...]} kde day_index 0=Po, 6=Ne, hour 0-23.
    """
    try:
        validated: dict[str, list[int]] = {}
        for day_key, hours in schedule.items():
            day_int = int(day_key)
            if day_int < 0 or day_int > 6:
                return False, "Neplatný index dne (0-6)."
            validated_hours = []
            for h in hours:
                h_int = int(h)
                if h_int < 0 or h_int > 23:
                    return False, "Neplatná hodina (0-23)."
                validated_hours.append(h_int)
            validated[str(day_int)] = sorted(set(validated_hours))

        now = datetime.utcnow().isoformat()
        with get_db_connection() as conn:
            conn.execute(
                """INSERT INTO user_schedule (user_id, schedule_json, updated_at)
                   VALUES (?, ?, ?)
                   ON CONFLICT(user_id) DO UPDATE SET schedule_json = excluded.schedule_json,
                                                       updated_at = excluded.updated_at""",
                (user_id, json.dumps(validated), now)
            )
            # Pokud má uživatel uložen nenulový rozvrh, aktivujeme mu time_restricted v users
            has_hours = any(len(h) > 0 for h in validated.values())
            conn.execute(
                "UPDATE users SET time_restricted = ? WHERE id = ?",
                (1 if has_hours else 0, user_id)
            )
            conn.commit()
        return True, "Rozvrh uložen."
    except (ValueError, TypeError) as e:
        return False, f"Neplatný formát dat: {e}"
    except Exception as e:
        logger.error(f"Chyba při set_user_schedule({user_id}): {e}")
        return False, "Chyba databáze při ukládání rozvrhu."


def check_user_schedule(user_id: int, now_dt: datetime = None) -> tuple[bool, str]:
    """
    Zkontroluje, zda má uživatel podle rozvrhu (tabulka user_schedule) povoleno odemknout v daný čas.
    Vrací (povoleno: bool, duvod: str).
    Pokud uživatel nemá žádný rozvrh definovaný, vrací True (žádné omezení).
    Pokud uživatel má rozvrh s nastavenými hodinami, musí aktuální hodina odpovídat.
    """
    schedule = get_user_schedule(user_id)
    if not schedule:
        return True, ""

    # Pokud je rozvrh prázdný objekt nebo všechny dny jsou prázdné
    has_any_slots = any(isinstance(hours, list) and len(hours) > 0 for hours in schedule.values())
    if not has_any_slots:
        return True, ""

    if now_dt is None:
        now_dt = datetime.now()

    # datetime.weekday(): 0 = Pondělí, 6 = Neděle (stejně jako v naší tabulce)
    day_str = str(now_dt.weekday())
    cur_hour = now_dt.hour

    day_names = ["pondělí", "úterý", "středu", "čtvrtek", "pátek", "sobotu", "neděli"]
    current_day_name = day_names[now_dt.weekday()]

    allowed_hours = schedule.get(day_str)
    if not allowed_hours or not isinstance(allowed_hours, list) or len(allowed_hours) == 0:
        return False, f"V {current_day_name} nemáte podle rozvrhu povolen přístup."

    if cur_hour not in allowed_hours:
        return False, f"V tento čas ({cur_hour:02d}:00–{cur_hour:02d}:59) nemáte podle rozvrhu povolen přístup."

    return True, ""
