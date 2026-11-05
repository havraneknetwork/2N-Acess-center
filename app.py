import collections
from contextlib import nullcontext
import hashlib
from datetime import datetime, timedelta, timezone
import functools
import hmac
import ipaddress
import os
import json
import logging
import secrets
import time
import base64
import sqlite3
import threading
import fcntl
from zoneinfo import ZoneInfo
from flask import Flask, jsonify, request, send_from_directory, redirect, session
import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from cryptography.fernet import Fernet, InvalidToken

import config
import auth
import permissions_config
from ntp_clock import normalize_ntp_server, query_ntp_server

import pywebpush
from pywebpush import webpush, WebPushException
import webauthn
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    AuthenticatorAttachment,
    PublicKeyCredentialDescriptor,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

UNIT_TYPES = (
    "2N IP Verso",
    "2N IP Verso 2.0",
    "2N IP Style",
    "2N IP Force 2.0",
    "2N IP Solo",
    "2N IP Solo 2.0",
    "2N IP One",
    "2N IP Force",
    "2N IP Safety",
    "2N IP Vario",
    "2N IP Base",
    "2N IP Uni",
    "2N IP Audio Kit",
    "2N IP Video Kit",
    "2N Access Unit 2.0",
    "2N Access Unit 2.0 RFID",
    "2N Access Unit 2.0 Bluetooth & RFID",
    "2N Access Unit 2.0 Touch Keypad",
    "2N Access Unit M",
    "2N Access Unit QR",
    "2N Access Unit RFID",
    "2N Access Unit Bluetooth",
)

_unit_cipher_key = base64.urlsafe_b64encode(
    hashlib.sha256(b"door-units:" + config.SECRET_KEY.encode("utf-8")).digest()
)
UNIT_CIPHER = Fernet(_unit_cipher_key)

# Potlačení varování o nezabezpečeném HTTPS (při vlastních/self-signed certifikátech na LAN)
if not config.VERIFY_SSL:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__, static_folder="static", static_url_path="")

# Konfigurace Flask Session
app.secret_key = config.SECRET_KEY
app.config.update(
    SESSION_COOKIE_NAME=config.SESSION_COOKIE_NAME,
    SESSION_COOKIE_HTTPONLY=config.SESSION_COOKIE_HTTPONLY,
    SESSION_COOKIE_SAMESITE=config.SESSION_COOKIE_SAMESITE,
    SESSION_COOKIE_SECURE=config.SESSION_COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(days=config.REMEMBER_ME_DAYS),
    SEND_FILE_MAX_AGE_DEFAULT=0
)

# Inicializace databáze a administrátorského účtu
auth.init_db()
auth.init_push_tables()
auth.init_webauthn_tables()


def init_security_keys_db():
    with auth.get_db_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS app_schema_migrations (
                name TEXT PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS app_settings (
                setting_key TEXT PRIMARY KEY,
                setting_value TEXT NOT NULL,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS security_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                card_hash TEXT NOT NULL UNIQUE,
                action TEXT NOT NULL CHECK (action IN ('unlock', 'ring', 'permanent_toggle', 'web_block_toggle')),
                last_triggered_at REAL NOT NULL DEFAULT 0,
                created_by INTEGER,
                unit_id INTEGER REFERENCES units(id) ON DELETE CASCADE,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS security_key_registration (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                expires_at REAL NOT NULL,
                card_hash TEXT,
                valid INTEGER,
                unit_id INTEGER REFERENCES units(id) ON DELETE CASCADE,
                started_by INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS security_key_controls (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                web_unlock_blocked INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS units (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL COLLATE NOCASE UNIQUE,
                model TEXT NOT NULL,
                ip TEXT NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'https',
                port INTEGER NOT NULL DEFAULT 443,
                api_username TEXT NOT NULL,
                api_password_encrypted TEXT NOT NULL,
                auth_type TEXT NOT NULL DEFAULT 'digest',
                switch_id INTEGER NOT NULL DEFAULT 1,
                switch_action TEXT NOT NULL DEFAULT 'trigger',
                is_legacy INTEGER NOT NULL DEFAULT 0,
                connected INTEGER NOT NULL DEFAULT 0,
                last_seen TEXT,
                last_unlock_at REAL NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_units_ip_port ON units(ip, port);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_units_single_legacy
                ON units(is_legacy) WHERE is_legacy = 1;
            CREATE TABLE IF NOT EXISTS user_unit_preferences (
                user_id INTEGER PRIMARY KEY,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS user_display_units (
                user_id INTEGER NOT NULL,
                unit_id INTEGER NOT NULL,
                PRIMARY KEY (user_id, unit_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (unit_id) REFERENCES units(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS user_unit_access (
                user_id INTEGER NOT NULL,
                unit_id INTEGER NOT NULL,
                can_unlock INTEGER NOT NULL DEFAULT 1,
                network_bypass INTEGER NOT NULL DEFAULT 0,
                permanent_unlock_allowed INTEGER NOT NULL DEFAULT 0,
                permanent_unlock_max_duration INTEGER NOT NULL DEFAULT 60,
                PRIMARY KEY (user_id, unit_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (unit_id) REFERENCES units(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS user_unit_schedule (
                user_id INTEGER NOT NULL,
                unit_id INTEGER NOT NULL,
                schedule_json TEXT NOT NULL DEFAULT '{}',
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (user_id, unit_id),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (unit_id) REFERENCES units(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS unit_permanent_unlock_state (
                unit_id INTEGER PRIMARY KEY,
                is_active INTEGER NOT NULL DEFAULT 0,
                activated_by_id INTEGER,
                activated_by_username TEXT,
                duration_minutes INTEGER NOT NULL DEFAULT 0,
                started_at TEXT,
                expires_at TEXT,
                FOREIGN KEY (unit_id) REFERENCES units(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS unit_web_unlock_controls (
                unit_id INTEGER PRIMARY KEY,
                web_unlock_blocked INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (unit_id) REFERENCES units(id) ON DELETE CASCADE
            );
        """)
        conn.execute("BEGIN IMMEDIATE")
        legacy_seed_migration = "legacy_unit_seed_v1"
        has_units = conn.execute("SELECT 1 FROM units LIMIT 1").fetchone() is not None
        legacy_seeded = conn.execute(
            "SELECT 1 FROM app_schema_migrations WHERE name = ?",
            (legacy_seed_migration,)
        ).fetchone() is not None
        if has_units:
            conn.execute(
                "INSERT OR IGNORE INTO app_schema_migrations (name) VALUES (?)",
                (legacy_seed_migration,)
            )
        elif not legacy_seeded and config.DEVICE_IP and config.API_USERNAME and config.API_PASSWORD:
            conn.execute(
                """
                INSERT INTO units (
                    name, model, ip, protocol, port, api_username,
                    api_password_encrypted, auth_type, switch_id, switch_action, is_legacy
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    f"2N {config.DEVICE_IP}",
                    "2N Access Unit M",
                    config.DEVICE_IP,
                    config.DEVICE_PROTOCOL,
                    config.DEVICE_PORT,
                    config.API_USERNAME,
                    UNIT_CIPHER.encrypt(config.API_PASSWORD.encode("utf-8")).decode("ascii"),
                    config.AUTH_TYPE,
                    config.SWITCH_ID,
                    config.SWITCH_ACTION,
                )
            )
            conn.execute(
                "INSERT OR IGNORE INTO app_schema_migrations (name) VALUES (?)",
                (legacy_seed_migration,)
            )
        conn.commit()
        key_table_sql = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'security_keys'"
        ).fetchone()["sql"]
        if "permanent_toggle" not in key_table_sql or "web_block_toggle" not in key_table_sql:
            with conn:
                conn.execute("""
                    CREATE TABLE security_keys_migrated (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        card_hash TEXT NOT NULL UNIQUE,
                        action TEXT NOT NULL CHECK (action IN ('unlock', 'ring', 'permanent_toggle', 'web_block_toggle')),
                        last_triggered_at REAL NOT NULL DEFAULT 0,
                        created_by INTEGER,
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                old_columns = {
                    column["name"]
                    for column in conn.execute("PRAGMA table_info(security_keys)").fetchall()
                }
                last_triggered_expression = "last_triggered_at" if "last_triggered_at" in old_columns else "0"
                conn.execute(f"""
                    INSERT INTO security_keys_migrated
                        (id, name, card_hash, action, last_triggered_at, created_by, created_at)
                    SELECT id, name, card_hash, action, {last_triggered_expression}, created_by, created_at
                    FROM security_keys
                """)
                conn.execute("DROP TABLE security_keys")
                conn.execute("ALTER TABLE security_keys_migrated RENAME TO security_keys")
        else:
            key_columns = {
                column["name"]
                for column in conn.execute("PRAGMA table_info(security_keys)").fetchall()
            }
            if "last_triggered_at" not in key_columns:
                conn.execute("ALTER TABLE security_keys ADD COLUMN last_triggered_at REAL NOT NULL DEFAULT 0")
        conn.execute("INSERT OR IGNORE INTO security_key_controls (id, web_unlock_blocked) VALUES (1, 0)")
        registration_columns = {
            column["name"]
            for column in conn.execute("PRAGMA table_info(security_key_registration)").fetchall()
        }
        if "valid" not in registration_columns:
            conn.execute("ALTER TABLE security_key_registration ADD COLUMN valid INTEGER")
        conn.commit()
        conn.execute("BEGIN IMMEDIATE")
        key_columns = {
            column["name"]
            for column in conn.execute("PRAGMA table_info(security_keys)").fetchall()
        }
        if "unit_id" not in key_columns:
            conn.execute(
                "ALTER TABLE security_keys ADD COLUMN unit_id INTEGER REFERENCES units(id) ON DELETE CASCADE"
            )
        registration_columns = {
            column["name"]
            for column in conn.execute("PRAGMA table_info(security_key_registration)").fetchall()
        }
        if "unit_id" not in registration_columns:
            conn.execute(
                "ALTER TABLE security_key_registration ADD COLUMN unit_id INTEGER REFERENCES units(id) ON DELETE CASCADE"
            )

        migration = "multi_unit_settings_v1"
        if not conn.execute(
            "SELECT 1 FROM app_schema_migrations WHERE name = ?", (migration,)
        ).fetchone():
            units = conn.execute("SELECT id, is_legacy FROM units ORDER BY id").fetchall()
            users = conn.execute("SELECT * FROM users").fetchall()
            source_unit = next((unit for unit in units if unit["is_legacy"]), units[0] if units else None)
            for user in users:
                for unit in units:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO user_unit_access (
                            user_id, unit_id, can_unlock, network_bypass,
                            permanent_unlock_allowed, permanent_unlock_max_duration
                        ) VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            user["id"], unit["id"], user["can_unlock"], user["network_bypass"],
                            user["permanent_unlock_allowed"], user["permanent_unlock_max_duration"]
                        )
                    )
                    if source_unit:
                        conn.execute(
                            """
                            INSERT OR IGNORE INTO user_unit_schedule (user_id, unit_id, schedule_json)
                            SELECT user_id, ?, schedule_json FROM user_schedule WHERE user_id = ?
                            """,
                            (unit["id"], user["id"])
                        )
            if source_unit:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO unit_permanent_unlock_state (
                        unit_id, is_active, activated_by_id, activated_by_username,
                        duration_minutes, started_at, expires_at
                    )
                    SELECT ?, is_active, activated_by_id, activated_by_username,
                           duration_minutes, started_at, expires_at
                    FROM permanent_unlock_state WHERE id = 1
                    """,
                    (source_unit["id"],)
                )
                conn.execute(
                    """
                    INSERT OR IGNORE INTO unit_web_unlock_controls (unit_id, web_unlock_blocked)
                    SELECT ?, web_unlock_blocked FROM security_key_controls WHERE id = 1
                    """,
                    (source_unit["id"],)
                )
                conn.execute("UPDATE security_key_controls SET web_unlock_blocked = 0 WHERE id = 1")
            if source_unit:
                conn.execute(
                    "UPDATE security_keys SET unit_id = ? WHERE unit_id IS NULL",
                    (source_unit["id"],)
                )
            conn.execute("INSERT INTO app_schema_migrations (name) VALUES (?)", (migration,))
        conn.commit()
        migration = "security_keys_sidebar_item"
        with conn:
            conn.execute("BEGIN IMMEDIATE")
            if not conn.execute(
                "SELECT 1 FROM app_schema_migrations WHERE name = ?",
                (migration,)
            ).fetchone():
                users = conn.execute(
                    "SELECT id, sidebar_menu FROM users WHERE role IN ('admin', 'správce') AND sidebar_menu IS NOT NULL"
                ).fetchall()
                for user in users:
                    try:
                        menu = json.loads(user["sidebar_menu"])
                    except (TypeError, json.JSONDecodeError):
                        menu = []
                    if isinstance(menu, list) and "keys" not in menu:
                        menu.append("keys")
                        conn.execute(
                            "UPDATE users SET sidebar_menu = ? WHERE id = ?",
                            (json.dumps(menu, ensure_ascii=False), user["id"])
                        )
                conn.execute(
                    "INSERT INTO app_schema_migrations (name) VALUES (?)",
                    (migration,)
                )


init_security_keys_db()

APP_TIMEZONE = ZoneInfo("Europe/Prague")
_ntp_clock_lock = threading.Lock()
_ntp_clock_state = {
    "server": "",
    "offset_seconds": 0.0,
    "last_sync": None,
    "error": "NTP server není nastaven.",
    "last_attempt_monotonic": 0.0,
}


def _read_app_setting(key, default=""):
    with auth.get_db_connection() as conn:
        row = conn.execute(
            "SELECT setting_value FROM app_settings WHERE setting_key = ?",
            (key,)
        ).fetchone()
    return row["setting_value"] if row else default


def _write_app_settings(values):
    with auth.get_db_connection() as conn:
        for key, value in values.items():
            conn.execute(
                """
                INSERT INTO app_settings (setting_key, setting_value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
                ON CONFLICT(setting_key) DO UPDATE SET
                    setting_value = excluded.setting_value,
                    updated_at = CURRENT_TIMESTAMP
                """,
                (key, str(value))
            )


def _load_ntp_clock_state():
    server = _read_app_setting("ntp_server")
    try:
        offset = float(_read_app_setting("ntp_offset_seconds", "0"))
    except ValueError:
        logger.error("Uložená NTP odchylka není platné číslo; používá se nula.")
        offset = 0.0
    last_sync = _read_app_setting("ntp_last_sync") or None
    stored_error = _read_app_setting("ntp_last_error")
    error = stored_error or (
        "" if server and last_sync else
        "NTP server není nastaven." if not server else
        "Čas zatím nebyl synchronizován."
    )
    with _ntp_clock_lock:
        _ntp_clock_state.update(
            server=server,
            offset_seconds=offset if server and last_sync else 0.0,
            last_sync=last_sync,
            error=error,
            last_attempt_monotonic=0.0,
        )


def _ntp_clock_status():
    with _ntp_clock_lock:
        state = dict(_ntp_clock_state)
    return {
        "ntp_server": state["server"],
        "synchronized": bool(state["server"] and state["last_sync"] and not state["error"]),
        "last_sync": state["last_sync"],
        "offset_seconds": round(state["offset_seconds"], 3),
        "error": state["error"],
        "timezone": "Europe/Prague",
        "host_clock_changed": False,
    }


def _set_ntp_failure(server, error):
    with _ntp_clock_lock:
        if _ntp_clock_state["server"] != server:
            _ntp_clock_state["offset_seconds"] = 0.0
            _ntp_clock_state["last_sync"] = None
        _ntp_clock_state.update(
            server=server,
            error=error,
            last_attempt_monotonic=time.monotonic(),
        )
        state = dict(_ntp_clock_state)
    try:
        _write_app_settings({
            "ntp_server": server,
            "ntp_offset_seconds": state["offset_seconds"],
            "ntp_last_sync": state["last_sync"] or "",
            "ntp_last_error": error,
        })
    except sqlite3.Error:
        logger.exception("Nepodařilo se uložit stav synchronizace NTP.")


def _synchronize_ntp_server(server):
    try:
        result = query_ntp_server(server)
    except (OSError, ValueError) as error:
        message = f"NTP server se nepodařilo synchronizovat: {error}"
        _set_ntp_failure(server, message)
        logger.warning("%s", message)
        return False

    offset = result["offset_seconds"]
    synced_at = datetime.fromtimestamp(
        time.time() + offset,
        timezone.utc
    ).isoformat(timespec="seconds").replace("+00:00", "Z")
    try:
        _write_app_settings({
            "ntp_server": server,
            "ntp_offset_seconds": offset,
            "ntp_last_sync": synced_at,
            "ntp_last_error": "",
        })
    except sqlite3.Error:
        logger.exception("NTP odpověď byla přijata, ale stav se nepodařilo uložit.")
        with _ntp_clock_lock:
            _ntp_clock_state["error"] = "NTP čas byl přijat, ale jeho stav se nepodařilo uložit."
        return False
    with _ntp_clock_lock:
        _ntp_clock_state.update(
            server=server,
            offset_seconds=offset,
            last_sync=synced_at,
            error="",
            last_attempt_monotonic=time.monotonic(),
        )
    logger.info(
        "Aplikační čas synchronizován s NTP serverem %s (odchylka %.3f s, stratum %s).",
        server, offset, result["stratum"]
    )
    return True


def _ntp_sync_worker():
    while True:
        try:
            server = _read_app_setting("ntp_server")
            if not server:
                with _ntp_clock_lock:
                    _ntp_clock_state.update(
                        server="",
                        offset_seconds=0.0,
                        last_sync=None,
                        error="NTP server není nastaven.",
                        last_attempt_monotonic=time.monotonic(),
                    )
            else:
                with _ntp_clock_lock:
                    should_sync = (
                        server != _ntp_clock_state["server"]
                        or time.monotonic() - _ntp_clock_state["last_attempt_monotonic"] >= 300
                    )
                    if should_sync:
                        _ntp_clock_state["last_attempt_monotonic"] = time.monotonic()
                if should_sync:
                    _synchronize_ntp_server(server)
        except (sqlite3.Error, OSError):
            logger.exception("Chyba při automatické synchronizaci aplikačního času.")
        time.sleep(30)


def application_now_utc():
    with _ntp_clock_lock:
        offset = _ntp_clock_state["offset_seconds"]
    return datetime.fromtimestamp(time.time() + offset, timezone.utc)


_load_ntp_clock_state()


def decrypt_unit_password(encrypted_password):
    try:
        return UNIT_CIPHER.decrypt(encrypted_password.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError, AttributeError) as error:
        raise RuntimeError("Nepodařilo se dešifrovat heslo jednotky; ověřte, že se nezměnil SECRET_KEY.") from error


def get_unit(unit_id, include_secret=False):
    with auth.get_db_connection() as conn:
        row = conn.execute("SELECT * FROM units WHERE id = ?", (unit_id,)).fetchone()
    if not row:
        return None
    unit = dict(row)
    if include_secret:
        unit["api_password"] = decrypt_unit_password(unit.pop("api_password_encrypted"))
    else:
        unit.pop("api_password_encrypted", None)
    return unit


def get_units(include_secret=False):
    with auth.get_db_connection() as conn:
        rows = conn.execute("SELECT * FROM units ORDER BY id").fetchall()
    units = []
    for row in rows:
        unit = dict(row)
        if include_secret:
            unit["api_password"] = decrypt_unit_password(unit.pop("api_password_encrypted"))
        else:
            unit.pop("api_password_encrypted", None)
        units.append(unit)
    return units


def public_unit(unit):
    return {
        "id": unit["id"],
        "name": unit["name"],
        "model": unit["model"],
        "ip": unit["ip"],
        "protocol": unit["protocol"],
        "port": unit["port"],
        "api_username": unit["api_username"],
        "auth_type": unit["auth_type"],
        "is_legacy": bool(unit["is_legacy"]),
        "connected": bool(unit["connected"]),
        "last_seen": unit["last_seen"],
    }


def unit_base_url(protocol, ip, port):
    host = f"[{ip}]" if ":" in ip and not ip.startswith("[") else ip
    return f"{protocol}://{host}:{port}"


def unit_auth_handlers(username, password, preferred="digest"):
    primary = HTTPDigestAuth(username, password) if preferred == "digest" else HTTPBasicAuth(username, password)
    fallback = HTTPBasicAuth(username, password) if preferred == "digest" else HTTPDigestAuth(username, password)
    return ((primary, preferred), (fallback, "basic" if preferred == "digest" else "digest"))


def probe_unit_connection(ip, username, password, preferred_protocol=None, preferred_port=None, preferred_auth="digest"):
    protocol_order = [preferred_protocol] if preferred_protocol in ("https", "http") else []
    protocol_order.extend(protocol for protocol in ("https", "http") if protocol not in protocol_order)
    candidates = []
    if preferred_port and preferred_protocol in ("https", "http"):
        candidates.append((preferred_protocol, int(preferred_port)))
    for protocol in protocol_order:
        default_port = 443 if protocol == "https" else 80
        if (protocol, default_port) not in candidates:
            candidates.append((protocol, default_port))
    for protocol, port in candidates:
        url = f"{unit_base_url(protocol, ip, port)}/api/switch/caps"
        for handler, auth_type in unit_auth_handlers(username, password, preferred_auth):
            try:
                response = requests.get(
                    url,
                    auth=handler,
                    timeout=config.REQUEST_TIMEOUT,
                    verify=config.VERIFY_SSL
                )
            except requests.RequestException:
                continue
            if response.status_code == 200:
                return {"protocol": protocol, "port": port, "auth_type": auth_type}
    return None


def unit_is_selected_for_user(user_id, unit_id):
    with auth.get_db_connection() as conn:
        configured = conn.execute(
            "SELECT 1 FROM user_unit_preferences WHERE user_id = ?",
            (user_id,)
        ).fetchone()
        if not configured:
            return True
        return conn.execute(
            "SELECT 1 FROM user_display_units WHERE user_id = ? AND unit_id = ?",
            (user_id, unit_id)
        ).fetchone() is not None


def get_unit_access(user_id, unit_id):
    with auth.get_db_connection() as conn:
        row = conn.execute(
            "SELECT * FROM user_unit_access WHERE user_id = ? AND unit_id = ?",
            (user_id, unit_id)
        ).fetchone()
    if row:
        return dict(row)
    user = auth.get_user_by_id(user_id) if user_id else None
    return {
        "user_id": user_id,
        "unit_id": unit_id,
        "can_unlock": int(user.get("can_unlock", True)) if user else 0,
        "network_bypass": int(user.get("network_bypass", False)) if user else 0,
        "permanent_unlock_allowed": int(user.get("permanent_unlock_allowed", False)) if user else 0,
        "permanent_unlock_max_duration": user.get("permanent_unlock_max_duration", 60) if user else 60,
    }


def save_user_unit_access(user_id, unit_access, caller_id, caller_role, dry_run=False, connection=None):
    if not isinstance(unit_access, list):
        return False, "Nastavení oprávnění jednotek musí být seznam."
    target_user = auth.get_user_by_id(user_id)
    if not target_user or target_user.get("username", "").lower() == "admin":
        return False, "Oprávnění tohoto účtu nelze upravit."
    if caller_role == "správce" and (user_id == caller_id or target_user.get("role") != "user"):
        return False, "Správce může upravovat pouze běžné účty ostatních uživatelů."

    caller_user = auth.get_user_by_id(caller_id) if caller_id else None
    caller_permissions = permissions_config.get_caller_management_permissions(caller_role, caller_user)
    can_edit = {
        "can_unlock": caller_role == "admin" or caller_permissions.get("can_edit_can_unlock", False),
        "network_bypass": caller_role == "admin" or caller_permissions.get("can_edit_network_bypass", False),
        "permanent_unlock_allowed": caller_role == "admin" or caller_permissions.get("can_edit_permanent_unlock", False),
        "permanent_unlock_max_duration": caller_role == "admin" or caller_permissions.get("can_edit_permanent_unlock", False),
    }

    try:
        db_context = auth.get_db_connection() if connection is None else nullcontext(connection)
        with db_context as conn:
            existing_ids = {row["id"] for row in conn.execute("SELECT id FROM units").fetchall()}
            seen = set()
            validated = []
            for entry in unit_access:
                if not isinstance(entry, dict):
                    return False, "Neplatné nastavení jednotky."
                unit_id = entry.get("unit_id")
                if not isinstance(unit_id, int) or isinstance(unit_id, bool) or unit_id not in existing_ids or unit_id in seen:
                    return False, "Některá jednotka chybí nebo je uvedena vícekrát."
                seen.add(unit_id)
                for field in ("can_unlock", "network_bypass", "permanent_unlock_allowed"):
                    if field in entry and not isinstance(entry[field], bool):
                        return False, "Příznak oprávnění musí být typu boolean."
                try:
                    duration = int(entry.get("permanent_unlock_max_duration", 60))
                except (ValueError, TypeError):
                    return False, "Neplatný limit trvalého odemčení."
                if not 1 <= duration <= 1440:
                    return False, "Limit trvalého odemčení musí být 1 až 1440 minut."
                validated.append((unit_id, entry, duration))

            expected_ids = existing_ids
            if seen != expected_ids:
                return False, "Odešlete nastavení pro všechny dostupné jednotky."

            if dry_run:
                return True, "Oprávnění jednotek jsou platná."

            if not conn.in_transaction:
                conn.execute("BEGIN IMMEDIATE")
            for unit_id, entry, duration in validated:
                current = conn.execute(
                    "SELECT * FROM user_unit_access WHERE user_id = ? AND unit_id = ?",
                    (user_id, unit_id)
                ).fetchone()
                if not current:
                    current = {
                        "can_unlock": int(target_user.get("can_unlock", True)),
                        "network_bypass": int(target_user.get("network_bypass", False)),
                        "permanent_unlock_allowed": int(target_user.get("permanent_unlock_allowed", False)),
                        "permanent_unlock_max_duration": target_user.get("permanent_unlock_max_duration", 60),
                    }
                values = {
                    field: int(entry[field]) if can_edit[field] and field in entry else int(current[field])
                    for field in ("can_unlock", "network_bypass", "permanent_unlock_allowed")
                }
                max_duration = (
                    duration if can_edit["permanent_unlock_max_duration"]
                    else int(current["permanent_unlock_max_duration"])
                )
                if caller_role == "správce":
                    max_duration = min(max_duration, 120)
                conn.execute(
                    """
                    INSERT INTO user_unit_access (
                        user_id, unit_id, can_unlock, network_bypass,
                        permanent_unlock_allowed, permanent_unlock_max_duration
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(user_id, unit_id) DO UPDATE SET
                        can_unlock = excluded.can_unlock,
                        network_bypass = excluded.network_bypass,
                        permanent_unlock_allowed = excluded.permanent_unlock_allowed,
                        permanent_unlock_max_duration = excluded.permanent_unlock_max_duration
                    """,
                    (
                        user_id, unit_id, values["can_unlock"], values["network_bypass"],
                        values["permanent_unlock_allowed"], max_duration
                    )
                )
    except sqlite3.Error:
        logger.exception("Nepodařilo se uložit oprávnění jednotek pro uživatele %s.", user_id)
        return False, "Chyba databáze při ukládání oprávnění jednotek."
    return True, "Oprávnění jednotek byla uložena."


def get_unit_schedule(user_id, unit_id):
    with auth.get_db_connection() as conn:
        row = conn.execute(
            "SELECT schedule_json FROM user_unit_schedule WHERE user_id = ? AND unit_id = ?",
            (user_id, unit_id)
        ).fetchone()
    if not row:
        return {}
    try:
        schedule = json.loads(row["schedule_json"])
    except (TypeError, json.JSONDecodeError) as error:
        logger.exception("Neplatný rozvrh uživatele %s pro jednotku %s.", user_id, unit_id)
        raise ValueError(f"Rozvrh uživatele {user_id} pro jednotku {unit_id} je poškozen.") from error
    if not isinstance(schedule, dict):
        raise ValueError(f"Rozvrh uživatele {user_id} pro jednotku {unit_id} má neplatný formát.")
    return schedule


def set_unit_schedule(user_id, unit_id, schedule):
    if not isinstance(schedule, dict):
        return False, "Pole rozvrhu musí být objekt."
    validated = {}
    try:
        for day_key, hours in schedule.items():
            day = int(day_key)
            if day < 0 or day > 6 or not isinstance(hours, list):
                return False, "Neplatný den nebo seznam hodin rozvrhu."
            parsed = sorted({int(hour) for hour in hours})
            if any(hour < 0 or hour > 23 for hour in parsed):
                return False, "Hodiny rozvrhu musí být mezi 0 a 23."
            validated[str(day)] = parsed
    except (ValueError, TypeError):
        return False, "Neplatný formát rozvrhu."
    with auth.get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO user_unit_schedule (user_id, unit_id, schedule_json, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id, unit_id) DO UPDATE SET
                schedule_json = excluded.schedule_json,
                updated_at = CURRENT_TIMESTAMP
            """,
            (user_id, unit_id, json.dumps(validated))
        )
    return True, "Rozvrh jednotky uložen."


def check_unit_schedule(user_id, unit_id, now_dt=None):
    try:
        schedule = get_unit_schedule(user_id, unit_id)
    except ValueError as error:
        return False, str(error)
    if not any(isinstance(hours, list) and hours for hours in schedule.values()):
        return True, ""
    now_dt = now_dt or application_now_utc().astimezone(APP_TIMEZONE)
    allowed_hours = schedule.get(str(now_dt.weekday()), [])
    if now_dt.hour in allowed_hours:
        return True, ""
    return False, "V tuto dobu nemáte podle rozvrhu povolené odemykání této jednotky."


def get_unit_permanent_state(unit_id):
    with auth.get_db_connection() as conn:
        row = conn.execute(
            "SELECT * FROM unit_permanent_unlock_state WHERE unit_id = ?",
            (unit_id,)
        ).fetchone()
    if not row:
        return {
            "active": False, "is_active": False, "activated_by_id": None,
            "activated_by_username": "", "duration_minutes": 0, "started_at": None,
            "expires_at": None, "remaining_seconds": 0, "unit_id": unit_id,
        }
    state = dict(row)
    remaining = 0
    active = bool(state["is_active"])
    if active and state["expires_at"]:
        try:
            expires = datetime.fromisoformat(state["expires_at"].rstrip("Z")).replace(tzinfo=timezone.utc)
            remaining = max(0, int((expires - application_now_utc()).total_seconds()))
            if remaining == 0:
                active = False
        except ValueError:
            logger.exception("Neplatný čas expirace trvalého odemčení jednotky %s.", unit_id)
    return {
        **state,
        "active": active,
        "is_active": active,
        "activated_by_username": state["activated_by_username"] or "",
        "expires_at": state["expires_at"] if not state["expires_at"] or state["expires_at"].endswith("Z") else f"{state['expires_at']}Z",
        "remaining_seconds": remaining,
    }


def set_unit_permanent_state(unit_id, active, user_id=None, username=None, duration_minutes=0):
    now = application_now_utc()
    started_at = now.strftime("%Y-%m-%dT%H:%M:%SZ") if active else None
    expires_at = (
        (now + timedelta(minutes=duration_minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
        if active and duration_minutes > 0 else None
    )
    with auth.get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO unit_permanent_unlock_state (
                unit_id, is_active, activated_by_id, activated_by_username,
                duration_minutes, started_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(unit_id) DO UPDATE SET
                is_active = excluded.is_active,
                activated_by_id = excluded.activated_by_id,
                activated_by_username = excluded.activated_by_username,
                duration_minutes = excluded.duration_minutes,
                started_at = excluded.started_at,
                expires_at = excluded.expires_at
            """,
            (
                unit_id, int(active), user_id if active else None, username if active else None,
                duration_minutes if active else 0, started_at, expires_at
            )
        )
    return get_unit_permanent_state(unit_id)


def is_web_unlock_blocked(unit_id=None):
    with auth.get_db_connection() as conn:
        global_row = conn.execute(
            "SELECT web_unlock_blocked FROM security_key_controls WHERE id = 1"
        ).fetchone()
        if global_row and global_row["web_unlock_blocked"]:
            return True
        if unit_id is None:
            return False
        row = conn.execute(
            "SELECT web_unlock_blocked FROM unit_web_unlock_controls WHERE unit_id = ?",
            (unit_id,)
        ).fetchone()
    return bool(row and row["web_unlock_blocked"])


def toggle_web_unlock_blocked(unit_id=None):
    with auth.get_db_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if unit_id is None:
            row = conn.execute(
                "SELECT web_unlock_blocked FROM security_key_controls WHERE id = 1"
            ).fetchone()
            if not row:
                raise RuntimeError("Chybí globální nastavení blokace webového odemykání.")
            is_blocked = not bool(row["web_unlock_blocked"])
            conn.execute(
                "UPDATE security_key_controls SET web_unlock_blocked = ? WHERE id = 1",
                (int(is_blocked),)
            )
        else:
            row = conn.execute(
                "SELECT web_unlock_blocked FROM unit_web_unlock_controls WHERE unit_id = ?",
                (unit_id,)
            ).fetchone()
            is_blocked = not bool(row and row["web_unlock_blocked"])
            conn.execute(
                """
                INSERT INTO unit_web_unlock_controls (unit_id, web_unlock_blocked)
                VALUES (?, ?)
                ON CONFLICT(unit_id) DO UPDATE SET web_unlock_blocked = excluded.web_unlock_blocked
                """,
                (unit_id, int(is_blocked))
            )
    return is_blocked

# ==============================================================================
# SDÍLENÝ LOG UDÁLOSTÍ (soubor, přístupný všem gunicorn workerům)
# ==============================================================================
ACTIVITY_LOG_PATH = os.path.join(config.DATA_DIR, "activity_log.json")
ACTIVITY_LOG_MAX = 300


ACTIVITY_LOG_LOCK_PATH = ACTIVITY_LOG_PATH + ".lock"


def _read_logs() -> list:
    """Přečte logy ze sdíleného souboru. Vrací prázdný seznam při chybě."""
    try:
        with open(ACTIVITY_LOG_LOCK_PATH, "a") as lock_f:
            fcntl.flock(lock_f, fcntl.LOCK_SH)
            try:
                with open(ACTIVITY_LOG_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    return data if isinstance(data, list) else []
            except (FileNotFoundError, json.JSONDecodeError, ValueError):
                return []
            finally:
                fcntl.flock(lock_f, fcntl.LOCK_UN)
    except Exception:
        return []


def _write_logs(logs: list):
    """Zapíše logy do sdíleného souboru atomicky s exkluzivním zámkem."""
    try:
        with open(ACTIVITY_LOG_LOCK_PATH, "a") as lock_f:
            fcntl.flock(lock_f, fcntl.LOCK_EX)
            try:
                tmp_path = ACTIVITY_LOG_PATH + ".tmp"
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(logs[-ACTIVITY_LOG_MAX:], f, ensure_ascii=False)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_path, ACTIVITY_LOG_PATH)
            finally:
                fcntl.flock(lock_f, fcntl.LOCK_UN)
    except Exception as e:
        logger.warning(f"Nelze zapsat activity log: {e}")


def add_log(level, title, message="", details=None, unit_id=None, unit_name=None):
    """Přidá záznam do sdíleného aktivity logu a do standardního loggeru."""
    now_local = application_now_utc().astimezone(APP_TIMEZONE)
    timestamp = now_local.strftime("%H:%M:%S")
    entry = {
        "time": timestamp,
        "timestamp": now_local.isoformat(timespec="seconds"),
        "level": level.lower(),
        "title": title,
        "message": message,
        "details": details,
        "source_type": "unit" if unit_id is not None else "system",
        "unit_id": unit_id,
        "unit_name": unit_name,
    }
    logs = _read_logs()
    logs.append(entry)
    _write_logs(logs)
    log_func = getattr(logger, level.lower() if hasattr(logger, level.lower()) else "info")
    log_func(f"[{title}] {message} {details if details else ''}")


CARD_IDENTIFIER_FIELDS = {
    "card", "cardid", "cardnumber", "cardno", "cardcode", "cardvalue",
    "carduid", "cardserial", "cardidentifier", "rfid", "rfidid",
    "tag", "tagid", "credential", "credentialid", "credentialvalue", "uid"
}


def toggle_permanent_unlock_from_key(key_name, units):
    results = []
    for unit in units:
        target_active = not get_unit_permanent_state(unit["id"])["active"]
        action = "hold" if target_active else "release"
        success, message, elapsed_ms, _ = send_unit_switch_command(unit, action)
        if not success:
            add_log(
                "error", "RFID TRVALÉ ODEMČENÍ",
                f"Akce klíče '{key_name}' na jednotce '{unit['name']}' selhala: {message}.",
                unit_id=unit["id"], unit_name=unit["name"]
            )
            results.append(False)
            continue
        set_unit_permanent_state(
            unit["id"], target_active,
            username=f"RFID: {key_name}" if target_active else None,
            duration_minutes=0
        )
        title = "TRVALE ODEMČENO RFID KLÍČEM" if target_active else "UZAMČENO RFID KLÍČEM"
        message = (
            f"Klíč '{key_name}' aktivoval trvalé odemčení bez časového limitu."
            if target_active else f"Klíč '{key_name}' ukončil trvalé odemčení."
        )
        add_log("success", title, f"{unit['name']}: {message} ({elapsed_ms} ms).", unit_id=unit["id"], unit_name=unit["name"])
        results.append(True)
    return bool(results) and all(results)


def security_key_target_units(unit_id, event_unit_id):
    if unit_id is not None:
        if unit_id != event_unit_id:
            return []
        target_ids = [unit_id]
    else:
        target_ids = [unit["id"] for unit in get_units()]
    return [
        unit for target_id in target_ids
        if (unit := get_unit(target_id, include_secret=True)) is not None
    ]


def extract_card_identifier(value):
    if isinstance(value, dict):
        for key, candidate in value.items():
            normalized_key = "".join(char for char in str(key).casefold() if char.isalnum())
            if normalized_key in CARD_IDENTIFIER_FIELDS and isinstance(candidate, (str, int)) and not isinstance(candidate, bool):
                identifier = str(candidate).strip()
                if identifier and len(identifier) <= 128:
                    return identifier
        for candidate in value.values():
            identifier = extract_card_identifier(candidate)
            if identifier:
                return identifier
    elif isinstance(value, (list, tuple)):
        for candidate in value:
            identifier = extract_card_identifier(candidate)
            if identifier:
                return identifier
    return None


def extract_card_validity(value):
    if isinstance(value, dict):
        for key, candidate in value.items():
            normalized_key = "".join(char for char in str(key).casefold() if char.isalnum())
            if normalized_key == "valid":
                if isinstance(candidate, bool):
                    return candidate
                if isinstance(candidate, int) and candidate in (0, 1):
                    return bool(candidate)
                if isinstance(candidate, str):
                    normalized_value = candidate.strip().casefold()
                    if normalized_value in ("true", "1"):
                        return True
                    if normalized_value in ("false", "0"):
                        return False
            nested_value = extract_card_validity(candidate)
            if nested_value is not None:
                return nested_value
    elif isinstance(value, (list, tuple)):
        for candidate in value:
            nested_value = extract_card_validity(candidate)
            if nested_value is not None:
                return nested_value
    return None


def hash_card_identifier(identifier):
    normalized = identifier.strip().casefold()
    return hmac.new(
        config.SECRET_KEY.encode("utf-8"),
        normalized.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()


def redact_card_identifiers(value):
    if isinstance(value, dict):
        return {
            key: (
                "[skryto]"
                if "".join(char for char in str(key).casefold() if char.isalnum()) in CARD_IDENTIFIER_FIELDS
                else redact_card_identifiers(candidate)
            )
            for key, candidate in value.items()
        }
    if isinstance(value, list):
        return [redact_card_identifiers(candidate) for candidate in value]
    return value


def process_card_event(event_type, params, event_unit_id):
    normalized_event_type = "".join(char for char in event_type.casefold() if char.isalnum())
    if normalized_event_type not in ("cardentered", "accessgranted"):
        return

    identifier = extract_card_identifier(params)
    if not identifier:
        return

    validity = extract_card_validity(params)
    card_hash = hash_card_identifier(identifier)
    now = time.time()
    with auth.get_db_connection() as conn:
        registration = conn.execute(
            "SELECT id, unit_id FROM security_key_registration WHERE id = 1 AND expires_at >= ? AND card_hash IS NULL AND valid IS NULL",
            (now,)
        ).fetchone()
        if registration and (registration["unit_id"] is None or registration["unit_id"] == event_unit_id):
            if validity is True:
                conn.execute(
                    "UPDATE security_key_registration SET valid = 1, expires_at = ? WHERE id = 1 AND expires_at >= ? AND card_hash IS NULL AND valid IS NULL",
                    (now + 300, now)
                )
                add_log("warning", "RFID REGISTRACE", "Karta je již zaregistrována pro odemykání v nastavení zámku.")
                return
            if validity is False:
                conn.execute(
                    "UPDATE security_key_registration SET card_hash = ?, valid = 0, expires_at = ? WHERE id = 1 AND expires_at >= ? AND card_hash IS NULL AND valid IS NULL",
                    (card_hash, now + 300, now)
                )

        key = conn.execute(
            "SELECT id, name, action, unit_id FROM security_keys WHERE card_hash = ?",
            (card_hash,)
        ).fetchone()
        if key and key["unit_id"] is not None and key["unit_id"] != event_unit_id:
            return
        if key and key["action"] in ("permanent_toggle", "web_block_toggle"):
            claimed = conn.execute(
                """
                UPDATE security_keys
                SET last_triggered_at = ?
                WHERE id = ? AND last_triggered_at <= ?
                """,
                (now, key["id"], now - 2)
            )
            if claimed.rowcount == 0:
                return

    if registration and validity is False and (registration["unit_id"] is None or registration["unit_id"] == event_unit_id):
        source_unit = get_unit(event_unit_id)
        add_log("info", "RFID KLÍČ", "Nový klíč byl načten během registrace.", unit_id=event_unit_id, unit_name=source_unit["name"] if source_unit else None)
        return

    if not key:
        return

    targets = security_key_target_units(key["unit_id"], event_unit_id)
    if not targets:
        return
    if key["action"] == "ring":
        for unit in targets:
            schedule_doorbell_ring(f"Registrovaný klíč: {key['name']}", unit_id=unit["id"], unit_name=unit["name"])
            add_log("info", "RFID AKCE", f"Klíč '{key['name']}' spustil zvonění.", unit_id=unit["id"], unit_name=unit["name"])
        return
    if key["action"] == "permanent_toggle":
        toggle_permanent_unlock_from_key(key["name"], targets)
        return
    if key["action"] == "web_block_toggle":
        for unit in targets:
            try:
                is_blocked = toggle_web_unlock_blocked(unit["id"])
                state_text = "zablokovalo" if is_blocked else "znovu povolilo"
                add_log("warning" if is_blocked else "success", "WEB ODEMYKÁNÍ", f"Klíč '{key['name']}' {state_text} odemykání přes webové rozhraní.", unit_id=unit["id"], unit_name=unit["name"])
            except Exception:
                logger.exception("Nepodařilo se přepnout blokaci webového odemykání RFID klíčem na jednotce %s.", unit["id"])
        return

    now = time.time()
    for unit in targets:
        with auth.get_db_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute(
                "SELECT last_unlock_at FROM units WHERE id = ?",
                (unit["id"],)
            ).fetchone()
            if not current:
                continue
            previous_unlock = current["last_unlock_at"] or 0
            if now - previous_unlock < COOLDOWN_SECONDS:
                remaining = round(COOLDOWN_SECONDS - (now - previous_unlock), 1)
                add_log("warning", "RFID ODEMČENÍ", f"Opakované použití klíče '{key['name']}' na jednotce '{unit['name']}' bylo potlačeno bezpečnostní prodlevou ({remaining} s).", unit_id=unit["id"], unit_name=unit["name"])
                continue
            conn.execute(
                "UPDATE units SET last_unlock_at = ? WHERE id = ?",
                (now, unit["id"])
            )
        success, message, elapsed_ms, _ = send_unit_switch_command(unit)
        if success:
            with auth.get_db_connection() as conn:
                conn.execute("UPDATE units SET last_unlock_at = ?, connected = 1, last_seen = CURRENT_TIMESTAMP WHERE id = ?", (time.time(), unit["id"]))
            add_log("success", "RFID ODEMČENÍ", f"Klíč '{key['name']}' odemkl dveře ({elapsed_ms} ms).", unit_id=unit["id"], unit_name=unit["name"])
        else:
            with auth.get_db_connection() as conn:
                conn.execute(
                    "UPDATE units SET last_unlock_at = ? WHERE id = ? AND last_unlock_at = ?",
                    (previous_unlock, unit["id"], now)
                )
            add_log("error", "RFID ODEMČENÍ", f"Odemčení klíčem '{key['name']}' selhalo: {message}", unit_id=unit["id"], unit_name=unit["name"])


# Inicializační záznam
add_log("info", "SYSTÉM", f"Služba spuštěna. Cílová 2N jednotka: {config.DEVICE_IP or 'Nenastaveno'}")

# Ochrana proti zahlcení spínače
LAST_UNLOCK_TIME = 0
COOLDOWN_SECONDS = 3


def get_client_ip() -> str:
    """Získání reálné IP adresy klienta s ohledem na Cloudflare tunel a reverzní proxy."""
    cf_ip = request.headers.get("CF-Connecting-IP")
    if cf_ip:
        return cf_ip.strip()
    true_client_ip = request.headers.get("True-Client-IP")
    if true_client_ip:
        return true_client_ip.strip()
    x_forwarded = request.headers.get("X-Forwarded-For")
    if x_forwarded:
        return x_forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


def parse_allowed_subnets() -> list:
    """Rozparsování konfigurovaných podsítí sítě Sesule."""
    subnets = []
    raw = getattr(config, "ALLOWED_SUBNETS", "")
    for part in raw.split(","):
        part = part.strip()
        if part:
            try:
                subnets.append(ipaddress.ip_network(part, strict=False))
            except ValueError as e:
                logger.warning(f"Neplatná podsíť v ALLOWED_SUBNETS: {part} ({e})")
    return subnets


ALLOWED_NETWORKS = parse_allowed_subnets()


def is_ip_in_allowed_subnets(client_ip: str) -> bool:
    """Ověří, zda daná IP adresa patří do povolených podsítí sítě Sesule."""
    if not client_ip:
        return False
    try:
        ip_obj = ipaddress.ip_address(client_ip)
        if ip_obj.is_loopback:
            return True
        for net in ALLOWED_NETWORKS:
            if ip_obj in net:
                return True
        return False
    except ValueError:
        return False


def is_authenticated() -> bool:
    """Ověření, zda je uživatel v session řádně přihlášen."""
    return bool(session.get("user_id") and session.get("username"))


def verify_csrf_token() -> bool:
    """Ověření CSRF tokenu s ochranou proti timing útokům."""
    session_token = session.get("csrf_token")
    if not session_token:
        return False

    request_token = request.headers.get("X-CSRF-Token")
    if not request_token:
        if request.is_json and request.json:
            request_token = request.json.get("csrf_token")
        elif request.form:
            request_token = request.form.get("csrf_token")

    if not request_token:
        return False

    return hmac.compare_digest(session_token, request_token)


def login_required(f):
    """Dekorátor vyžadující přihlášení uživatele."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_authenticated():
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized", "message": "Přihlášení vypršelo nebo chybí."}), 401
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Dekorátor vyžadující roli admin."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("role") != "admin":
            return permission_denied_response()
        return f(*args, **kwargs)
    return decorated_function


def permission_denied_response():
    message = "Na tuto akci nemáte právo. Obraťte se na správce systému."
    return jsonify({"success": False, "error": "Forbidden", "message": message}), 403


ROLE_LEVELS = {"user": 0, "správce": 1, "admin": 2}


def admin_or_spravce_required(f):
    """Dekorátor vyžadující roli admin, správce nebo explicitní oprávnění ke správě."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        role = session.get("role")
        if role in ("admin", "správce"):
            return f(*args, **kwargs)
        user_id = session.get("user_id")
        user = auth.get_user_by_id(user_id) if user_id else None
        if permissions_config.can_user_manage_users(role, user):
            return f(*args, **kwargs)
        return permission_denied_response()
    return decorated_function


def can_manage_users_required(f):
    """Dekorátor vyžadující oprávnění ke správě uživatelů (podle role či uživatelského nastavení)."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_authenticated():
            return jsonify({"error": "Unauthorized"}), 401
        role = session.get("role")
        user_id = session.get("user_id")
        user = auth.get_user_by_id(user_id) if user_id else None
        if not permissions_config.can_user_manage_users(role, user):
            return permission_denied_response()
        return f(*args, **kwargs)
    return decorated_function


@app.before_request
def handle_session_and_csrf():
    """Globální middleware pro správu životnosti relace a CSRF ochranu."""
    # 1. Zajištění existence CSRF tokenu v každé relaci
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)

    # 2. Kontrola neaktivity pro přihlášeného uživatele (Session Expiry: 3 dny default, 90 dní remember_me)
    if is_authenticated():
        current_user = auth.get_user_by_id(session.get("user_id"))
        if not current_user:
            session.clear()
            session["csrf_token"] = secrets.token_urlsafe(32)
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized", "message": "Uživatelský účet již není dostupný."}), 401
            return redirect("/login")

        # Kontrola, zda účet nebyl deaktivován administrátorem (okamžité odhlášení)
        if current_user.get("is_disabled"):
            username = current_user.get("username", "uživatel")
            session.clear()
            session["csrf_token"] = secrets.token_urlsafe(32)
            add_log("warning", "ÚČET DEAKTIVOVÁN", f"Relace uživatele '{username}' byla okamžitě ukončena, protože účet byl deaktivován.")
            if request.path.startswith("/api/"):
                return jsonify({
                    "error": "Unauthorized",
                    "account_disabled": True,
                    "message": "Váš účet byl deaktivován. Obraťte se na správce systému."
                }), 401
            return redirect("/login?disabled=1")

        session["role"] = current_user["role"]
        session["username"] = current_user["username"]

        last_active = session.get("last_activity")
        now_ts = datetime.utcnow().timestamp()
        is_remember = session.get("remember_me", False)
        timeout_days = config.REMEMBER_ME_DAYS if is_remember else config.SESSION_LIFETIME_DAYS
        timeout_seconds = timeout_days * 24 * 60 * 60
        if last_active and (now_ts - last_active > timeout_seconds):
            username = session.get("username", "uživatel")
            session.clear()
            session["csrf_token"] = secrets.token_urlsafe(32)
            add_log("info", "RELACE VYPRŠELA", f"Relace uživatele '{username}' byla ukončena po uplynutí doby platnosti ({timeout_days} dní).")
            if request.path.startswith("/api/"):
                return jsonify({"error": "Unauthorized", "message": "Platnost přihlášení vypršela."}), 401
            return redirect("/login")
        session["last_activity"] = now_ts

    # 3. Kontrola CSRF pro všechny stav měnící metody (POST, PUT, DELETE, PATCH)
    if request.method in ("POST", "PUT", "DELETE", "PATCH"):
        if request.path == "/api/webhook/2n":
            pass
        elif not verify_csrf_token():
            add_log("warning", "CSRF BLOKOVÁNO", f"Požadavek na {request.path} odmítnut pro neplatný CSRF token z {get_client_ip()}.")
            return jsonify({"error": "Bad Request", "message": "Neplatný nebo chybějící CSRF token. Obnovte stránku."}), 400


@app.after_request
def add_security_headers(response):
    """Bezpečnostní a cache hlavičky."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: http: https:; "
        "connect-src 'self' http: https:; "
        "script-src 'self' 'unsafe-inline'; "
        "worker-src 'self'"
    )

    # Service Worker musí být vždy čerstvý (prohlížeč kontroluje při každém načtení)
    if request.path.endswith('/sw.js'):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Service-Worker-Allowed"] = "/"
    # Statické assety (CSS, JS, ikony) – krátká cache pro rychlé načtení, ale revalidace
    elif request.path.startswith('/icons/') or request.path.endswith(('.css', '.js', '.png', '.json')):
        response.headers["Cache-Control"] = "public, max-age=3600, must-revalidate"
    # API a HTML – vždy čerstvé
    else:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

    return response


# ==============================================================================
# ROUTY PRO AUTENTIZACI A SPRÁVU UŽIVATELŮ
# ==============================================================================

@app.route("/login")
def login_page():
    """Zobrazení přihlašovací stránky (nebo přesměrování na hl. stranu, pokud je přihlášen)."""
    if is_authenticated():
        return redirect("/")
    return send_from_directory(app.static_folder, "login.html")


@app.route("/api/csrf-token", methods=["GET"])
def get_csrf():
    """Poskytne aktuální CSRF token pro frontend."""
    return jsonify({"csrf_token": session.get("csrf_token", "")})


@app.route("/api/me", methods=["GET"])
def get_current_user():
    """Vrací informace o aktuálně přihlášeném uživateli, stavu připojení a CSRF token."""
    if not is_authenticated():
        return jsonify({"authenticated": False}), 401

    user_id = session.get("user_id")
    has_bypass = auth.is_user_network_bypassed(user_id) if user_id else False
    session["network_bypass"] = has_bypass

    perm = auth.get_user_permanent_unlock_permission(user_id) if user_id else {"allowed": False, "max_duration": 60}
    if session.get("role") == "admin":
        perm = {"allowed": True, "max_duration": 1440}
    perm_state = auth.get_permanent_unlock_state()

    client_ip = get_client_ip()
    ip_allowed = is_ip_in_allowed_subnets(client_ip)
    network_allowed = bool(has_bypass or ip_allowed)

    user = auth.get_user_by_id(user_id) if user_id else None
    role = session.get("role") or (user.get("role") if user else "user")

    sidebar_menu = user.get("sidebar_menu") if user else permissions_config.get_default_sidebar_menu_for_role(role)
    can_manage_users = permissions_config.can_user_manage_users(role, user)
    manage_permissions = permissions_config.get_caller_management_permissions(role, user)
    manageable_roles = permissions_config.CAN_MANAGE_ROLES.get(role, [])

    return jsonify({
        "authenticated": True,
        "user_id": user_id,
        "username": session.get("username"),
        "role": role,
        "network_bypass": has_bypass,
        "network_allowed": network_allowed,
        "client_ip": client_ip,
        "csrf_token": session.get("csrf_token"),
        "device_ip": config.DEVICE_IP or "",
        "device_port": config.DEVICE_PORT,
        "device_protocol": config.DEVICE_PROTOCOL,
        "push_enabled": auth.has_push_subscription(user_id) if user_id else False,
        "webauthn_enabled": auth.has_webauthn_credentials(user_id) if user_id else False,
        "vapid_public_key": config.VAPID_PUBLIC_KEY,
        "permanent_unlock_allowed": perm.get("allowed", False),
        "permanent_unlock_max_duration": perm.get("max_duration", 60),
        "permanent_unlock_state": perm_state,
        "web_unlock_blocked": is_web_unlock_blocked(),
        "can_unlock": user.get("can_unlock", True) if user else True,
        "sidebar_menu": sidebar_menu,
        "can_manage_users": can_manage_users,
        "manage_permissions": manage_permissions,
        "manageable_roles": manageable_roles
    })


@app.route("/api/login", methods=["POST"])
def login():
    """
    Přihlášení uživatele s ochranou proti brute-force, timing útokům a generickými hláškami.
    Regeneruje Session ID pro prevenci Session Fixation.
    """
    data = request.get_json(silent=True) or request.form or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    remember_me = bool(data.get("remember_me", False))
    client_ip = get_client_ip()

    if not username or not password:
        return jsonify({
            "success": False,
            "message": "Zadejte uživatelské jméno i heslo."
        }), 400

    success, user, error_msg = auth.authenticate_user(username, password, client_ip)

    if success and user:
        # Prevence Session Fixation: kompletní vyčištění relace a vygenerování nového CSRF tokenu
        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        session["network_bypass"] = user.get("network_bypass", False)
        session["remember_me"] = remember_me
        session["csrf_token"] = secrets.token_urlsafe(32)
        session["last_activity"] = datetime.utcnow().timestamp()
        session.permanent = True

        duration_desc = "3 měsíce" if remember_me else "3 dny"
        add_log("info", "PŘIHLÁŠENÍ", f"Uživatel '{user['username']}' [{user['role'].upper()}] se úspěšně přihlásil z IP {client_ip} (Platnost: {duration_desc}).")

        return jsonify({
            "success": True,
            "message": "Přihlášení bylo úspěšné.",
            "user": {
                "username": user["username"],
                "role": user["role"]
            },
            "csrf_token": session["csrf_token"]
        })
    else:
        add_log("warning", "PŘIHLÁŠENÍ SELHALO", f"Neúspěšné přihlášení uživatele '{username}' z IP {client_ip}.")
        return jsonify({
            "success": False,
            "message": error_msg or "Neplatné uživatelské jméno nebo heslo."
        }), 401


@app.route("/api/logout", methods=["POST"])
@login_required
def logout():
    """Odhlášení uživatele a zneplatnění relace."""
    uname = session.get("username", "neznámý")
    session.clear()
    session["csrf_token"] = secrets.token_urlsafe(32)
    add_log("info", "ODHLÁŠENÍ", f"Uživatel '{uname}' se úspěšně odhlásil.")

    resp = jsonify({"success": True, "message": "Byl jste úspěšně odhlášen."})
    resp.delete_cookie(config.SESSION_COOKIE_NAME)
    return resp


@app.route("/api/auth/change-password", methods=["POST"])
@login_required
def change_password():
    """Změna hesla aktuálně přihlášeného uživatele."""
    data = request.get_json(silent=True) or request.form or {}
    current_password = str(data.get("current_password", ""))
    new_password = str(data.get("new_password", ""))

    user_id = session.get("user_id")
    username = session.get("username", "uživatel")

    success, msg = auth.change_password(user_id, current_password, new_password)
    if success:
        add_log("info", "ZMĚNA HESLA", f"Uživatel '{username}' si úspěšně změnil heslo.")
        return jsonify({"success": True, "message": msg})
    else:
        add_log("warning", "ZMĚNA HESLA SELHALA", f"Neúspěšný pokus o změnu hesla uživatele '{username}'.")
        return jsonify({"success": False, "message": msg}), 400



def has_sidebar_permission(item_key: str) -> bool:
    """Ověří, zda má přihlášený uživatel oprávnění k dané záložce bočního menu."""
    role = session.get("role")
    if role == "admin":
        return True
    user_id = session.get("user_id")
    user = auth.get_user_by_id(user_id) if user_id else None
    menu = user.get("sidebar_menu", []) if user else permissions_config.get_default_sidebar_menu_for_role(role)
    return item_key in menu


@app.route("/api/permissions/config", methods=["GET"])
@login_required
def get_permissions_config():
    """Získání aktuální konfigurace oprávnění, rolí a limitů z permissions_config.py."""
    return jsonify({
        "roles": permissions_config.ROLES,
        "role_labels": permissions_config.ROLE_LABELS,
        "can_manage_roles": permissions_config.CAN_MANAGE_ROLES,
        "default_role_permissions": permissions_config.DEFAULT_ROLE_PERMISSIONS,
        "role_can_edit_permissions": permissions_config.ROLE_CAN_EDIT_PERMISSIONS,
        "sidebar_menu_items": permissions_config.SIDEBAR_MENU_ITEMS,
        "permanent_unlock_config": permissions_config.PERMANENT_UNLOCK_CONFIG,
        "time_restriction_config": permissions_config.TIME_RESTRICTION_CONFIG,
        "security_policies": permissions_config.SECURITY_POLICIES,
    })


@app.route("/api/users", methods=["GET"])
@login_required
@can_manage_users_required
def list_users():
    """Získání seznamu všech uživatelů (administrátor nebo oprávněná role)."""
    users = auth.get_all_users()
    return jsonify({"users": users})


@app.route("/api/users", methods=["POST"])
@login_required
@can_manage_users_required
def add_user():
    """Vytvoření nového uživatelského účtu administrátorem či oprávněnou rolí."""
    data = request.get_json(silent=True) or request.form or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    role = str(data.get("role", "user")).strip().lower()
    network_bypass = bool(data.get("network_bypass", False))
    sidebar_menu = data.get("sidebar_menu")
    can_manage_users_val = data.get("can_manage_users")

    caller_role = session.get("role")
    caller_id = session.get("user_id")
    caller_user = auth.get_user_by_id(caller_id) if caller_id else None
    caller_perms = permissions_config.get_caller_management_permissions(caller_role, caller_user)

    if not caller_perms.get("can_create_users", False):
        return permission_denied_response()

    # Správce či jiná role může vytvářet pouze role, které smí spravovat
    allowed_roles = permissions_config.CAN_MANAGE_ROLES.get(caller_role, [])
    if caller_role != "admin" and role not in allowed_roles:
        return permission_denied_response()

    # Kontrola síťového bypassu
    if not caller_perms.get("can_edit_network_bypass", False):
        network_bypass = False

    success, msg = auth.create_user(
        username,
        password,
        role,
        network_bypass=network_bypass,
        sidebar_menu=sidebar_menu,
        can_manage_users=can_manage_users_val
    )
    if success:
        created_user = auth.get_user_by_username(username)
        if created_user:
            with auth.get_db_connection() as conn:
                conn.executemany(
                    """
                    INSERT OR IGNORE INTO user_unit_access (
                        user_id, unit_id, can_unlock, network_bypass,
                        permanent_unlock_allowed, permanent_unlock_max_duration
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            created_user["id"], unit["id"], created_user.get("can_unlock", True),
                            created_user.get("network_bypass", False),
                            created_user.get("permanent_unlock_allowed", False),
                            created_user.get("permanent_unlock_max_duration", 60)
                        )
                        for unit in get_units()
                    ]
                )
        admin_name = session.get("username", "admin")
        add_log("info", "UŽIVATEL VYTVOŘEN", f"Správce '{admin_name}' vytvořil nový účet '{username}' s rolí '{role}' (Bypass: {'ANO' if network_bypass else 'NE'}).")
        return jsonify({"success": True, "message": msg})
    else:
        return jsonify({"success": False, "message": msg}), 400


@app.route("/api/users/<int:user_id>/bypass", methods=["POST"])
@login_required
@admin_required
def toggle_user_bypass(user_id: int):
    """Přepnutí / nastavení bypassu sítě Sesule pro uživatele (pouze administrátor)."""
    data = request.get_json(silent=True) or request.form or {}
    bypass = bool(data.get("bypass", False))
    target_user = auth.get_user_by_id(user_id)
    if not target_user:
        return jsonify({"success": False, "message": "Uživatel nebyl nalezen."}), 404
    if target_user.get("username", "").lower() == "admin":
        return permission_denied_response()

    success, msg = auth.set_user_network_bypass(user_id, bypass)
    if success:
        admin_name = session.get("username", "admin")
        state_str = "POVOLIL" if bypass else "VYPNUL"
        add_log("info", "ADMIN BYPASS", f"Uživatel '{admin_name}' {state_str} bypass sítě Sesule pro uživatele ID {user_id}.")
        return jsonify({"success": True, "message": msg, "network_bypass": bypass})
    else:
        return jsonify({"success": False, "message": msg}), 400


@app.route("/api/users/<int:user_id>", methods=["GET"])
@login_required
@admin_or_spravce_required
def get_user_details(user_id: int):
    """Získání detailů uživatele včetně všech oprávnění."""
    u = auth.get_user_by_id(user_id)
    if not u:
        return jsonify({"success": False, "message": "Uživatel nebyl nalezen."}), 404
    u["unit_access"] = [
        {"unit_name": unit["name"], **get_unit_access(user_id, unit["id"])}
        for unit in get_units()
    ]
    return jsonify({"success": True, "user": u})


@app.route("/api/users/<int:user_id>/permissions", methods=["POST", "PUT"])
@login_required
@admin_or_spravce_required
def set_user_permissions(user_id: int):
    """Komplexní nastavení oprávnění uživatele (administrátor nebo správce)."""
    data = request.get_json(silent=True) or request.form or {}
    caller_user_id = session.get("user_id")
    caller_role = session.get("role")
    unit_access = data.get("unit_access") if isinstance(data, dict) else None
    if unit_access is not None:
        target_user = auth.get_user_by_id(user_id)
        if not target_user:
            return jsonify({"success": False, "message": "Uživatel nebyl nalezen."}), 404
        if not isinstance(unit_access, list) or any(
            not isinstance(item, dict) or not isinstance(item.get("unit_id"), int)
            for item in unit_access
        ):
            return jsonify({"success": False, "message": "Neplatný seznam oprávnění jednotek."}), 400
        access_ok, access_message = save_user_unit_access(
            user_id, unit_access, caller_user_id, caller_role, dry_run=True
        )
        if not access_ok:
            return jsonify({"success": False, "message": access_message}), 400

    if unit_access is None:
        success, msg = auth.update_user_permissions(user_id, data, caller_user_id, caller_role)
    else:
        try:
            with auth.get_db_connection() as conn:
                conn.execute("BEGIN IMMEDIATE")
                success, msg = auth.update_user_permissions(
                    user_id,
                    data,
                    caller_user_id,
                    caller_role,
                    connection=conn,
                )
                if success:
                    success, msg = save_user_unit_access(
                        user_id,
                        unit_access,
                        caller_user_id,
                        caller_role,
                        connection=conn,
                    )
                if success:
                    conn.commit()
                else:
                    conn.rollback()
        except sqlite3.Error:
            logger.exception("Nepodařilo se atomicky uložit oprávnění uživatele %s.", user_id)
            return jsonify({
                "success": False,
                "message": "Chyba databáze při ukládání oprávnění."
            }), 500
    if success:
        admin_name = session.get("username", "admin")
        add_log("info", "ZMĚNA OPRÁVNĚNÍ", f"Správce '{admin_name}' aktualizoval oprávnění uživatele ID {user_id}.")
        updated_user = auth.get_user_by_id(user_id)
        return jsonify({"success": True, "message": msg, "user": updated_user})
    else:
        return jsonify({"success": False, "message": msg}), 400



@app.route("/api/users/<int:user_id>/role", methods=["POST"])
@login_required
@admin_or_spravce_required
def update_user_role(user_id: int):
    """Změna role uživatele (admin / správce / user) - administrátor nebo správce."""
    data = request.get_json(silent=True) or request.form or {}
    role = str(data.get("role", "")).strip().lower()
    current_user_id = session.get("user_id")
    caller_role = session.get("role")

    target_user = auth.get_user_by_id(user_id)
    if not target_user:
        return jsonify({"success": False, "message": "Uživatel nebyl nalezen."}), 404
    if target_user.get("username", "").lower() == "admin":
        return permission_denied_response()

    if caller_role != "admin":
        caller_user = auth.get_user_by_id(current_user_id) if current_user_id else None
        caller_perms = permissions_config.get_caller_management_permissions(caller_role, caller_user)
        allowed_roles = permissions_config.CAN_MANAGE_ROLES.get(caller_role, [])
        if (
            not caller_perms.get("can_change_role", False)
            or role not in allowed_roles
            or target_user.get("role") not in allowed_roles
        ):
            return permission_denied_response()

    if caller_role == "správce":
        if user_id == current_user_id:
            return permission_denied_response()
        if ROLE_LEVELS.get(target_user.get("role"), -1) > ROLE_LEVELS["správce"]:
            return permission_denied_response()
        if ROLE_LEVELS.get(role, -1) > ROLE_LEVELS["správce"]:
            return permission_denied_response()

    success, msg = auth.update_user_role(user_id, role, current_user_id)
    if success:
        admin_name = session.get("username", "admin")
        add_log("info", "ZMĚNA ROLE", f"Správce '{admin_name}' změnil roli uživatele ID {user_id} na '{role}'.")
        return jsonify({"success": True, "message": msg})
    else:
        return jsonify({"success": False, "message": msg}), 400


@app.route("/api/users/<int:user_id>", methods=["DELETE"])
@login_required
@admin_or_spravce_required
def delete_user(user_id: int):
    """Smazání uživatelského účtu (administrátor nebo správce)."""
    current_user_id = session.get("user_id")
    caller_role = session.get("role")

    target_user = auth.get_user_by_id(user_id)
    if not target_user:
        return jsonify({"success": False, "message": "Uživatel nebyl nalezen."}), 404
    if target_user.get("username", "").lower() == "admin":
        return permission_denied_response()
    if caller_role == "správce":
        if user_id == current_user_id:
            return permission_denied_response()
        if ROLE_LEVELS.get(target_user.get("role"), -1) >= ROLE_LEVELS["správce"]:
            return permission_denied_response()

    success, msg = auth.delete_user(user_id, current_user_id, caller_role)
    if success:
        admin_name = session.get("username", "admin")
        add_log("warning", "UŽIVATEL SMAZÁN", f"Správce '{admin_name}' smazal uživatele ID {user_id}.")
        return jsonify({"success": True, "message": msg})
    else:
        return jsonify({"success": False, "message": msg}), 400



# ==============================================================================
# ROZVRH ODEMYKÁNÍ – per-user schedule API
# ==============================================================================

@app.route("/api/users/<int:user_id>/schedule", methods=["GET"])
@login_required
@can_manage_users_required
def get_user_schedule_api(user_id: int):
    """Načte rozvrh odemykání uživatele pro konkrétní jednotku."""
    target_user = auth.get_user_by_id(user_id)
    if not target_user:
        return jsonify({"success": False, "message": "Uživatel nebyl nalezen."}), 404
    unit_id = request.args.get("unit_id", type=int)
    if not unit_id or not get_unit(unit_id):
        return jsonify({"success": False, "message": "Vyberte platnou jednotku."}), 400
    try:
        schedule = get_unit_schedule(user_id, unit_id)
    except ValueError as error:
        return jsonify({"success": False, "message": str(error)}), 500
    return jsonify({"success": True, "schedule": schedule, "unit_id": unit_id})


@app.route("/api/users/<int:user_id>/schedule", methods=["POST"])
@login_required
@can_manage_users_required
def set_user_schedule_api(user_id: int):
    """Uloží rozvrh odemykání uživatele pro konkrétní jednotku."""
    caller_role = session.get("role", "")
    target_user = auth.get_user_by_id(user_id)
    if not target_user:
        return jsonify({"success": False, "message": "Uživatel nebyl nalezen."}), 404
    if target_user.get("username", "").lower() == "admin" and caller_role != "admin":
        return permission_denied_response()

    data = request.get_json(silent=True) or {}
    schedule = data.get("schedule")
    if not isinstance(schedule, dict):
        return jsonify({"success": False, "message": "Pole 'schedule' musí být objekt."}), 400
    unit_id = data.get("unit_id")
    if not isinstance(unit_id, int) or isinstance(unit_id, bool) or not get_unit(unit_id):
        return jsonify({"success": False, "message": "Vyberte platnou jednotku."}), 400

    success, msg = set_unit_schedule(user_id, unit_id, schedule)
    if success:
        unit = get_unit(unit_id)
        add_log("info", "ROZVRH", f"Upraven rozvrh odemykání pro uživatele '{target_user['username']}' na jednotce '{unit['name']}' (správce: {session.get('username', '?')}).", unit_id=unit_id, unit_name=unit["name"])
        return jsonify({"success": True, "message": msg})
    else:
        return jsonify({"success": False, "message": msg}), 400


# ==============================================================================
# HLAVNÍ STRÁNKA A PROVOZNÍ ROUTY
# ==============================================================================

@app.route("/")
@login_required
def index():
    """Hlavní stránka pro odemknutí dveří - vyžaduje přihlášení."""
    return send_from_directory(app.static_folder, "index.html")


# SPA sekce – každá URL záložky vrátí index.html (frontend pak přečte pathname a zobrazí správnou sekci)
_SPA_SECTIONS = ("home", "log", "logs", "info", "units", "users", "keys", "permanent", "schedule", "global-settings")

@app.route("/<section>")
def spa_section(section):
    """SPA routing: každá sekce z bočního panelu má vlastní URL."""
    # Soubory (obsahují tečku) předáme bez login_required
    if '.' in section:
        return serve_static_file(section)
    # SPA sekce vyžadují přihlášení
    if section in _SPA_SECTIONS:
        if not is_authenticated():
            return redirect("/login")
        return send_from_directory(app.static_folder, "index.html")
    # Ostatní jednoduché cesty (neznámé) – zkus jako statický soubor
    return serve_static_file(section)


@app.route("/<path:filename>")
def serve_static_file(filename):
    """Obsluha statických souborů. Ochrana index.html před neoprávněným přístupem."""
    if filename == "index.html" and not is_authenticated():
        return redirect("/login")
    return send_from_directory(app.static_folder, filename)


@app.route("/api/global-settings", methods=["GET", "POST"])
@login_required
@admin_required
def manage_global_settings():
    if request.method == "GET":
        return jsonify(_ntp_clock_status())

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "message": "Očekávána jsou data globálního nastavení."}), 400
    try:
        server = normalize_ntp_server(data.get("ntp_server", ""))
    except ValueError as error:
        return jsonify({"success": False, "message": str(error)}), 400

    if not server:
        try:
            _write_app_settings({
                "ntp_server": "",
                "ntp_offset_seconds": "0",
                "ntp_last_sync": "",
                "ntp_last_error": "NTP server není nastaven.",
            })
        except sqlite3.Error:
            logger.exception("Nepodařilo se vypnout synchronizaci NTP.")
            return jsonify({"success": False, "message": "Synchronizaci NTP se nepodařilo vypnout."}), 500
        with _ntp_clock_lock:
            _ntp_clock_state.update(
                server="",
                offset_seconds=0.0,
                last_sync=None,
                error="NTP server není nastaven.",
                last_attempt_monotonic=time.monotonic(),
            )
        add_log("info", "NTP VYPNUTO", "Synchronizace aplikačního času s NTP serverem byla vypnuta.")
        return jsonify({
            "success": True,
            "message": "Synchronizace NTP byla vypnuta; systémový čas hostitele zůstává beze změny.",
            **_ntp_clock_status(),
        })

    try:
        _write_app_settings({"ntp_server": server})
    except sqlite3.Error:
        logger.exception("Nepodařilo se uložit nastavení NTP serveru.")
        return jsonify({"success": False, "message": "Nastavení NTP serveru se nepodařilo uložit."}), 500

    synchronized = _synchronize_ntp_server(server)
    status = _ntp_clock_status()
    message = (
        "NTP server byl uložen a aplikační čas synchronizován."
        if synchronized
        else "NTP server byl uložen, ale synchronizace se nezdařila. Aplikace se o ni bude opakovaně pokoušet."
    )
    add_log(
        "success" if synchronized else "warning",
        "NASTAVENÍ NTP",
        f"NTP server {server}: {'synchronizace úspěšná' if synchronized else 'čeká na úspěšnou synchronizaci'}."
    )
    return jsonify({"success": True, "message": message, **status})


@app.route("/api/units", methods=["GET", "POST"])
@login_required
@admin_required
def manage_units():
    if request.method == "GET":
        return jsonify({
            "units": [public_unit(unit) for unit in get_units()],
            "unit_types": list(UNIT_TYPES),
        })

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "message": "Očekávána jsou data nové jednotky."}), 400

    name = " ".join(str(data.get("name") or "").split())
    model = data.get("model")
    ip = str(data.get("ip") or "").strip()
    username = str(data.get("api_username") or "").strip()
    password = data.get("api_password")
    if not name or len(name) > 60:
        return jsonify({"success": False, "message": "Název jednotky musí mít 1 až 60 znaků."}), 400
    if model not in UNIT_TYPES:
        return jsonify({"success": False, "message": "Vyberte typ jednotky ze seznamu."}), 400
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"success": False, "message": "Zadejte platnou IP adresu jednotky."}), 400
    ip = str(ipaddress.ip_address(ip))
    if not username or len(username) > 128:
        return jsonify({"success": False, "message": "Název API účtu musí mít 1 až 128 znaků."}), 400
    if not isinstance(password, str) or not password or len(password) > 256:
        return jsonify({"success": False, "message": "Heslo API účtu musí mít 1 až 256 znaků."}), 400

    connection = probe_unit_connection(ip, username, password)
    if not connection:
        return jsonify({
            "success": False,
            "message": "Jednotku se nepodařilo ověřit. Zkontrolujte IP adresu, API účet, heslo a dostupnost 2N API."
        }), 502

    try:
        with auth.get_db_connection() as conn:
            result = conn.execute(
                """
                INSERT INTO units (
                    name, model, ip, protocol, port, api_username,
                    api_password_encrypted, auth_type, switch_id, switch_action
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    name, model, ip, connection["protocol"], connection["port"], username,
                    UNIT_CIPHER.encrypt(password.encode("utf-8")).decode("ascii"),
                    connection["auth_type"], config.SWITCH_ID, config.SWITCH_ACTION
                )
            )
            new_unit_id = result.lastrowid
            source_unit = conn.execute(
                "SELECT id FROM units WHERE id != ? ORDER BY is_legacy DESC, id LIMIT 1",
                (new_unit_id,)
            ).fetchone()
            users = conn.execute("SELECT * FROM users").fetchall()
            for user in users:
                conn.execute(
                    """
                    INSERT INTO user_unit_access (
                        user_id, unit_id, can_unlock, network_bypass,
                        permanent_unlock_allowed, permanent_unlock_max_duration
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        user["id"], new_unit_id, user["can_unlock"], user["network_bypass"],
                        user["permanent_unlock_allowed"], user["permanent_unlock_max_duration"]
                    )
                )
                if source_unit:
                    conn.execute(
                        """
                        INSERT INTO user_unit_schedule (user_id, unit_id, schedule_json)
                        SELECT user_id, ?, schedule_json FROM user_unit_schedule
                        WHERE user_id = ? AND unit_id = ?
                        """,
                        (new_unit_id, user["id"], source_unit["id"])
                    )
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "Jednotka se stejným názvem nebo IP adresou a portem již existuje."}), 409

    add_log("success", "JEDNOTKA PŘIDÁNA", f"Administrátor '{session.get('username')}' přidal jednotku '{name}' ({model}, {ip}).", unit_id=new_unit_id, unit_name=name)
    return jsonify({
        "success": True,
        "message": "Jednotka byla ověřena a přidána.",
        "unit": public_unit(get_unit(result.lastrowid)),
    }), 201


@app.route("/api/units/<int:unit_id>", methods=["PATCH", "DELETE"])
@login_required
@admin_required
def delete_unit(unit_id):
    if request.method == "PATCH":
        data = request.get_json(silent=True)
        name = " ".join(str(data.get("name") or "").split()) if isinstance(data, dict) else ""
        if not name or len(name) > 60:
            return jsonify({"success": False, "message": "Název jednotky musí mít 1 až 60 znaků."}), 400
        try:
            with auth.get_db_connection() as conn:
                unit = conn.execute("SELECT id FROM units WHERE id = ?", (unit_id,)).fetchone()
                if not unit:
                    return jsonify({"success": False, "message": "Jednotka nebyla nalezena."}), 404
                conn.execute("UPDATE units SET name = ? WHERE id = ?", (name, unit_id))
        except sqlite3.IntegrityError:
            return jsonify({"success": False, "message": "Jednotka s tímto názvem již existuje."}), 409
        add_log("info", "JEDNOTKA PŘEJMENOVÁNA", f"Administrátor '{session.get('username')}' změnil název jednotky na '{name}'.", unit_id=unit_id, unit_name=name)
        return jsonify({"success": True, "message": "Název jednotky byl změněn.", "name": name})

    with auth.get_db_connection() as conn:
        unit = conn.execute("SELECT id, name FROM units WHERE id = ?", (unit_id,)).fetchone()
        if not unit:
            return jsonify({"success": False, "message": "Jednotka nebyla nalezena."}), 404
        conn.execute("DELETE FROM units WHERE id = ?", (unit_id,))
    add_log("warning", "JEDNOTKA ODEBRÁNA", f"Administrátor '{session.get('username')}' odebral jednotku '{unit['name']}'.", unit_id=unit_id, unit_name=unit["name"])
    return jsonify({"success": True})


@app.route("/api/user/units", methods=["GET", "POST"])
@login_required
def user_units():
    user_id = session.get("user_id")
    with auth.get_db_connection() as conn:
        if request.method == "GET":
            configured = conn.execute(
                "SELECT 1 FROM user_unit_preferences WHERE user_id = ?",
                (user_id,)
            ).fetchone()
            selected_ids = {
                row["unit_id"] for row in conn.execute(
                    "SELECT unit_id FROM user_display_units WHERE user_id = ?",
                    (user_id,)
                ).fetchall()
            }
            units = conn.execute("SELECT * FROM units ORDER BY id").fetchall()
            role = session.get("role")
            return jsonify({
                "units": [
                    {
                        **public_unit(dict(unit)),
                        "selected": not configured or unit["id"] in selected_ids,
                        "access": {
                            **get_unit_access(user_id, unit["id"]),
                            "can_unlock": role == "admin" or bool(get_unit_access(user_id, unit["id"])["can_unlock"]),
                            "network_bypass": role == "admin" or bool(get_unit_access(user_id, unit["id"])["network_bypass"]),
                            "permanent_unlock_allowed": role == "admin" or bool(get_unit_access(user_id, unit["id"])["permanent_unlock_allowed"]),
                            "permanent_unlock_max_duration": 1440 if role == "admin" else get_unit_access(user_id, unit["id"])["permanent_unlock_max_duration"],
                        },
                        "permanent_state": get_unit_permanent_state(unit["id"]),
                        "web_unlock_blocked": is_web_unlock_blocked(unit["id"]),
                    }
                    for unit in units
                ]
            })

        data = request.get_json(silent=True)
        selected_ids = data.get("unit_ids") if isinstance(data, dict) else None
        if not isinstance(selected_ids, list) or any(
            not isinstance(unit_id, int) or isinstance(unit_id, bool) for unit_id in selected_ids
        ):
            return jsonify({"success": False, "message": "Vyberte platné jednotky."}), 400
        selected_ids = list(dict.fromkeys(selected_ids))
        existing_ids = {
            row["id"] for row in conn.execute("SELECT id FROM units").fetchall()
        }
        if any(unit_id not in existing_ids for unit_id in selected_ids):
            return jsonify({"success": False, "message": "Některá vybraná jednotka již není dostupná."}), 400
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "INSERT INTO user_unit_preferences (user_id) VALUES (?) ON CONFLICT(user_id) DO UPDATE SET updated_at = CURRENT_TIMESTAMP",
            (user_id,)
        )
        conn.execute("DELETE FROM user_display_units WHERE user_id = ?", (user_id,))
        conn.executemany(
            "INSERT INTO user_display_units (user_id, unit_id) VALUES (?, ?)",
            [(user_id, unit_id) for unit_id in selected_ids]
        )
    return jsonify({"success": True, "selected_unit_ids": selected_ids})


@app.route("/api/config-status", methods=["GET"])
@login_required
def config_status():
    """Vrací informace o konfiguraci a detailní parametry jednotky 2N (admin, správce nebo povolené menu)."""
    if not has_sidebar_permission("info") and session.get("role") not in ("admin", "správce"):
        return permission_denied_response()
    is_configured = bool(config.DEVICE_IP and config.API_USERNAME and config.API_PASSWORD)
    resp_data = {
        "configured": is_configured,
        "device_ip": config.DEVICE_IP if config.DEVICE_IP else None,
        "device_port": config.DEVICE_PORT,
        "device_protocol": config.DEVICE_PROTOCOL,
        "api_username": config.API_USERNAME if config.API_USERNAME else None,
        "switch_id": config.SWITCH_ID,
        "auth_type": config.AUTH_TYPE,
        "allowed_subnets": getattr(config, "ALLOWED_SUBNETS", ""),
        "unit_details": None
    }

    if is_configured:
        try:
            target_url = f"{config.DEVICE_PROTOCOL}://{config.DEVICE_IP}:{config.DEVICE_PORT}/api/system/info"
            auth_handler = HTTPDigestAuth(config.API_USERNAME, config.API_PASSWORD) if config.AUTH_TYPE == "digest" else HTTPBasicAuth(config.API_USERNAME, config.API_PASSWORD)
            r = requests.get(target_url, auth=auth_handler, timeout=config.REQUEST_TIMEOUT, verify=config.VERIFY_SSL)
            if r.status_code == 200:
                info_json = r.json()
                if info_json.get("success"):
                    resp_data["unit_details"] = info_json.get("result")
        except Exception as e:
            logger.debug(f"Nepodařilo se načíst detaily 2N jednotky: {e}")

    return jsonify(resp_data)


@app.route("/api/units/<int:unit_id>/info", methods=["GET"])
@login_required
def unit_info(unit_id):
    if not has_sidebar_permission("info") and session.get("role") not in ("admin", "správce"):
        return permission_denied_response()
    if session.get("role") != "admin" and not unit_is_selected_for_user(session.get("user_id"), unit_id):
        return permission_denied_response()
    unit = get_unit(unit_id, include_secret=True)
    if not unit:
        return jsonify({"success": False, "message": "Jednotka nebyla nalezena."}), 404
    details = None
    try:
        response = requests.get(
            f"{unit_base_url(unit['protocol'], unit['ip'], unit['port'])}/api/system/info",
            auth=unit_auth_handlers(unit["api_username"], unit["api_password"], unit["auth_type"])[0][0],
            timeout=config.REQUEST_TIMEOUT,
            verify=config.VERIFY_SSL
        )
        if response.status_code == 200:
            data = response.json()
            if data.get("success"):
                details = data.get("result")
    except (requests.RequestException, ValueError):
        logger.exception("Nepodařilo se načíst informace z jednotky %s.", unit_id)
    return jsonify({
        "unit": public_unit(unit),
        "switch_id": unit["switch_id"],
        "allowed_subnets": getattr(config, "ALLOWED_SUBNETS", ""),
        "unit_details": details,
    })


@app.route("/api/logs", methods=["GET"])
@login_required
def get_logs():
    """Vrací historii záznamů pro zobrazení na webu - admin, správce nebo povolené menu."""
    if not has_sidebar_permission("logs") and session.get("role") not in ("admin", "správce"):
        return permission_denied_response()
    source = request.args.get("source", "all")
    logs = _read_logs()
    if source == "system":
        logs = [entry for entry in logs if entry.get("source_type", "system") == "system"]
    elif source != "all":
        try:
            unit_id = int(source)
        except ValueError:
            return jsonify({"success": False, "message": "Neplatný filtr jednotky."}), 400
        if session.get("role") != "admin" and not unit_is_selected_for_user(session.get("user_id"), unit_id):
            return permission_denied_response()
        logs = [entry for entry in logs if entry.get("unit_id") == unit_id]
    elif session.get("role") != "admin":
        selected_ids = {
            unit["id"] for unit in get_units()
            if unit_is_selected_for_user(session.get("user_id"), unit["id"])
        }
        logs = [
            entry for entry in logs
            if entry.get("source_type", "system") == "system" or entry.get("unit_id") in selected_ids
        ]
    return jsonify({"logs": logs})


@app.route("/api/security-keys", methods=["GET", "POST"])
@login_required
@admin_or_spravce_required
def security_keys():
    if request.method == "GET":
        with auth.get_db_connection() as conn:
            keys = conn.execute(
                """
                SELECT security_keys.id, security_keys.name, security_keys.action,
                       security_keys.unit_id, units.name AS unit_name, security_keys.created_at
                FROM security_keys
                LEFT JOIN units ON units.id = security_keys.unit_id
                ORDER BY security_keys.created_at DESC, security_keys.id DESC
                """
            ).fetchall()
        return jsonify({"keys": [dict(key) for key in keys]})

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"success": False, "message": "Očekávána jsou data bezpečnostního klíče."}), 400
    name = data.get("name")
    action = data.get("action")
    if not isinstance(name, str):
        return jsonify({"success": False, "message": "Název klíče musí mít 1 až 60 znaků."}), 400
    name = " ".join(name.split())
    if not name or len(name) > 60:
        return jsonify({"success": False, "message": "Název klíče musí mít 1 až 60 znaků."}), 400
    if not isinstance(action, str):
        return jsonify({"success": False, "message": "Vyberte platnou funkci klíče."}), 400
    action = action.strip()
    if action not in ("unlock", "ring", "permanent_toggle", "web_block_toggle"):
        return jsonify({"success": False, "message": "Vyberte platnou funkci klíče."}), 400

    user_id = session.get("user_id")
    now = time.time()
    with auth.get_db_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        registration = conn.execute(
            "SELECT card_hash, valid, unit_id FROM security_key_registration WHERE id = 1 AND started_by = ? AND expires_at >= ?",
            (user_id, now)
        ).fetchone()
        if not registration:
            return jsonify({"success": False, "message": "Registrace vypršela. Spusťte ji znovu."}), 410
        if registration["valid"] != 0:
            return jsonify({
                "success": False,
                "message": "Tuto kartu nelze přiřadit: je již zaregistrována pro odemykání v nastavení zámku."
            }), 409
        if not registration["card_hash"]:
            return jsonify({"success": False, "message": "Nejdříve přiložte čipovou kartu k jednotce."}), 400

        try:
            result = conn.execute(
                "INSERT INTO security_keys (name, card_hash, action, created_by, unit_id) VALUES (?, ?, ?, ?, ?)",
                (name, registration["card_hash"], action, user_id, registration["unit_id"])
            )
        except sqlite3.IntegrityError:
            return jsonify({"success": False, "message": "Tento klíč je již v systému zaregistrován."}), 409

        conn.execute(
            "DELETE FROM security_key_registration WHERE id = 1 AND started_by = ?",
            (user_id,)
        )

    add_log("info", "RFID KLÍČ", f"Uživatel '{session.get('username')}' zaregistroval klíč '{name}' ({action}).")
    return jsonify({"success": True, "id": result.lastrowid}), 201


@app.route("/api/security-keys/registration", methods=["GET", "POST", "DELETE"])
@login_required
@admin_or_spravce_required
def security_key_registration():
    user_id = session.get("user_id")

    if request.method == "GET":
        with auth.get_db_connection() as conn:
            registration = conn.execute(
                "SELECT expires_at, card_hash, valid, unit_id FROM security_key_registration WHERE id = 1 AND started_by = ?",
                (user_id,)
            ).fetchone()
        now = time.time()
        if not registration or registration["expires_at"] < now:
            return jsonify({"active": False, "captured": False, "remaining_seconds": 0})
        return jsonify({
            "active": True,
            "captured": bool(registration["card_hash"]),
            "registered_in_lock": registration["valid"] == 1,
            "unit_id": registration["unit_id"],
            "remaining_seconds": max(0, int(registration["expires_at"] - now + 0.999))
        })

    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        raw_unit_id = data.get("unit_id")
        if raw_unit_id == "all":
            unit_id = None
        elif isinstance(raw_unit_id, int) and not isinstance(raw_unit_id, bool) and get_unit(raw_unit_id):
            unit_id = raw_unit_id
        else:
            return jsonify({"success": False, "message": "Vyberte jednotku nebo všechny jednotky."}), 400
        if unit_id is None and not get_units():
            return jsonify({"success": False, "message": "Nejdříve přidejte alespoň jednu jednotku."}), 400
        now = time.time()
        expires_at = now + 15
        with auth.get_db_connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            active = conn.execute(
                "SELECT started_by FROM security_key_registration WHERE id = 1 AND expires_at >= ? AND started_by != ?",
                (now, user_id)
            ).fetchone()
            if active:
                return jsonify({"success": False, "message": "Jiný uživatel právě registruje bezpečnostní klíč."}), 409
            conn.execute(
                """
                INSERT INTO security_key_registration (id, expires_at, card_hash, valid, unit_id, started_by)
                VALUES (1, ?, NULL, NULL, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    expires_at = excluded.expires_at,
                    card_hash = NULL,
                    valid = NULL,
                    unit_id = excluded.unit_id,
                    started_by = excluded.started_by
                """,
                (expires_at, unit_id, user_id)
            )
        add_log("info", "RFID REGISTRACE", f"Uživatel '{session.get('username')}' zahájil registraci klíče.")
        return jsonify({"success": True, "remaining_seconds": 15})

    with auth.get_db_connection() as conn:
        result = conn.execute(
            "DELETE FROM security_key_registration WHERE id = 1 AND started_by = ?",
            (user_id,)
        )
    return jsonify({"success": True, "cancelled": result.rowcount > 0})


@app.route("/api/security-keys/<int:key_id>", methods=["DELETE"])
@login_required
@admin_or_spravce_required
def delete_security_key(key_id):
    with auth.get_db_connection() as conn:
        result = conn.execute("DELETE FROM security_keys WHERE id = ?", (key_id,))
    if result.rowcount == 0:
        return jsonify({"success": False, "message": "Bezpečnostní klíč nebyl nalezen."}), 404
    add_log("info", "RFID KLÍČ", f"Uživatel '{session.get('username')}' odstranil bezpečnostní klíč #{key_id}.")
    return jsonify({"success": True})


@app.route("/api/logs/clear", methods=["POST"])
@login_required
@admin_or_spravce_required
def clear_logs():
    """Vymaže záznamy ze sdíleného souboru (admin nebo správce)."""
    _write_logs([])
    add_log("info", "LOG", f"Záznamy byly vyčištěny uživatelem '{session.get('username')}'.")
    return jsonify({"success": True})


@app.route("/api/test-connection", methods=["POST"])
@login_required
@admin_or_spravce_required
def test_connection():
    """Rychlý test dostupnosti 2N jednotky a platnosti přihlašovacích údajů."""
    if not config.DEVICE_IP:
        return jsonify({"success": False, "message": "Není zadána IP adresa 2N jednotky."}), 400

    target_url = f"{config.DEVICE_PROTOCOL}://{config.DEVICE_IP}:{config.DEVICE_PORT}/api/switch/caps"
    add_log("info", "TEST", f"Uživatel '{session.get('username')}' testuje spojení s 2N na {target_url}...")

    auth_handler = HTTPDigestAuth(config.API_USERNAME, config.API_PASSWORD) if config.AUTH_TYPE == "digest" else HTTPBasicAuth(config.API_USERNAME, config.API_PASSWORD)
    start_time = time.time()
    try:
        res = requests.get(target_url, auth=auth_handler, timeout=config.REQUEST_TIMEOUT, verify=config.VERIFY_SSL)
        elapsed_ms = int((time.time() - start_time) * 1000)
        if res.status_code == 200:
            add_log("success", "TEST ÚSPĚŠNÝ", f"Spojení s 2N je funkční (odezva {elapsed_ms} ms).")
            return jsonify({"success": True, "message": f"Spojení s 2N je funkční (odezva {elapsed_ms} ms)."})
        else:
            add_log("warning", "TEST CHYBA", f"2N vrátila HTTP {res.status_code}", {"status": res.status_code, "body": res.text[:200]})
            return jsonify({"success": False, "message": f"2N vrátila HTTP kód {res.status_code}."}), res.status_code
    except Exception as e:
        elapsed_ms = int((time.time() - start_time) * 1000)
        add_log("error", "TEST SELHAL", f"Chyba spojení po {elapsed_ms} ms: {str(e)}")
        return jsonify({"success": False, "message": f"Chyba spojení: {str(e)}"}), 502


def send_switch_command(action: str) -> tuple[bool, str, int, int]:
    """
    Odesílá API požadavek na 2N Access Unit M pro ovládání spínače.
    action: "trigger" (časový impuls), "on" (trvalé sepnutí), "off" (vypnutí/návrat)
    Vrací: (success, message, elapsed_ms, http_status)
    """
    if not config.DEVICE_IP or not config.API_USERNAME or not config.API_PASSWORD:
        return False, "Chybí konfigurace 2N (IP adresa, jméno nebo heslo API).", 0, 400

    target_url = f"{config.DEVICE_PROTOCOL}://{config.DEVICE_IP}:{config.DEVICE_PORT}/api/switch/ctrl"
    params = {
        "switch": config.SWITCH_ID,
        "action": action
    }

    if config.AUTH_TYPE == "basic":
        primary_auth = HTTPBasicAuth(config.API_USERNAME, config.API_PASSWORD)
        fallback_auth = HTTPDigestAuth(config.API_USERNAME, config.API_PASSWORD)
    else:
        primary_auth = HTTPDigestAuth(config.API_USERNAME, config.API_PASSWORD)
        fallback_auth = HTTPBasicAuth(config.API_USERNAME, config.API_PASSWORD)

    start_time = time.time()
    try:
        response = requests.get(
            target_url,
            params=params,
            auth=primary_auth,
            timeout=config.REQUEST_TIMEOUT,
            verify=config.VERIFY_SSL
        )
        elapsed_ms = int((time.time() - start_time) * 1000)

        if response.status_code == 401 and fallback_auth:
            response = requests.get(
                target_url,
                params=params,
                auth=fallback_auth,
                timeout=config.REQUEST_TIMEOUT,
                verify=config.VERIFY_SSL
            )
            elapsed_ms = int((time.time() - start_time) * 1000)

        if response.status_code == 200:
            try:
                data = response.json()
                if data.get("success", False) is True:
                    return True, "Dveře byly úspěšně aktivovány!", elapsed_ms, 200
                else:
                    err_info = data.get("error", {})
                    err_msg = err_info.get("description", "Neznámá chyba z 2N")
                    return False, f"Chyba jednotky 2N: {err_msg}", elapsed_ms, 502
            except Exception:
                return True, "Dveře byly úspěšně aktivovány!", elapsed_ms, 200
        elif response.status_code == 401:
            return False, "Neplatné přihlašovací údaje k 2N API (401 Unauthorized).", elapsed_ms, 401
        elif response.status_code == 403:
            return False, "Přístup zakázán (403 Forbidden). Účet nemá oprávnění pro ovládání spínače v 2N jednotce.", elapsed_ms, 403
        else:
            return False, f"Jednotka 2N vrátila neočekávaný kód HTTP {response.status_code}.", elapsed_ms, response.status_code

    except requests.exceptions.Timeout:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return False, f"Vypršel časový limit pro spojení s 2N ({config.DEVICE_IP}) po {elapsed_ms} ms.", elapsed_ms, 504
    except Exception as e:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return False, f"Chyba spojení s 2N: {str(e)}", elapsed_ms, 502


def send_unit_switch_command(unit, action=None):
    action = action or unit["switch_action"]
    target_url = f"{unit_base_url(unit['protocol'], unit['ip'], unit['port'])}/api/switch/ctrl"
    params = {"switch": unit["switch_id"], "action": action}
    start_time = time.time()
    try:
        for handler, auth_type in unit_auth_handlers(
            unit["api_username"],
            unit["api_password"],
            unit["auth_type"]
        ):
            response = requests.get(
                target_url,
                params=params,
                auth=handler,
                timeout=config.REQUEST_TIMEOUT,
                verify=config.VERIFY_SSL
            )
            if response.status_code == 401 and auth_type == unit["auth_type"]:
                continue
            elapsed_ms = int((time.time() - start_time) * 1000)
            if response.status_code == 200:
                try:
                    result = response.json()
                except requests.exceptions.JSONDecodeError:
                    result = None
                if result is None or result.get("success") is True:
                    return True, "Jednotka byla úspěšně aktivována.", elapsed_ms, 200
                error = result.get("error", {})
                return False, error.get("description", "Jednotka vrátila chybu."), elapsed_ms, 502
            if response.status_code == 401:
                return False, "Neplatné přihlašovací údaje k API jednotky.", elapsed_ms, 401
            if response.status_code == 403:
                return False, "API účet nemá oprávnění k ovládání spínače.", elapsed_ms, 403
            return False, f"Jednotka vrátila HTTP {response.status_code}.", elapsed_ms, response.status_code
        elapsed_ms = int((time.time() - start_time) * 1000)
        return False, "Neplatné přihlašovací údaje k API jednotky.", elapsed_ms, 401
    except requests.exceptions.Timeout:
        elapsed_ms = int((time.time() - start_time) * 1000)
        return False, f"Vypršel časový limit spojení s jednotkou {unit['name']}.", elapsed_ms, 504
    except requests.RequestException as error:
        elapsed_ms = int((time.time() - start_time) * 1000)
        logger.warning("Chyba komunikace s jednotkou %s: %s", unit["id"], error)
        return False, "Chyba při komunikaci s jednotkou.", elapsed_ms, 502


@app.route("/api/units/<int:unit_id>/unlock", methods=["POST"])
@login_required
def unlock_unit(unit_id):
    user_id = session.get("user_id")
    username = session.get("username", "neznámý")
    if is_web_unlock_blocked(unit_id):
        return jsonify({
            "success": False,
            "message": "Odemčení přes webové rozhraní je zablokováno bezpečnostním klíčem."
        }), 403
    if not unit_is_selected_for_user(user_id, unit_id):
        return permission_denied_response()

    unit = get_unit(unit_id, include_secret=True)
    if not unit:
        return jsonify({"success": False, "message": "Jednotka nebyla nalezena."}), 404

    user_data = auth.get_user_by_id(user_id)
    access = get_unit_access(user_id, unit_id)
    if session.get("role") != "admin" and not access["can_unlock"]:
        return permission_denied_response()
    if user_data:
        if user_data.get("is_disabled"):
            return jsonify({"success": False, "message": "Váš účet je deaktivován správcem systému."}), 403
        schedule_ok, schedule_reason = check_unit_schedule(user_id, unit_id, datetime.now())
        if not schedule_ok:
            return jsonify({"success": False, "message": schedule_reason}), 403

    has_bypass = session.get("role") == "admin" or bool(access["network_bypass"])
    ip_allowed = is_ip_in_allowed_subnets(get_client_ip())
    data = request.get_json(silent=True) or request.form or {}
    client_probe_ok = bool(data.get("client_probe_ok", False))
    if not has_bypass and not ip_allowed and not client_probe_ok:
        return jsonify({
            "success": False,
            "message": "Nejste připojeni k povolené síti. Nelze odemknout dveře."
        }), 403

    now = time.time()
    cooldown = COOLDOWN_SECONDS
    with auth.get_db_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        current = conn.execute(
            "SELECT last_unlock_at FROM units WHERE id = ?",
            (unit_id,)
        ).fetchone()
        if not current:
            return jsonify({"success": False, "message": "Jednotka nebyla nalezena."}), 404
        last_unlock_at = current["last_unlock_at"] or 0
        if now - last_unlock_at < cooldown:
            remaining = round(cooldown - (now - last_unlock_at), 1)
            return jsonify({
                "success": False,
                "message": f"Jednotka byla právě aktivována. Počkejte prosím {remaining} s."
            }), 429
        conn.execute("UPDATE units SET last_unlock_at = ? WHERE id = ?", (now, unit_id))

    success, message, elapsed_ms, http_status = send_unit_switch_command(unit)
    if success:
        with auth.get_db_connection() as conn:
            conn.execute(
                "UPDATE units SET connected = 1, last_seen = CURRENT_TIMESTAMP WHERE id = ?",
                (unit_id,)
            )
        add_log("success", "JEDNOTKA ODEMKČENA", f"Uživatel '{username}' odemkl jednotku '{unit['name']}' ({elapsed_ms} ms).", unit_id=unit_id, unit_name=unit["name"])
        return jsonify({
            "success": True,
            "message": f"Jednotka „{unit['name']}“ byla úspěšně odemčena.",
            "elapsed_ms": elapsed_ms
        })

    with auth.get_db_connection() as conn:
        conn.execute(
            "UPDATE units SET last_unlock_at = ? WHERE id = ? AND last_unlock_at = ?",
            (last_unlock_at, unit_id, now)
        )
    add_log("error", "ODEMČENÍ JEDNOTKY SELHALO", f"Uživatel '{username}' neodemkl jednotku '{unit['name']}': {message}", unit_id=unit_id, unit_name=unit["name"])
    return jsonify({"success": False, "message": message}), http_status


@app.route("/api/unlock", methods=["POST"])
@login_required
def unlock_door():
    """Compat endpoint routed through per-unit authorization for older clients."""
    units = get_units()
    unit = next((candidate for candidate in units if candidate["is_legacy"]), None)
    if unit is None and len(units) == 1:
        unit = units[0]
    if unit is None:
        return jsonify({
            "success": False,
            "message": "Vyberte konkrétní jednotku pro odemčení."
        }), 409
    return redirect(f"/api/units/{unit['id']}/unlock", code=307)


# ==============================================================================
# TRVALÉ ODEMČENÍ DVEŘÍ (BLOKOVÁNÍ V OTEVŘENÉ POLOZE)
# ==============================================================================

@app.route("/api/permanent-unlock/status", methods=["GET"])
@login_required
def get_permanent_unlock_status():
    """Vrací stav trvalého odemčení jedné nebo všech viditelných jednotek."""
    user_id = session.get("user_id")
    unit_id = request.args.get("unit_id", type=int)
    if unit_id is None:
        visible = [
            unit for unit in get_units()
            if session.get("role") == "admin" or unit_is_selected_for_user(user_id, unit["id"])
        ]
        return jsonify({
            "success": True,
            "units": [
                {
                    "unit": public_unit(unit),
                    "state": get_unit_permanent_state(unit["id"]),
                    "permission": {
                        "can_unlock": (
                            session.get("role") == "admin"
                            or bool(get_unit_access(user_id, unit["id"])["can_unlock"])
                        ),
                        "network_bypass": (
                            session.get("role") == "admin"
                            or bool(get_unit_access(user_id, unit["id"])["network_bypass"])
                        ),
                        "permanent_unlock_allowed": (
                            session.get("role") == "admin"
                            or bool(get_unit_access(user_id, unit["id"])["permanent_unlock_allowed"])
                        ),
                        "permanent_unlock_max_duration": (
                            1440 if session.get("role") == "admin"
                            else get_unit_access(user_id, unit["id"])["permanent_unlock_max_duration"]
                        ),
                    },
                    "web_unlock_blocked": is_web_unlock_blocked(unit["id"]),
                }
                for unit in visible
            ]
        })
    if not unit_is_selected_for_user(user_id, unit_id):
        return permission_denied_response()
    unit = get_unit(unit_id)
    if not unit:
        return jsonify({"success": False, "message": "Jednotka nebyla nalezena."}), 404
    access = get_unit_access(user_id, unit_id)
    return jsonify({
        "success": True,
        "permission": {
            "allowed": session.get("role") == "admin" or bool(access["permanent_unlock_allowed"]),
            "max_duration": 1440 if session.get("role") == "admin" else access["permanent_unlock_max_duration"],
        },
        "state": get_unit_permanent_state(unit_id),
        "web_unlock_blocked": is_web_unlock_blocked(unit_id)
    })


@app.route("/api/permanent-unlock/start", methods=["POST"])
@login_required
def start_permanent_unlock():
    """Aktivuje trvalé odemčení dveří na zadanou dobu (v minutách)."""
    user_id = session.get("user_id")
    username = session.get("username", "neznámý")
    data = request.get_json(silent=True) or request.form or {}
    unit_id = data.get("unit_id")
    if not isinstance(unit_id, int) or isinstance(unit_id, bool):
        return jsonify({"success": False, "message": "Vyberte jednotku."}), 400
    unit = get_unit(unit_id, include_secret=True)
    if not unit:
        return jsonify({"success": False, "message": "Jednotka nebyla nalezena."}), 404
    if not unit_is_selected_for_user(user_id, unit_id):
        return permission_denied_response()
    if is_web_unlock_blocked(unit_id):
        add_log("warning", "WEB ODEMYKÁNÍ BLOKOVÁNO", f"Trvalé odemčení přes web uživatele '{username}' bylo odmítnuto globální blokací.")
        return jsonify({
            "success": False,
            "message": "Odemčení přes webové rozhraní je zablokováno bezpečnostním klíčem."
        }), 403

    # 1. Kontrola oprávnění uživatele
    access = get_unit_access(user_id, unit_id)
    perm = {
        "allowed": bool(access["permanent_unlock_allowed"]),
        "max_duration": access["permanent_unlock_max_duration"],
    }
    if session.get("role") == "admin":
        perm = {"allowed": True, "max_duration": 1440}
    if session.get("role") != "admin" and not perm.get("allowed"):
        add_log("warning", "TRVALÉ ODEMČENÍ OMEZENO", f"Uživatel '{username}' se pokusil o trvalé odemčení bez oprávnění.")
        return permission_denied_response()

    # 2. Kontrola sítě Sesule a bypassu
    has_bypass = session.get("role") == "admin" or bool(access["network_bypass"])
    client_ip = get_client_ip()
    ip_allowed = is_ip_in_allowed_subnets(client_ip)
    client_probe_ok = bool(data.get("client_probe_ok", False))

    if not has_bypass and not ip_allowed and not client_probe_ok:
        add_log("warning", "SÍŤ BLOKOVÁNA", f"Uživatel '{username}' zablokován při pokusu o trvalé odemčení z nepovolené IP {client_ip}.")
        return jsonify({
            "success": False,
            "message": "Nejste připojeni k síti Sesule. Nelze povolit trvalé odemčení dveří."
        }), 403

    # 3. Kontrola doby trvání podle permissions_config
    user_role = session.get("role", "user")
    configured_user_max = perm.get("max_duration", 60)
    allowed_max = permissions_config.clamp_permanent_unlock_duration(
        1440 if user_role == "admin" else configured_user_max,
        user_role
    )
    try:
        duration_minutes = int(data.get("duration_minutes", allowed_max))
    except (ValueError, TypeError):
        duration_minutes = allowed_max

    duration_minutes = max(permissions_config.PERMANENT_UNLOCK_CONFIG["min_duration_minutes"], min(allowed_max, duration_minutes))

    schedule_ok, schedule_reason = check_unit_schedule(user_id, unit_id)
    if not schedule_ok:
        return jsonify({"success": False, "message": schedule_reason}), 403

    # 4. Odeslání příkazu 'hold' do zvolené jednotky
    auth_reason = "BYPASS" if has_bypass else ("LAN" if ip_allowed else "SONDA 2N OK")
    add_log("info", "POŽADAVEK", f"Uživatel '{username}' [{auth_reason}] odesílá příkaz k trvalému odemčení jednotky '{unit['name']}' na {duration_minutes} min.", unit_id=unit_id, unit_name=unit["name"])

    success, msg, elapsed_ms, http_status = send_unit_switch_command(unit, "hold")
    if success:
        new_state = set_unit_permanent_state(unit_id, True, user_id=user_id, username=username, duration_minutes=duration_minutes)
        add_log("success", "TRVALE ODEMČENO", f"Jednotka '{unit['name']}' zůstává odemčena uživatelem '{username}' na {duration_minutes} min ({elapsed_ms} ms).", unit_id=unit_id, unit_name=unit["name"])
        return jsonify({
            "success": True,
            "message": f"Dveře byly trvale odemčeny na {duration_minutes} minut.",
            "state": new_state
        })
    else:
        add_log("error", "TRVALÉ ODEMČENÍ SELHALO", f"Chyba při sepnutí spínače v 2N: {msg}")
        return jsonify({
            "success": False,
            "message": msg
        }), http_status


@app.route("/api/permanent-unlock/stop", methods=["POST"])
@login_required
def stop_permanent_unlock():
    """Zruší trvalé odemčení a vrátí zámek do výchozího stavu (uzamčeno)."""
    user_id = session.get("user_id")
    username = session.get("username", "neznámý")
    data = request.get_json(silent=True) or request.form or {}
    unit_id = data.get("unit_id")
    if not isinstance(unit_id, int) or isinstance(unit_id, bool):
        return jsonify({"success": False, "message": "Vyberte jednotku."}), 400
    unit = get_unit(unit_id, include_secret=True)
    if not unit:
        return jsonify({"success": False, "message": "Jednotka nebyla nalezena."}), 404
    if not unit_is_selected_for_user(user_id, unit_id):
        return permission_denied_response()

    access = get_unit_access(user_id, unit_id)
    perm = {"allowed": bool(access["permanent_unlock_allowed"])}
    current_state = get_unit_permanent_state(unit_id)
    is_admin_or_spravce = session.get("role") in ("admin", "správce")
    is_initiator = (current_state.get("activated_by_id") == user_id)
    is_rfid_controlled = (
        current_state.get("active")
        and str(current_state.get("activated_by_username") or "").startswith("RFID:")
    )

    if not is_rfid_controlled:
        if session.get("role") == "správce" and not is_initiator:
            initiator = auth.get_user_by_id(current_state.get("activated_by_id")) if current_state.get("activated_by_id") else None
            if not initiator or ROLE_LEVELS.get(initiator.get("role"), -1) >= ROLE_LEVELS["správce"]:
                return permission_denied_response()
        elif session.get("role") != "admin" and not is_admin_or_spravce and not perm.get("allowed") and not is_initiator:
            return permission_denied_response()

    add_log("info", "POŽADAVEK", f"Uživatel '{username}' odesílá příkaz k uzamčení jednotky '{unit['name']}'.", unit_id=unit_id, unit_name=unit["name"])

    success, msg, elapsed_ms, http_status = send_unit_switch_command(unit, "release")

    if success:
        new_state = set_unit_permanent_state(unit_id, False)
        add_log("success", "UZAMČENO", f"Trvalé odemčení jednotky '{unit['name']}' ukončeno uživatelem '{username}' ({elapsed_ms} ms).", unit_id=unit_id, unit_name=unit["name"])
        return jsonify({
            "success": True,
            "message": "Trvalé odemčení bylo ukončeno. Dveře jsou opět uzamčeny.",
            "state": new_state
        })
    else:
        add_log("warning", "UZAMČENÍ CHYBA", f"Příkaz pro uzamčení jednotky '{unit['name']}' selhal: {msg}", unit_id=unit_id, unit_name=unit["name"])
        return jsonify({
            "success": False,
            "message": f"Chyba při komunikaci s 2N: {msg}",
            "state": current_state
        }), http_status


@app.route("/api/permanent-unlock/users/<int:target_user_id>", methods=["POST"])
@login_required
@admin_or_spravce_required
def set_user_permanent_unlock_config(target_user_id: int):
    """Nastaví oprávnění a dobu trvalého odemčení pro uživatele a konkrétní jednotku."""
    data = request.get_json(silent=True) or request.form or {}
    allowed = data.get("allowed", False)
    unit_id = data.get("unit_id")
    if not isinstance(allowed, bool):
        return jsonify({"success": False, "message": "Příznak oprávnění musí být typu boolean."}), 400
    if not isinstance(unit_id, int) or isinstance(unit_id, bool) or not get_unit(unit_id):
        return jsonify({"success": False, "message": "Vyberte platnou jednotku."}), 400
    try:
        max_duration = int(data.get("max_duration", 60))
    except (ValueError, TypeError):
        max_duration = 60

    caller_role = session.get("role")
    target_user = auth.get_user_by_id(target_user_id)
    if not target_user:
        return jsonify({"success": False, "message": "Uživatel nebyl nalezen."}), 404
    if target_user.get("username", "").lower() == "admin":
        return permission_denied_response()

    if caller_role == "správce":
        if ROLE_LEVELS.get(target_user.get("role"), -1) >= ROLE_LEVELS["správce"]:
            return permission_denied_response()
        if max_duration > 120:
            return permission_denied_response()

    if max_duration < 1 or max_duration > (120 if caller_role == "správce" else 1440):
        return jsonify({"success": False, "message": "Maximální doba překračuje povolený limit."}), 400
    current_access = get_unit_access(target_user_id, unit_id)
    with auth.get_db_connection() as conn:
        conn.execute(
            """
            INSERT INTO user_unit_access (
                user_id, unit_id, can_unlock, network_bypass,
                permanent_unlock_allowed, permanent_unlock_max_duration
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, unit_id) DO UPDATE SET
                permanent_unlock_allowed = excluded.permanent_unlock_allowed,
                permanent_unlock_max_duration = excluded.permanent_unlock_max_duration
            """,
            (
                target_user_id, unit_id, current_access["can_unlock"],
                current_access["network_bypass"], int(allowed), max_duration
            )
        )
    unit = get_unit(unit_id)
    admin_name = session.get("username", "admin")
    state_str = f"POVOLIL (max {max_duration} min)" if allowed else "ZAKÁZAL"
    add_log("info", "SPRÁVA TRVALÉHO ODEMČENÍ", f"Správce '{admin_name}' {state_str} trvalé odemčení pro uživatele '{target_user['username']}' na jednotce '{unit['name']}'.", unit_id=unit_id, unit_name=unit["name"])
    return jsonify({"success": True, "message": "Oprávnění bylo uloženo.", "allowed": allowed, "max_duration": max_duration})



# ==============================================================================
# PUSH NOTIFIKACE (Web Push)
# ==============================================================================

def get_push_subscriptions_for_unit(unit_id):
    with auth.get_db_connection() as conn:
        rows = conn.execute(
            """
            SELECT ps.endpoint, ps.p256dh, ps.auth_key
            FROM push_subscriptions ps
            WHERE NOT EXISTS (
                SELECT 1 FROM user_unit_preferences pref
                WHERE pref.user_id = ps.user_id
            ) OR EXISTS (
                SELECT 1 FROM user_display_units selected
                WHERE selected.user_id = ps.user_id AND selected.unit_id = ?
            )
            """,
            (unit_id,)
        ).fetchall()
    return [
        {"endpoint": row["endpoint"], "keys": {"p256dh": row["p256dh"], "auth": row["auth_key"]}}
        for row in rows
    ]


def send_push_notification(title: str, body: str, url: str = "/", unit_id=None):
    """Odeslání Web Push notifikace všem uživatelům s povoleným oznámením."""
    if not config.VAPID_PRIVATE_KEY:
        logger.warning("VAPID privátní klíč není k dispozici, push notifikace nelze odeslat.")
        return 0

    subscriptions = (
        get_push_subscriptions_for_unit(unit_id)
        if unit_id is not None
        else auth.get_all_push_subscriptions()
    )
    if not subscriptions:
        logger.info("Žádné aktivní push subscriptions k odeslání.")
        return 0

    payload = json.dumps({
        "title": title,
        "body": body,
        "icon": "/icons/icon-192x192.png",
        "badge": "/icons/icon-96x96.png",
        "data": {
            "url": url,
            "timestamp": int(time.time() * 1000)
        }
    })

    success_count = 0
    expired = []

    for sub in subscriptions:
        try:
            vapid_key = config.VAPID_PRIVATE_KEY_PATH if (hasattr(config, "VAPID_PRIVATE_KEY_PATH") and os.path.exists(config.VAPID_PRIVATE_KEY_PATH)) else config.VAPID_PRIVATE_KEY
            pywebpush.webpush(
                subscription_info=sub,
                data=payload,
                vapid_private_key=vapid_key,
                vapid_claims={"sub": config.VAPID_CLAIMS_EMAIL}
            )
            success_count += 1
        except pywebpush.WebPushException as ex:
            logger.warning(f"Chyba při odesílání push: {ex}")
            if ex.response is not None and ex.response.status_code in (404, 410):
                expired.append(sub["endpoint"])
        except Exception as e:
            logger.warning(f"Neočekávaná chyba při push notifikaci: {e}")

    for ep in expired:
        auth.remove_push_subscription(ep)

    return success_count


# Ochrana proti zahlcení notifikací zvonku a odložené zvonění pro každou jednotku zvlášť
LAST_DOORBELL_TIMES = {}
DOORBELL_PENDING_TIMERS = {}
DOORBELL_PENDING_LOCK = threading.Lock()


def handle_doorbell_ring(source_info: str = "2N Událost", unit_id=None, unit_name=None) -> bool:
    """
    Zpracuje událost zazvonění u dveří.
    Aplikuje debounce, zaloguje záznam a rozešle Web Push notifikaci všem aktivním uživatelům.
    """
    cooldown = getattr(config, "DOORBELL_COOLDOWN_SECONDS", 5.0)
    now = time.time()
    cooldown_key = unit_id if unit_id is not None else 0
    if now - LAST_DOORBELL_TIMES.get(cooldown_key, 0) < cooldown:
        logger.info(f"Ignorováno duplicitní zvonění v rámci cooldownu ({source_info}).")
        return False

    LAST_DOORBELL_TIMES[cooldown_key] = now
    unit_label = f" na jednotce „{unit_name}“" if unit_name else ""
    add_log(
        "warning",
        "ZVONĚNÍ U DVEŘÍ",
        f"Někdo zvoní{unit_label}! ({source_info})",
        unit_id=unit_id,
        unit_name=unit_name,
    )
    title = f"Zvonění – {unit_name}" if unit_name else "Dveře Šešule"
    body = f"Někdo zvoní na jednotce {unit_name}." if unit_name else "Někdo zvoní u dveří."
    sent = send_push_notification(title, body, "/", unit_id=unit_id)
    add_log(
        "info",
        "PUSH ODESLÁNO",
        f"Oznámení o zvonění odesláno na {sent} zařízení.",
        unit_id=unit_id,
        unit_name=unit_name,
    )
    return True


def schedule_doorbell_ring(source_info: str = "2N Událost", delay: float = None, unit_id=None, unit_name=None) -> None:
    """
    Naplánuje odeslání notifikace o zvonění po uplynutí delay (výchozí 1.5s).
    Pokud během této doby dorazí událost UserAuthenticated, zvonění je stornováno.
    """
    if delay is None:
        delay = getattr(config, "DOORBELL_AUTH_WINDOW_SECONDS", 1.5)

    cooldown = getattr(config, "DOORBELL_COOLDOWN_SECONDS", 5.0)
    now = time.time()
    pending_key = unit_id if unit_id is not None else 0

    with DOORBELL_PENDING_LOCK:
        if now - LAST_DOORBELL_TIMES.get(pending_key, 0) < cooldown:
            logger.info(f"Ignorováno plánování zvonění v rámci cooldownu ({source_info}).")
            return

        existing_timer = DOORBELL_PENDING_TIMERS.get(pending_key)
        if existing_timer is not None and existing_timer.is_alive():
            logger.debug(f"Plánované zvonění již čeká ve frontě ({source_info}).")
            return

        def _trigger():
            with DOORBELL_PENDING_LOCK:
                DOORBELL_PENDING_TIMERS.pop(pending_key, None)
            handle_doorbell_ring(source_info, unit_id=unit_id, unit_name=unit_name)

        timer = threading.Timer(delay, _trigger)
        timer.daemon = True
        DOORBELL_PENDING_TIMERS[pending_key] = timer
        timer.start()
        logger.info(f"Naplánováno zvonění za {delay}s ({source_info}) – čeká se na případné ověření uživatele.")


def cancel_doorbell_ring(reason: str = "UserAuthenticated", unit_id=None) -> bool:
    """
    Zruší naplánované zvonění, pokud dojde k úspěšné autentizaci uživatele.
    """
    with DOORBELL_PENDING_LOCK:
        pending_key = unit_id if unit_id is not None else 0
        timer = DOORBELL_PENDING_TIMERS.get(pending_key)
        if timer is not None and timer.is_alive():
            timer.cancel()
            DOORBELL_PENDING_TIMERS.pop(pending_key, None)
            logger.info(f"Plánované zvonění zrušeno: {reason}")
            unit = get_unit(unit_id) if unit_id is not None else None
            add_log("info", "2N AUTH", f"Ověření uživatele ({reason}) – notifikace zvonění zrušena.", unit_id=unit_id, unit_name=unit["name"] if unit else None)
            return True
        return False


def process_unit_event(unit, event):
    event_type = str(event.get("event") or event.get("type") or event.get("name") or "")
    normalized_event_type = "".join(char for char in event_type.casefold() if char.isalnum())
    params = event.get("params") if isinstance(event.get("params"), dict) else {}
    safe_params = redact_card_identifiers(params)
    logger.info("2N událost z jednotky '%s': event='%s' params=%s", unit["name"], event_type, safe_params)

    def schedule(source):
        schedule_doorbell_ring(source, unit_id=unit["id"], unit_name=unit["name"])

    if event_type == "UserAuthenticated" or ("uuid" in params and "name" in params):
        user_name = params.get("name") or params.get("uuid") or "Uživatel"
        cancel_doorbell_ring(f"UserAuthenticated ({user_name})", unit_id=unit["id"])
        add_log("info", "2N PŘÍSTUP", f"Uživatel ověřen na jednotce '{unit['name']}': {user_name}", unit_id=unit["id"], unit_name=unit["name"])
    elif event_type == "KeyPressed" or str(params.get("key", "")).upper() == "B":
        key = str(params.get("key", "B")).upper()
        if key == "B":
            schedule(f"{unit['name']}: KeyPressed (key={key})")
        else:
            add_log("info", "2N KLÁVESA", f"Jednotka '{unit['name']}': stisknuta klávesa {key}.", unit_id=unit["id"], unit_name=unit["name"])
    elif event_type == "WaveKeyActivated" or str(params.get("type", "")).lower() in ("touch", "wave"):
        wave_type = str(params.get("type", "touch")).lower()
        if wave_type in ("touch", "wave"):
            schedule(f"{unit['name']}: WaveKeyActivated (type={wave_type})")
        else:
            add_log("info", "2N WAVEKEY", f"Jednotka '{unit['name']}': {safe_params}", unit_id=unit["id"], unit_name=unit["name"])
    elif event_type == "UserActionActivated":
        action_id = str(params.get("id", "1"))
        action_state = str(params.get("state", "out")).lower()
        if action_id == "1" and action_state in ("out", ""):
            schedule(f"{unit['name']}: UserActionActivated (id={action_id}, state={action_state})")
        else:
            add_log("info", "2N AKCE", f"Jednotka '{unit['name']}': akce {event_type} (id={action_id}, state={action_state}).", unit_id=unit["id"], unit_name=unit["name"])
    elif normalized_event_type in ("mobkeyentered", "cardentered", "accessgranted"):
        cancel_doorbell_ring(event_type, unit_id=unit["id"])
        add_log("info", "2N PŘÍSTUP", f"Detekována autorizace na jednotce '{unit['name']}' ({event_type}): {safe_params}", unit_id=unit["id"], unit_name=unit["name"])
    elif event_type not in ("CallStateChanged", "SwitchStateChanged"):
        logger.debug("Ostatní 2N událost z jednotky '%s' %s: %s", unit["name"], event_type, safe_params)

    process_card_event(event_type, event, unit["id"])


def poll_unit_events(unit_id, stop_event):
    while not stop_event.is_set():
        unit = get_unit(unit_id, include_secret=True)
        if not unit:
            return

        protocol_order = [unit["protocol"]]
        protocol_order.extend(protocol for protocol in ("https", "http") if protocol not in protocol_order)
        endpoints = [(unit["protocol"], unit["port"])]
        for protocol in protocol_order:
            port = 443 if protocol == "https" else 80
            if (protocol, port) not in endpoints:
                endpoints.append((protocol, port))

        subscription = None
        for protocol, port in endpoints:
            if stop_event.is_set():
                break
            base_url = unit_base_url(protocol, unit["ip"], port)
            for handler, auth_type in unit_auth_handlers(
                unit["api_username"], unit["api_password"], unit["auth_type"]
            ):
                try:
                    response = requests.get(
                        f"{base_url}/api/log/subscribe",
                        auth=handler,
                        verify=config.VERIFY_SSL,
                        timeout=10
                    )
                    payload = response.json() if response.status_code == 200 else {}
                except (requests.RequestException, ValueError) as error:
                    logger.debug("Odběr událostí z jednotky %s selhal: %s", unit_id, error)
                    continue
                result = payload.get("result") if isinstance(payload, dict) else None
                if payload.get("success") and isinstance(result, dict) and result.get("id") is not None:
                    subscription = {
                        "id": result["id"],
                        "base_url": base_url,
                        "auth": handler,
                        "protocol": protocol,
                        "port": port,
                        "auth_type": auth_type,
                    }
                    break
            if subscription:
                break

        if not subscription:
            with auth.get_db_connection() as conn:
                conn.execute("UPDATE units SET connected = 0 WHERE id = ?", (unit_id,))
            stop_event.wait(10)
            continue

        with auth.get_db_connection() as conn:
            conn.execute(
                """
                UPDATE units
                SET connected = 1, last_seen = CURRENT_TIMESTAMP,
                    protocol = ?, port = ?, auth_type = ?
                WHERE id = ?
                """,
                (subscription["protocol"], subscription["port"], subscription["auth_type"], unit_id)
            )
        add_log("info", "2N MONITOR", f"Aktivován odběr událostí z jednotky '{unit['name']}'.", unit_id=unit["id"], unit_name=unit["name"])

        try:
            while not stop_event.is_set():
                try:
                    response = requests.get(
                        f"{subscription['base_url']}/api/log/pull",
                        params={"id": subscription["id"], "timeout": 15},
                        auth=subscription["auth"],
                        verify=config.VERIFY_SSL,
                        timeout=25
                    )
                    if response.status_code != 200:
                        raise requests.RequestException(f"HTTP {response.status_code}")
                    payload = response.json()
                    if not payload.get("success"):
                        error = payload.get("error", {})
                        raise requests.RequestException(f"API error {error.get('code', 'unknown')}")
                    with auth.get_db_connection() as conn:
                        conn.execute(
                            "UPDATE units SET connected = 1, last_seen = CURRENT_TIMESTAMP WHERE id = ?",
                            (unit_id,)
                        )
                    for event in payload.get("result", {}).get("events", []):
                        process_unit_event(unit, event)
                except requests.exceptions.Timeout:
                    continue
                except (requests.RequestException, ValueError, TypeError) as error:
                    logger.warning("Odběr událostí z jednotky '%s' byl přerušen: %s", unit["name"], error)
                    break
                except Exception:
                    logger.exception("Zpracování události z jednotky '%s' selhalo.", unit["name"])
        finally:
            try:
                requests.get(
                    f"{subscription['base_url']}/api/log/unsubscribe",
                    params={"id": subscription["id"]},
                    auth=subscription["auth"],
                    verify=config.VERIFY_SSL,
                    timeout=5
                )
            except requests.RequestException:
                logger.debug("Nepodařilo se ukončit odběr jednotky %s.", unit_id)
            with auth.get_db_connection() as conn:
                conn.execute("UPDATE units SET connected = 0 WHERE id = ?", (unit_id,))

        stop_event.wait(3)


def start_2n_event_listener():
    """Spustí jediný procesní správce, který udržuje samostatný odběr pro každou 2N jednotku."""
    def run_unit_worker(unit_id, stop_event):
        while not stop_event.is_set():
            try:
                poll_unit_events(unit_id, stop_event)
                return
            except Exception:
                logger.exception("Monitor jednotky %s selhal a bude znovu spuštěn.", unit_id)
                with auth.get_db_connection() as conn:
                    conn.execute("UPDATE units SET connected = 0 WHERE id = ?", (unit_id,))
                stop_event.wait(10)

    def manager_loop():
        lock_file_path = os.path.join(config.DATA_DIR, "2n_poller.lock")
        try:
            lock_file = open(lock_file_path, "w")
            fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (IOError, BlockingIOError):
            logger.info("2N Event Poller již běží v jiném procesu, toto vlákno se ukončuje.")
            return

        logger.info("Správce 2N jednotek byl spuštěn jako výhradní proces.")
        workers = {}
        while True:
            try:
                configured_units = get_units()
            except Exception:
                logger.exception("Nepodařilo se načíst seznam 2N jednotek.")
                time.sleep(5)
                continue
            wanted_ids = {unit["id"] for unit in configured_units}
            for unit_id, (stop_event, thread) in list(workers.items()):
                if unit_id not in wanted_ids:
                    stop_event.set()
                if not thread.is_alive():
                    workers.pop(unit_id, None)
            for unit in configured_units:
                if unit["id"] not in workers:
                    stop_event = threading.Event()
                    thread = threading.Thread(
                        target=run_unit_worker,
                        args=(unit["id"], stop_event),
                        daemon=True,
                        name=f"2N-Event-Poller-{unit['id']}"
                    )
                    workers[unit["id"]] = (stop_event, thread)
                    thread.start()
            time.sleep(5)

    threading.Thread(target=manager_loop, daemon=True, name="2N-Event-Manager").start()


def permanent_unlock_monitor_loop():
    """Periodicky uzamkne každou jednotku po vypršení jejího limitu."""
    while True:
        try:
            time.sleep(1)
            for unit in get_units():
                state = get_unit_permanent_state(unit["id"])
                if not state.get("expires_at") or state.get("remaining_seconds", 0) > 0:
                    continue
                secret_unit = get_unit(unit["id"], include_secret=True)
                if not secret_unit:
                    continue
                success, msg, elapsed_ms, _ = send_unit_switch_command(secret_unit, "release")
                if success:
                    set_unit_permanent_state(unit["id"], False)
                    add_log("info", "TRVALÉ ODEMČENÍ VYPRŠELO", f"Časový limit na jednotce '{unit['name']}' vypršel. Dveře byly automaticky uzamčeny ({elapsed_ms} ms).", unit_id=unit["id"], unit_name=unit["name"])
                else:
                    logger.error("Automatické uzamčení jednotky %s po vypršení trvalého odemčení selhalo: %s", unit["id"], msg)
                    add_log("error", "AUTOMATICKÉ UZAMČENÍ SELHALO", f"Uzamčení jednotky '{unit['name']}' selhalo: {msg}", unit_id=unit["id"], unit_name=unit["name"])
        except Exception as ex:
            logger.error(f"Chyba v permanent_unlock_monitor_loop: {ex}")
            time.sleep(3)


def start_permanent_unlock_monitor():
    t = threading.Thread(target=permanent_unlock_monitor_loop, daemon=True, name="Permanent-Unlock-Monitor")
    t.start()


# Spuštění odběru událostí z 2N jednotky a monitoru trvalého odemčení
start_2n_event_listener()
start_permanent_unlock_monitor()


@app.route("/api/webhook/2n", methods=["GET", "POST"])
def webhook_2n():
    """
    Webhook přijímající signál z 2N jednotky (např. přes 2N Automation / HTTP request).
    Spustí se při události stisku zvonku / dotyku.
    """
    secret = request.args.get("secret") or (request.get_json(silent=True) or {}).get("secret")
    if config.WEBHOOK_SECRET and secret != config.WEBHOOK_SECRET:
        add_log("warning", "WEBHOOK ODMÍTNUT", "Neplatný secret pro 2N webhook.")
        return jsonify({"success": False, "message": "Neplatný secret."}), 403

    client_ip = get_client_ip()
    source_unit = next((unit for unit in get_units() if unit["ip"] == client_ip), None)
    source_unit_id = source_unit["id"] if source_unit else None
    source_unit_name = source_unit["name"] if source_unit else None
    req_json = request.get_json(silent=True) or {}

    # Získání parametrů události
    ev_type = request.args.get("event") or request.args.get("type") or req_json.get("event") or req_json.get("type") or "UserActionActivated"
    ev_id = str(request.args.get("id") or req_json.get("id") or req_json.get("params", {}).get("id") or "1")
    ev_state = str(request.args.get("state") or req_json.get("state") or req_json.get("params", {}).get("state") or "out")
    ev_key = str(request.args.get("key") or req_json.get("key") or req_json.get("params", {}).get("key") or "").upper()

    if ev_type == "UserAuthenticated":
        cancel_doorbell_ring(f"Webhook UserAuthenticated z {client_ip}", unit_id=source_unit_id)
    elif ev_type == "KeyPressed" and ev_key == "B":
        schedule_doorbell_ring(f"2N Webhook KeyPressed key=B z {client_ip}", unit_id=source_unit_id, unit_name=source_unit_name)
    elif ev_type == "WaveKeyActivated":
        schedule_doorbell_ring(f"2N Webhook WaveKeyActivated z {client_ip}", unit_id=source_unit_id, unit_name=source_unit_name)
    else:
        source_desc = f"2N Webhook z {client_ip} ({ev_type} id={ev_id}, state={ev_state})"
        schedule_doorbell_ring(source_desc, unit_id=source_unit_id, unit_name=source_unit_name)

    return jsonify({
        "success": True,
        "message": "Upozornění na zvonění bylo úspěšně zpracováno.",
        "event": ev_type,
        "id": ev_id,
        "state": ev_state
    })


@app.route("/api/push/subscribe", methods=["POST"])
@login_required
def push_subscribe():
    """Uloží push subscription pro přihlášeného uživatele."""
    user_id = session.get("user_id")
    data = request.get_json(silent=True) or {}
    endpoint = data.get("endpoint")
    keys = data.get("keys", {})
    p256dh = keys.get("p256dh")
    auth_key = keys.get("auth")

    if not endpoint or not p256dh or not auth_key:
        return jsonify({"success": False, "message": "Chybí parametry subscription."}), 400

    ok, msg = auth.save_push_subscription(user_id, endpoint, p256dh, auth_key)
    if ok:
        add_log("info", "NOTIFIKACE POVOLENY", f"Uživatel '{session.get('username')}' aktivoval push oznámení.")
    return jsonify({"success": ok, "message": msg}), (200 if ok else 400)


@app.route("/api/push/unsubscribe", methods=["POST"])
@login_required
def push_unsubscribe():
    """Odebere push subscription pro přihlášeného uživatele."""
    data = request.get_json(silent=True) or {}
    endpoint = data.get("endpoint")
    if not endpoint:
        return jsonify({"success": False, "message": "Chybí endpoint."}), 400

    ok, msg = auth.remove_push_subscription(endpoint)
    if ok:
        add_log("info", "NOTIFIKACE VYPNUTY", f"Uživatel '{session.get('username')}' deaktivoval push oznámení.")
    return jsonify({"success": ok, "message": msg}), (200 if ok else 400)


@app.route("/api/push/test", methods=["POST"])
@login_required
def push_test():
    """Testovací odeslání notifikace přihlášeným uživatelům."""
    username = session.get("username", "uživatel")
    add_log("info", "TEST NOTIFIKACE", f"Uživatel '{username}' spustil test push notifikace.")
    sent = send_push_notification("Dveře Šešule", "Někdo zvoní u dveří.", "/")
    return jsonify({
        "success": True,
        "message": f"Testovací notifikace byla odeslána (příjemců: {sent}).",
        "sent": sent
    })


# ==============================================================================
# WEBAUTHN / FIDO2 (BIOMETRICKÉ PŘIHLÁŠENÍ)
# ==============================================================================

def get_rp_id():
    if config.WEBAUTHN_RP_ID:
        return config.WEBAUTHN_RP_ID
    host = request.host.split(":")[0]
    return host


def get_origin():
    if config.WEBAUTHN_ORIGIN:
        return config.WEBAUTHN_ORIGIN
    return request.origin or f"{request.scheme}://{request.host}"


@app.route("/api/webauthn/register/options", methods=["POST"])
@login_required
def webauthn_register_options():
    """Vygeneruje registrační parametry pro WebAuthn / otisk prstu."""
    user_id = session.get("user_id")
    username = session.get("username", "user")

    existing_creds = auth.get_webauthn_credentials(user_id)
    exclude_credentials = []
    for cred in existing_creds:
        try:
            exclude_credentials.append(PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred["credential_id"])))
        except Exception:
            pass

    options = generate_registration_options(
        rp_id=get_rp_id(),
        rp_name=config.WEBAUTHN_RP_NAME,
        user_id=str(user_id).encode("utf-8"),
        user_name=username,
        user_display_name=username,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            user_verification=UserVerificationRequirement.PREFERRED,
            resident_key=ResidentKeyRequirement.PREFERRED,
        ),
        exclude_credentials=exclude_credentials if exclude_credentials else None,
    )

    session["webauthn_reg_challenge"] = base64.b64encode(options.challenge).decode("utf-8")
    return options_to_json(options), 200, {"Content-Type": "application/json"}


@app.route("/api/webauthn/register/verify", methods=["POST"])
@login_required
def webauthn_register_verify():
    """Ověří odpověď z autentizátoru a uloží otisk prstu / credential do DB."""
    user_id = session.get("user_id")
    username = session.get("username", "user")
    challenge_b64 = session.get("webauthn_reg_challenge")

    if not challenge_b64:
        return jsonify({"success": False, "message": "Chybí výzva (challenge) v relaci."}), 400

    expected_challenge = base64.b64decode(challenge_b64)
    data = request.get_json(silent=True) or {}

    try:
        verified_reg = verify_registration_response(
            credential=data,
            expected_challenge=expected_challenge,
            expected_origin=get_origin(),
            expected_rp_id=get_rp_id(),
            require_user_verification=False,
        )

        cred_id_str = bytes_to_base64url(verified_reg.credential_id)
        pub_key_str = bytes_to_base64url(verified_reg.credential_public_key)

        ok, msg = auth.save_webauthn_credential(user_id, cred_id_str, pub_key_str, verified_reg.sign_count)
        if ok:
            session.pop("webauthn_reg_challenge", None)
            add_log("info", "WEBAUTHN REGISTRACE", f"Uživatel '{username}' úspěšně zaregistroval biometrické přihlášení.")
            return jsonify({"success": True, "message": "Biometrické přihlášení bylo úspěšně aktivováno."})
        else:
            return jsonify({"success": False, "message": msg}), 400
    except Exception as e:
        logger.error(f"Chyba při ověřování WebAuthn registrace: {e}")
        return jsonify({"success": False, "message": f"Ověření selhalo: {str(e)}"}), 400


@app.route("/api/webauthn/login/options", methods=["POST"])
def webauthn_login_options():
    """Vygeneruje výzvu (challenge) pro přihlášení biometrií."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()

    allow_credentials = None
    if username:
        user = auth.get_user_by_username(username)
        if user:
            user_creds = auth.get_webauthn_credentials(user["id"])
            if user_creds:
                allow_credentials = []
                for c in user_creds:
                    try:
                        allow_credentials.append(PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credential_id"])))
                    except Exception:
                        pass

    options = generate_authentication_options(
        rp_id=get_rp_id(),
        user_verification=UserVerificationRequirement.PREFERRED,
        allow_credentials=allow_credentials,
    )

    session["webauthn_auth_challenge"] = base64.b64encode(options.challenge).decode("utf-8")
    return options_to_json(options), 200, {"Content-Type": "application/json"}


@app.route("/api/webauthn/login/verify", methods=["POST"])
def webauthn_login_verify():
    """Ověří podpis biometrií a přihlásí uživatele."""
    challenge_b64 = session.get("webauthn_auth_challenge")
    if not challenge_b64:
        return jsonify({"success": False, "message": "Chybí výzva autentizace."}), 400

    expected_challenge = base64.b64decode(challenge_b64)
    data = request.get_json(silent=True) or {}

    cred_id_str = data.get("id")
    if not cred_id_str:
        raw_id = data.get("rawId")
        if raw_id:
            cred_id_str = raw_id

    if not cred_id_str:
        return jsonify({"success": False, "message": "Chybí ID pověření."}), 400

    cred_record = auth.get_webauthn_credentials_by_credential_id(cred_id_str)
    if not cred_record:
        return jsonify({"success": False, "message": "Biometrické pověření nebylo nalezeno nebo není přiřazeno žádnému účtu."}), 401

    if cred_record.get("is_disabled"):
        username = cred_record.get("username", "")
        add_log("warning", "PŘIHLÁŠENÍ OTISKEM SELHALO", f"Pokus o přihlášení otiskem k deaktivovanému účtu '{username}'.")
        return jsonify({"success": False, "message": "Váš účet byl deaktivován. Obraťte se na správce systému."}), 401

    try:
        pub_key_bytes = base64url_to_bytes(cred_record["public_key"])
        verified_auth = verify_authentication_response(
            credential=data,
            expected_challenge=expected_challenge,
            expected_origin=get_origin(),
            expected_rp_id=get_rp_id(),
            credential_public_key=pub_key_bytes,
            credential_current_sign_count=cred_record["sign_count"],
            require_user_verification=False,
        )

        auth.update_webauthn_sign_count(cred_id_str, verified_auth.new_sign_count)
        session.clear()
        session["authenticated"] = True
        session["user_id"] = cred_record["user_id"]
        session["username"] = cred_record["username"]
        session["role"] = cred_record["role"]
        session["network_bypass"] = cred_record["network_bypass"]
        session["remember_me"] = True
        session["csrf_token"] = secrets.token_urlsafe(32)
        session["last_activity"] = datetime.utcnow().timestamp()
        session.permanent = True

        add_log("success", "PŘIHLÁŠENÍ OTISKEM", f"Uživatel '{cred_record['username']}' se úspěšně přihlásil pomocí biometrie (Platnost: 3 měsíce).")

        return jsonify({
            "success": True,
            "message": "Přihlášení otiskem prstu proběhlo úspěšně.",
            "username": cred_record["username"],
            "csrf_token": session["csrf_token"]
        })
    except Exception as e:
        logger.error(f"Chyba při ověřování biometrie: {e}")
        return jsonify({"success": False, "message": f"Ověření otisku selhalo: {str(e)}"}), 401


@app.route("/api/webauthn/credentials", methods=["DELETE"])
@login_required
def webauthn_delete_credentials():
    """Deaktivuje biometrické přihlášení pro přihlášeného uživatele."""
    user_id = session.get("user_id")
    ok, msg = auth.delete_webauthn_credentials(user_id)
    if ok:
        add_log("info", "WEBAUTHN SMAZÁNO", f"Uživatel '{session.get('username')}' deaktivoval biometrické přihlášení.")
    return jsonify({"success": ok, "message": msg}), (200 if ok else 400)


threading.Thread(
    target=_ntp_sync_worker,
    name="ntp-clock-sync",
    daemon=True,
).start()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=config.PORT, debug=False)
