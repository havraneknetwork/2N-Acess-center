"""
==============================================================================
2N DOOR UNLOCKER — KONFIGURACE OPRÁVNĚNÍ, ROLÍ A BEZPEČNOSTNÍCH LIMITŮ
==============================================================================

Tento soubor obsahuje veškerá pravidla, výchozí hodnoty a limity pro uživatelská
oprávnění, včetně nastavení toho, co mohou jednotlivé role či uživatelé měnit
jiným uživatelům, a viditelnosti položek v bočním menu.
Můžete jej jednoduše upravit přepsáním hodnot níže podle svých potřeb.
Po úpravě stačí restartovat kontejner (nebo aplikaci).
"""

from datetime import datetime
import json
from typing import Any

# ==============================================================================
# 1. DOSTUPNÉ ROLE V SYSTÉMU
# ==============================================================================
# Seznam platných rolí
ROLES = ("admin", "správce", "user")

# Textové popisky a názvy rolí pro rozhraní
ROLE_LABELS = {
    "admin": "Administrátor (plná práva)",
    "správce": "Správce (správa běžných uživatelů, logy, trvalé odemčení)",
    "user": "Uživatel (běžný přístup k odemykání)",
}

# Hierarchie správy: jaké role může daná role vytvářet a upravovat
# Klíč: role přihlášeného uživatele -> Hodnota: seznam rolí, které smí spravovat
CAN_MANAGE_ROLES = {
    "admin": ["admin", "správce", "user"],
    "správce": [],
    "user": [],
}


# ==============================================================================
# 2. POLOŽKY BOČNÍHO MENU (SIDEBAR)
# ==============================================================================
# Seznam všech možností v bočním menu, které lze uživatelům povolit či zakázat.
SIDEBAR_MENU_ITEMS: dict[str, dict[str, Any]] = {
    "home": {
        "id": "home",
        "label": "Home",
        "description": "Hlavní obrazovka a odemykání dveří",
        "icon": "home",
        "default_roles": ["admin", "správce", "user"],
    },
    "logs": {
        "id": "logs",
        "label": "Log",
        "description": "Historie záznamů a auditní log",
        "icon": "file-text",
        "default_roles": ["admin", "správce"],
    },
    "info": {
        "id": "info",
        "label": "Informace",
        "description": "Stav 2N jednotky a systémové informace",
        "icon": "info",
        "default_roles": ["admin", "správce"],
    },
    "users": {
        "id": "users",
        "label": "Správa uživatelů",
        "description": "Správa účtů, oprávnění a přístupů",
        "icon": "users",
        "default_roles": ["admin"],
    },
    "keys": {
        "id": "keys",
        "label": "Bezpečnostní klíče",
        "description": "Registrace a správa čipových karet",
        "icon": "key",
        "default_roles": ["admin", "správce"],
    },
    "permanent": {
        "id": "permanent",
        "label": "Trvalé odemčení",
        "description": "Trvalé odemčení zámku a jeho sledování",
        "icon": "lock-open",
        "default_roles": ["admin", "správce"],
    },
    "schedule": {
        "id": "schedule",
        "label": "Rozvrh",
        "description": "Harmonogram a časová pravidla přístupu",
        "icon": "calendar",
        "default_roles": ["admin", "správce"],
    },
}

ALL_SIDEBAR_KEYS = tuple(SIDEBAR_MENU_ITEMS.keys())


# ==============================================================================
# 3. VÝCHOZÍ OPRÁVNĚNÍ PŘI VYTVOŘENÍ NOVÉHO UŽIVATELE PODLE ROLE
# ==============================================================================
# Zde si můžete nastavit, co přesně má nový uživatel povoleno ihned po vytvoření,
# včetně výchozích viditelných položek v bočním menu a správy uživatelů.
DEFAULT_ROLE_PERMISSIONS: dict[str, dict[str, Any]] = {
    # Administrátor: plná práva včetně bypassu a neomezeného trvalého odemčení
    "admin": {
        "can_unlock": True,                      # Povoleno odemykat dveře
        "network_bypass": True,                  # Povoleno odemykat i mimo Wi-Fi / LAN Šešule
        "permanent_unlock_allowed": True,        # Povoleno trvalé zablokování zámku
        "permanent_unlock_max_duration": 1440,   # Max. doba trvalého odemčení v minutách (1440 = 24 h)
        "time_restricted": False,                # Řízeno rozvrhem v user_schedule
        "user_note": "Systémový administrátor",
        "sidebar_menu": ["home", "logs", "info", "users", "keys", "permanent", "schedule"],
        "can_manage_users": True,                # Povolena správa uživatelů
    },

    # Správce: provozní správa, možnost trvalého odemčení s limitem
    "správce": {
        "can_unlock": True,
        "network_bypass": False,                 # Vyžaduje být na síti Šešule (lze povolit v modalu)
        "permanent_unlock_allowed": True,
        "permanent_unlock_max_duration": 240,    # Max. 4 hodiny (240 min)
        "time_restricted": False,
        "user_note": "",
        "sidebar_menu": ["home", "logs", "info", "keys", "permanent", "schedule"],
        "can_manage_users": False,
    },

    # Běžný uživatel: pouze okamžité odemčení dveří a domovská obrazovka
    "user": {
        "can_unlock": True,
        "network_bypass": False,
        "permanent_unlock_allowed": False,       # Trvalé odemčení ve výchozím stavu zakázáno
        "permanent_unlock_max_duration": 60,     # Max. 60 minut (pokud je mu trvalé odemčení povoleno)
        "time_restricted": False,
        "user_note": "",
        "sidebar_menu": ["home"],
        "can_manage_users": False,
    },
}


# ==============================================================================
# 4. NASTAVENÍ TOHO, CO MŮŽE JAKÁ ROLE MĚNIT JINÝM UŽIVATELŮM
# ==============================================================================
# Tato matice určuje, jaké konkrétní položky a oprávnění smí daná role měnit
# u cílových uživatelů, které má právo spravovat (podle CAN_MANAGE_ROLES).
# Zde si můžete přesně nakonfigurovat práva pro správce i další role.
ROLE_CAN_EDIT_PERMISSIONS: dict[str, dict[str, bool]] = {
    # Administrátor: může měnit všechna nastavení jiným uživatelům
    "admin": {
        "can_manage_users": True,              # Přístup do správy uživatelů
        "can_create_users": True,              # Vytváření nových účtů
        "can_delete_users": True,              # Mazání uživatelů
        "can_change_role": True,               # Změna role uživatele
        "can_edit_network_bypass": True,       # Zapnutí/vypnutí network bypassu
        "can_edit_unlock_permission": True,    # Povolení/zákaz odemykání
        "can_edit_permanent_unlock": True,     # Nastavení trvalého odemčení a limitu
        "can_edit_time_restrictions": True,    # Nastavení časového rozvrhu a dnů
        "can_edit_sidebar_menu": True,         # Nastavení položek v bočním menu
        "can_edit_user_note": True,            # Úprava interní poznámky
        "can_toggle_account_disabled": True,   # Deaktivace a aktivace účtu
        "can_reset_password": True,            # Vynucení změny hesla
        "can_unlock_account": True,            # Odemknutí dočasně zablokovaného účtu
        "can_edit_management_rights": True,    # Nastavení oprávnění ke správě jiných uživatelů
    },

    # Správce: provozní správa (správa uživatelů je vyhrazena pouze pro admina)
    "správce": {
        "can_manage_users": True,             # Pouze administrátor smí spravovat uživatele
        "can_create_users": True,
        "can_delete_users": True,
        "can_change_role": False,
        "can_edit_network_bypass": False,
        "can_edit_unlock_permission": True,
        "can_edit_permanent_unlock": True,
        "can_edit_time_restrictions": True,
        "can_edit_sidebar_menu": True,
        "can_edit_user_note": True,
        "can_toggle_account_disabled": True,
        "can_reset_password": False,
        "can_unlock_account": False,
        "can_edit_management_rights": False,
    },

    # Běžný uživatel: nemá žádná práva správy jiných uživatelů
    "user": {
        "can_manage_users": False,
        "can_create_users": False,
        "can_delete_users": False,
        "can_change_role": False,
        "can_edit_network_bypass": False,
        "can_edit_unlock_permission": False,
        "can_edit_permanent_unlock": False,
        "can_edit_time_restrictions": False,
        "can_edit_sidebar_menu": False,
        "can_edit_user_note": False,
        "can_toggle_account_disabled": False,
        "can_reset_password": False,
        "can_unlock_account": False,
        "can_edit_management_rights": False,
    },
}


# ==============================================================================
# 5. PRAVIDLA A LIMITY TRVALÉHO ODEMČENÍ DVEŘÍ
# ==============================================================================
PERMANENT_UNLOCK_CONFIG = {
    # Výchozí nabízená doba při otevření dialogu (v minutách)
    "default_duration_minutes": 60,

    # Minimální povolená doba (v minutách)
    "min_duration_minutes": 1,

    # Maximální absolutní strop pro administrátora (1440 minut = 24 hodin)
    "max_duration_admin": 1440,

    # Maximální strop, který může nastavit správce (není-li admin)
    "max_duration_spravce": 240,

    # Maximální strop pro běžného uživatele
    "max_duration_user": 120,

    # Rychlé předvolby pro UI (v minutách)
    "quick_presets_minutes": [15, 30, 60, 120, 240, 480, 1440],
}


# ==============================================================================
# 6. ČASOVÁ OMEZENÍ PŘÍSTUPU (ROZVRH)
# ==============================================================================
TIME_RESTRICTION_CONFIG = {
    # Výchozí časový interval při aktivaci omezení
    "default_time_from": "06:00",
    "default_time_to": "22:00",

    # Podporované dny v týdnu
    "allowed_days_modes": {
        "all": "Každý den (včetně víkendů)",
        "weekdays": "Pouze všední dny (Pondělí až Pátek)",
        "weekend": "Pouze víkendy (Sobota a Neděle)",
    },
}


# ==============================================================================
# 7. BEZPEČNOSTNÍ POLITIKY & OCHRANA ÚČTŮ
# ==============================================================================
SECURITY_POLICIES = {
    # Chráněná uživatelská jména (nelze je smazat, deaktivovat ani jim odebrat admin roli)
    "protected_usernames": ["admin"],

    # Minimální délka hesla
    "min_password_length": 8,

    # Počet neúspěšných pokusů o přihlášení před dočasným uzamčením účtu
    "max_failed_login_attempts": 5,

    # Doba uzamčení účtu po překročení pokusů (v minutách)
    "lockout_duration_minutes": 15,

    # Zda může běžný správce (ne-admin) měnit hesla jiným uživatelům
    "spravce_can_reset_user_passwords": True,

    # Zda může běžný správce (ne-admin) mazat běžné uživatele
    "spravce_can_delete_users": True,
}


# ==============================================================================
# 8. POMOCNÉ FUNKCE PRO VALIDACI A APLIKACI PRAVIDEL
# ==============================================================================

def get_default_permissions_for_role(role: str) -> dict[str, Any]:
    """Vrátí kopii výchozích oprávnění pro danou roli."""
    role_clean = str(role or "user").strip().lower()
    defaults = DEFAULT_ROLE_PERMISSIONS.get(role_clean, DEFAULT_ROLE_PERMISSIONS["user"])
    res = dict(defaults)
    # Hluboká kopie seznamu položek bočního menu
    if "sidebar_menu" in res:
        res["sidebar_menu"] = list(res["sidebar_menu"])
    return res


def get_default_sidebar_menu_for_role(role: str) -> list[str]:
    """Vrátí výchozí seznam povolených položek v bočním menu pro roli."""
    role_clean = str(role or "user").strip().lower()
    defaults = DEFAULT_ROLE_PERMISSIONS.get(role_clean, DEFAULT_ROLE_PERMISSIONS["user"])
    return list(defaults.get("sidebar_menu", ["home"]))


def sanitize_sidebar_menu(menu_items: Any) -> list[str]:
    """
    Ověří a vyčistí seznam položek bočního menu.
    Zajišťuje, že položka 'home' je vždy přítomna a jsou povoleny pouze platné klíče.
    """
    if isinstance(menu_items, str):
        try:
            parsed = json.loads(menu_items)
            if isinstance(parsed, list):
                menu_items = parsed
            else:
                menu_items = [s.strip() for s in menu_items.split(",") if s.strip()]
        except Exception:
            menu_items = [s.strip() for s in menu_items.split(",") if s.strip()]

    if not isinstance(menu_items, (list, tuple, set)):
        menu_items = ["home"]

    valid_keys = set(ALL_SIDEBAR_KEYS)
    cleaned = [str(item).strip().lower() for item in menu_items if str(item).strip().lower() in valid_keys]

    # 'home' je základní obrazovka a musí být vždy přítomna
    if "home" not in cleaned:
        cleaned.insert(0, "home")

    # Zachovat pořadí podle ALL_SIDEBAR_KEYS
    ordered = [k for k in ALL_SIDEBAR_KEYS if k in cleaned]
    return ordered


def can_user_manage_users(caller_role: str, caller_user: dict | None = None) -> bool:
    """Zjistí, zda má daná role nebo konkrétní uživatel oprávnění ke správě uživatelů."""
    role_clean = str(caller_role or "user").strip().lower()

    # Uživatelské přepsání v DB (pokud existuje)
    if caller_user and caller_user.get("can_manage_users") is not None:
        return bool(caller_user["can_manage_users"])

    role_perms = ROLE_CAN_EDIT_PERMISSIONS.get(role_clean, ROLE_CAN_EDIT_PERMISSIONS["user"])
    return bool(role_perms.get("can_manage_users", False))


def get_caller_management_permissions(caller_role: str, caller_user: dict | None = None) -> dict[str, bool]:
    """Vrátí slovník oprávnění toho, co smí volající měnit jiným uživatelům."""
    role_clean = str(caller_role or "user").strip().lower()
    base_perms = dict(ROLE_CAN_EDIT_PERMISSIONS.get(role_clean, ROLE_CAN_EDIT_PERMISSIONS["user"]))

    # Pokud má uživatel v DB vlastní přepsání specifických oprávnění (uložené v JSON)
    if caller_user and caller_user.get("user_management_permissions"):
        try:
            custom_perms = caller_user["user_management_permissions"]
            if isinstance(custom_perms, str):
                custom_perms = json.loads(custom_perms)
            if isinstance(custom_perms, dict):
                base_perms.update({k: bool(v) for k, v in custom_perms.items() if k in base_perms})
        except Exception:
            pass

    # Pokud má uživatel can_manage_users explicitně vypnuto, zneplatnit vše
    if caller_user and caller_user.get("can_manage_users") is False:
        for k in base_perms:
            base_perms[k] = False

    return base_perms


def clamp_permanent_unlock_duration(duration_minutes: int, user_role: str = "user") -> int:
    """Omezí zadanou dobu trvalého odemčení do povolených mezí podle role."""
    cfg = PERMANENT_UNLOCK_CONFIG
    min_dur = cfg["min_duration_minutes"]

    role_clean = str(user_role or "user").strip().lower()
    if role_clean == "admin":
        max_dur = cfg["max_duration_admin"]
    elif role_clean == "správce":
        max_dur = cfg["max_duration_spravce"]
    else:
        max_dur = cfg["max_duration_user"]

    try:
        val = int(duration_minutes)
    except (ValueError, TypeError):
        val = cfg["default_duration_minutes"]

    return max(min_dur, min(val, max_dur))


def is_user_protected(username: str) -> bool:
    """Zjistí, zda je uživatel chráněný před smazáním/deaktivací."""
    if not username:
        return False
    u = username.strip().lower()
    return u in [p.lower() for p in SECURITY_POLICIES["protected_usernames"]]


def can_caller_manage_target(caller_role: str, caller_id: int, target_user: dict, caller_user: dict | None = None) -> tuple[bool, str]:
    """
    Ověří, zda má volající právo spravovat cílového uživatele.
    Vrací (povoleno: bool, chybová_zpráva: str).
    """
    if not target_user:
        return False, "Cílový uživatel nebyl nalezen."

    caller_r = str(caller_role or "").strip().lower()
    target_username = target_user.get("username", "")
    target_role = target_user.get("role", "user").strip().lower()
    target_id = target_user.get("id")

    # Kontrola obecného práva spravovat uživatele
    if not can_user_manage_users(caller_r, caller_user):
        return False, "Nemáte oprávnění ke správě uživatelů."

    # Pouze administrátor smí spravovat uživatele (včetně sebe sama)
    if caller_r == "admin":
        return True, ""

    # Nikdo jiný kromě administrátora nemá oprávnění ke správě uživatelů
    return False, "Pouze administrátor má oprávnění spravovat uživatele."


def can_caller_edit_field(caller_role: str, caller_id: int, target_user: dict, field_key: str, caller_user: dict | None = None) -> tuple[bool, str]:
    """
    Ověří, zda má volající právo měnit konkrétní parametr/položku u cílového uživatele.
    Vrací (povoleno: bool, chybová_zpráva: str).
    """
    # 1. Základní kontrola, zda smí spravovat cílového uživatele jako celek
    can_manage, err_manage = can_caller_manage_target(caller_role, caller_id, target_user, caller_user)
    if not can_manage:
        return False, err_manage

    # Hlavní admin má neomezené právo ke všem povoleným cílům
    if str(caller_role).strip().lower() == "admin":
        return True, ""

    # 2. Zjištění efektivních oprávnění volajícího k editaci
    eff_perms = get_caller_management_permissions(caller_role, caller_user)
    if not eff_perms.get(field_key, False):
        labels = {
            "can_manage_users": "správa uživatelů",
            "can_create_users": "vytváření uživatelů",
            "can_delete_users": "mazání uživatelů",
            "can_change_role": "změna role uživatele",
            "can_edit_network_bypass": "nastavení síťového bypassu",
            "can_edit_unlock_permission": "nastavení povolení k odemykání",
            "can_edit_permanent_unlock": "nastavení trvalého odemčení",
            "can_edit_time_restrictions": "nastavení časového rozvrhu",
            "can_edit_sidebar_menu": "nastavení položek bočního menu",
            "can_edit_user_note": "úprava poznámky k účtu",
            "can_toggle_account_disabled": "pozastavení či aktivace účtu",
            "can_reset_password": "reset hesla uživatele",
            "can_unlock_account": "odemknutí zablokovaného účtu",
            "can_edit_management_rights": "nastavení práv správy uživatelů",
        }
        item_name = labels.get(field_key, field_key)
        return False, f"Vaše role '{caller_role}' nemá oprávnění pro akci: {item_name}."

    return True, ""


def check_time_restriction(user: dict, now_dt: datetime = None) -> tuple[bool, str]:
    """
    Zkontroluje, zda má uživatel v daný moment povolen přístup podle časového rozvrhu.
    Vrací (povoleno: bool, důvod_zamítnutí: str).
    Řízení přístupu probíhá výhradně přes tabulku user_schedule (rozvrh).
    """
    if not user:
        return True, ""

    try:
        import auth
        user_id = user.get("id")
        if user_id:
            return auth.check_user_schedule(user_id, now_dt)
    except Exception:
        pass

    return True, ""
