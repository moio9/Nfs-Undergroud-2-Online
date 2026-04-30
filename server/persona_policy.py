"""
Persona policy helpers.

The public config keys are PERSONA_*; legacy config names are translated by
the config loader before these helpers read values.
"""

import os
from typing import Callable


WarnFunc = Callable[..., None]

CPER_REASONS = frozenset(("dupl", "invp", "nspc"))
PERS_REASONS = frozenset(("invp", "maut", "pset"))
SUPPORTED_CODES_TEXT = "cperdupl cperinvp cpernspc persinvp persmaut perspset"

_REASON_ALIASES = {
    "dupl": "dupl",
    "duplicate": "dupl",
    "already_exists": "dupl",
    "in_use": "dupl",
    "invp": "invp",
    "invalid": "invp",
    "invalid_persona": "invp",
    "nspc": "nspc",
    "no_space": "nspc",
    "slots_full": "nspc",
    "maut": "maut",
    "must_auth": "maut",
    "not_authenticated": "maut",
    "pset": "pset",
    "persona_set": "pset",
    "already_set": "pset",
}

_REASON_TEXT = {
    "dupl": "Persona is already in use.",
    "invp": "Persona is invalid.",
    "nspc": "No persona slots are available.",
    "maut": "Persona selection requires authentication.",
    "pset": "Persona is already set.",
}


def normalize_key(value: object) -> str:
    return str(value or "").strip().lower()


def supported_codes_text() -> str:
    return SUPPORTED_CODES_TEXT


def parse_code(value: object) -> tuple[str, str]:
    text = str(value or "").strip().lower()
    text = text.replace("-", "_").replace(" ", "_")
    cmd = ""
    if len(text) == 8 and text[:4] in ("cper", "pers"):
        cmd = text[:4]
        text = text[4:]
    reason = _REASON_ALIASES.get(text, "")
    if not reason:
        return "", ""
    if not cmd:
        cmd = "cper" if reason in ("dupl", "nspc") else "pers"
    if cmd == "cper" and reason not in CPER_REASONS:
        return "", ""
    if cmd == "pers" and reason not in PERS_REASONS:
        return "", ""
    return cmd, reason


def canonical_reason(value: object) -> str:
    _, reason = parse_code(value)
    return reason


def reason_text(value: object) -> str:
    return _REASON_TEXT.get(canonical_reason(value), "Persona request rejected.")


def split_list(raw: object) -> list[str]:
    text = str(raw or "")
    if not text.strip():
        return []
    for sep in ("\r", "\n", ";"):
        text = text.replace(sep, ",")
    return [item.strip() for item in text.split(",") if item.strip()]


def blacklist_file_path(config_path: str, configured_path: object) -> str:
    path = str(configured_path or "").strip()
    if not path:
        return ""
    if os.path.isabs(path):
        return path
    return os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(config_path)), path))


def _cfg_get(cfg: object, key: str, default: object = "") -> object:
    getter = getattr(cfg, "get", None)
    if callable(getter):
        return getter(key, default)
    try:
        return cfg[key]  # type: ignore[index]
    except Exception:
        return default


def blacklist_terms(cfg: object, config_path: str, warn: WarnFunc | None = None) -> tuple[set[str], set[str]]:
    exact = {
        normalize_key(item)
        for item in split_list(_cfg_get(cfg, "PERSONA_RESERVED_NAMES", ""))
    }
    contains = {
        normalize_key(item)
        for item in split_list(_cfg_get(cfg, "PERSONA_FORBIDDEN_WORDS", ""))
    }
    path = blacklist_file_path(
        config_path,
        _cfg_get(cfg, "PERSONA_BLACKLIST_FILE", ""),
    )
    if path:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    prefix, sep, value = line.partition(":")
                    if sep and prefix.strip().lower() in ("contains", "word", "substring"):
                        term = normalize_key(value)
                        if term:
                            contains.add(term)
                        continue
                    if sep and prefix.strip().lower() in ("exact", "name", "reserved"):
                        term = normalize_key(value)
                        if term:
                            exact.add(term)
                        continue
                    term = normalize_key(line)
                    if term:
                        exact.add(term)
        except FileNotFoundError:
            if warn:
                warn("Persona blacklist file missing: %s", path)
        except OSError as exc:
            if warn:
                warn("Persona blacklist file unreadable: %s: %s", path, exc)
    exact.discard("")
    contains.discard("")
    return exact, contains


def blacklist_code(cfg: object, stage: object) -> str:
    stage_text = str(stage or "").strip().lower()
    stage_key = "PERSONA_BLACKLIST_CPER_CODE" if stage_text == "cper" else "PERSONA_BLACKLIST_PERS_CODE"
    raw = str(_cfg_get(cfg, stage_key, "") or "").strip()
    if not raw:
        raw = str(_cfg_get(cfg, "PERSONA_BLACKLIST_CODE", "invp") or "invp").strip()
    _, reason = parse_code(raw)
    if stage_text == "cper" and reason in CPER_REASONS:
        return reason
    if stage_text == "pers" and reason in PERS_REASONS:
        return reason
    return "invp"


def find_blacklist_match(persona_key: str, exact: set[str], contains: set[str]) -> tuple[str, str]:
    if persona_key in exact:
        return "exact", persona_key
    for term in sorted(contains, key=len, reverse=True):
        if term and term in persona_key:
            return "contains", term
    return "", ""


def blacklist_reject(
    cfg: object,
    config_path: str,
    persona: object,
    stage: object,
    warn: WarnFunc | None = None,
) -> tuple[str, str, str]:
    persona_key = normalize_key(persona)
    if not persona_key:
        return "", "", ""
    exact, contains = blacklist_terms(cfg, config_path, warn=warn)
    match_type, match_value = find_blacklist_match(persona_key, exact, contains)
    if not match_type:
        return "", "", ""
    return blacklist_code(cfg, stage), match_type, match_value
