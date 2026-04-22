"""
MSSQL Arsenal — i18n engine

Usage:
    from gui.i18n import _, set_lang, current_lang

    set_lang("en")          # switch language at runtime
    set_lang("zh")           # switch back to Chinese
    print(_("window_title")) # translate a string
"""

import json
import os
from typing import Dict

# ── Locate i18n directory ─────────────────────────────────────────────────────
_I18N_DIR = os.path.join(os.path.dirname(__file__), '..', 'assets', 'i18n')

SUPPORTED_LANGS = ["zh", "zh-tw", "en", "ja", "ru"]

# Language code aliases (zh-CN -> zh, zh-TW -> zh-tw, etc.)
_LANG_ALIASES = {
    "zh-CN": "zh",
    "zh-Hans": "zh",
    "zh-TW": "zh-tw",
    "zh-Hant": "zh-tw",
}

DEFAULT_LANG = "zh"

_translations: Dict[str, str] = {}
_current_lang: str = DEFAULT_LANG


def _resolve_lang(lang: str) -> str:
    """Resolve language code, handling aliases."""
    # Check aliases first
    if lang in _LANG_ALIASES:
        lang = _LANG_ALIASES[lang]
    # Validate against supported langs
    if lang not in SUPPORTED_LANGS:
        lang = DEFAULT_LANG
    return lang


def _load(lang: str) -> Dict[str, str]:
    lang = _resolve_lang(lang)
    path = os.path.join(_I18N_DIR, f"{lang}.json")
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def set_lang(lang: str) -> None:
    """Switch UI language at runtime."""
    global _translations, _current_lang
    _current_lang = _resolve_lang(lang)
    _translations = _load(_current_lang)


def current_lang() -> str:
    return _current_lang


def _(key: str, **kwargs) -> str:
    """
    Translate ``key`` using the current language.
    Supports positional interpolation:  _("err_no_target", host="1.2.3.4")
    """
    text = _translations.get(key, key)
    if kwargs:
        try:
            text = text.format(**kwargs)
        except (KeyError, ValueError):
            pass
    return text


# Load default language on import
set_lang(DEFAULT_LANG)
