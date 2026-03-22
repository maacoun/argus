"""
Network Traffic Watchdog — i18n helper

Set LANGUAGE in config.py ("cs" or "en") to choose the UI language.
Each language is a strings/<lang>.py file containing a STRINGS dict.
"""
import importlib
import logging

logger = logging.getLogger("watchdog.i18n")

_strings: dict[str, str] = {}


def _load(lang: str) -> None:
    global _strings
    try:
        _strings = importlib.import_module(f"strings.{lang}").STRINGS
        logger.debug("Language loaded: %s (%d keys)", lang, len(_strings))
    except ImportError:
        logger.warning("Language '%s' not found — falling back to 'en'", lang)
        _strings = importlib.import_module("strings.en").STRINGS


def t(key: str, **kwargs) -> str:
    """Return translation for *key*, substituting *kwargs* placeholders.
    Falls back to the key itself when the translation is missing."""
    s = _strings.get(key, key)
    return s.format(**kwargs) if kwargs else s


def maybe(key: str, **kwargs) -> "str | None":
    """Like t() but returns None when *key* is absent from the catalogue."""
    s = _strings.get(key)
    if s is None:
        return None
    return s.format(**kwargs) if kwargs else s


# Load on import
import config as _cfg
_load(_cfg.LANGUAGE)
