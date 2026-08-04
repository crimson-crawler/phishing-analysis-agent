"""Defang IOC values so reports are safe to paste anywhere.

Conventions: hxxp(s):// for schemes, [.] for dots, [@] for at-signs.
Hashes need no defanging. We only defang for output — pipeline internals
always carry the real ("fanged") value.
"""

from __future__ import annotations

import re

import tldextract

# Offline PSL snapshot (no network at import) — used to tell a real bare domain
# ("evil.com") from a dotted non-domain token ("Node.js", "v2.0", "e.g").
_TLDX = tldextract.TLDExtract(suffix_list_urls=())

_EMAILISH_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_URLISH_RE = re.compile(r"(?:https?://|www\.)\S+", re.I)
# C0/C1 controls (except \t \n) plus bidi overrides: rich's Text() neutralizes
# markup but passes ESC and RTLO through, letting email content forge or
# visually rewrite terminal output.
_CONTROL_RE = re.compile("[\\x00-\\x08\\x0b-\\x1f\\x7f-\\x9f\\u202a-\\u202e\\u2066-\\u2069]")


def strip_controls(text: str) -> str:
    """Remove control and bidi-override characters from attacker-controlled
    text before it reaches a terminal (or any other output)."""
    return _CONTROL_RE.sub("", text)


# Inverse of the conventions above, plus the variants other tools emit: (.) {.}
# [dot] for dots, [:] for the scheme colon, [@] (at) for at-signs. Ordered so
# the scheme is restored before the separators it contains.
_REFANG_SCHEME_RE = re.compile(r"\bh(?:xx|XX)p(s?)\b", re.I)
_REFANG_COLON_RE = re.compile(r"\[:\]|\(:\)")
_REFANG_SLASH_RE = re.compile(r"\[/\]")
_REFANG_DOT_RE = re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)", re.I)
_REFANG_AT_RE = re.compile(r"\[@\]|\(@\)|\[at\]|\(at\)", re.I)


def refang(text: str) -> str:
    """Undo defanging so a link pasted in defanged form is still analyzed.

    Inverse of `defang`/`defang_text` for this tool's own conventions and the
    common third-party ones. Extraction-time only: the *stored* indicator is
    always the real (fanged) value, and output is re-defanged by `defang`."""
    text = _REFANG_SCHEME_RE.sub(r"http\1", text)
    text = _REFANG_COLON_RE.sub(":", text)
    text = _REFANG_SLASH_RE.sub("/", text)
    text = _REFANG_DOT_RE.sub(".", text)
    return _REFANG_AT_RE.sub("@", text)


def defang(value: str, ioc_type: str) -> str:
    if ioc_type in ("md5", "sha1", "sha256"):
        return value
    if ioc_type == "email":
        return value.replace("@", "[@]").replace(".", "[.]")
    if ioc_type == "url":
        out = value
        if out.lower().startswith("https://"):
            out = "hxxps://" + out[8:]
        elif out.lower().startswith("http://"):
            out = "hxxp://" + out[7:]
        return out.replace(".", "[.]")
    # domain / hostname / ip
    return value.replace(".", "[.]")


_IPISH_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
# A dotted token not already inside a URL/email/IP (those run first and leave no
# literal dots behind). Ends in ≥2 letters so IPs and version strings are skipped.
_DOMAINISH_RE = re.compile(r"(?<![\w@./-])(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?![\w-])")


def _defang_domain_token(match: re.Match) -> str:
    token = match.group(0)
    # Only defang when the tail is a real public suffix; leaves "Node.js",
    # "e.g", "v2.0" (no PSL suffix) as ordinary prose.
    if _TLDX(token).suffix:
        return token.replace(".", "[.]")
    return token


def defang_text(text: str) -> str:
    """Defang URL-, email-, IP-, and bare-domain-shaped substrings inside
    attacker-controlled free text (display names, anchor text, CC-echoed feed
    names and AI summaries) without mangling ordinary prose."""
    text = _URLISH_RE.sub(lambda m: defang(m.group(0), "url"), text)
    text = _EMAILISH_RE.sub(lambda m: defang(m.group(0), "email"), text)
    text = _IPISH_RE.sub(lambda m: defang(m.group(0), "ip"), text)
    return _DOMAINISH_RE.sub(_defang_domain_token, text)
