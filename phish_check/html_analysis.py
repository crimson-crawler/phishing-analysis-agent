"""HTML body analysis: links, forms, visible vs hidden text, zero-width chars.

Uses a real parser (BeautifulSoup) — regex over HTML misses href/src/action
context and can't tell visible from hidden text.
"""

from __future__ import annotations

import re

from bs4 import BeautifulSoup, Tag

from .models import HtmlAnalysis, Link

ZERO_WIDTH = ("​", "‌", "‍", "⁠", "﻿")
# Zero-width chars only count as evasion when adjacent to a word character
# ("ver​ify", "evil​.com") — a bare presence check false-positives on every
# compound-emoji ZWJ sequence (👩‍💻, whose neighbours are symbols, not \w)
# in ordinary marketing mail.
_ZW_IN_WORD_RE = re.compile(
    "\\w[\\u200b\\u200c\\u200d\\u2060\\ufeff]|[\\u200b\\u200c\\u200d\\u2060\\ufeff]\\w"
)

_HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|"
    r"mso-hide\s*:\s*all|opacity\s*:\s*0(?:\.0+)?(?:\s*;|\s*$)",
    re.I,
)
_FONT_SIZE_RE = re.compile(r"font-size\s*:\s*(\d+(?:\.\d+)?)\s*(px|pt|em|rem|%)?", re.I)
# Below these sizes text is unreadable — hiding, not fine print. Newsletter
# fine print (0.8em, 11px, 80%) must stay visible; attacker near-zero sizes
# (0, 0.5px, 0.1em) must stay hidden.
_TINY_FONT_LIMITS = {"px": 2.0, "pt": 1.5, "em": 0.15, "rem": 0.15, "%": 15.0}


def _is_tiny_font(style: str) -> bool:
    for num, unit in _FONT_SIZE_RE.findall(style):
        size = float(num)
        if unit:
            if size < _TINY_FONT_LIMITS.get(unit.lower(), 0):
                return True
        elif size == 0:  # unitless is only valid CSS as exactly 0
            return True
    return False


_OFFSCREEN_RE = re.compile(r"(?:left|top)\s*:\s*-\d{3,}", re.I)
_META_REFRESH_URL_RE = re.compile(r"url\s*=\s*['\"]?([^'\">;\s]+)", re.I)


def _is_hidden(tag: Tag) -> bool:
    style = tag.get("style") or ""
    if isinstance(style, list):
        style = ";".join(style)
    return (
        bool(_HIDDEN_STYLE_RE.search(style) or _OFFSCREEN_RE.search(style))
        or _is_tiny_font(style)
        or tag.get("hidden") is not None
    )


def analyze_html(html: str) -> HtmlAnalysis:
    result = HtmlAnalysis()
    soup = BeautifulSoup(html, "html.parser")

    result.has_zero_width_chars = bool(_ZW_IN_WORD_RE.search(html))

    for meta in soup.find_all("meta"):
        if str(meta.get("http-equiv", "")).lower() == "refresh":
            m = _META_REFRESH_URL_RE.search(str(meta.get("content", "")))
            if m:
                result.links.append(Link(href=m.group(1), text="", source="meta-refresh"))

    for form in soup.find_all("form"):
        action = str(form.get("action") or "").strip()
        if action:
            result.form_actions.append(action)
            result.links.append(Link(href=action, text="", source="form-action"))

    for a in soup.find_all("a"):
        href = str(a.get("href") or "").strip()
        if href:
            result.links.append(Link(href=href, text=a.get_text(" ", strip=True), source="href"))

    for tag in soup.find_all(("img", "script", "iframe")):
        src = str(tag.get("src") or "").strip()
        if src and not src.startswith("data:"):
            # iframes get their own source tag: they deliver payloads, unlike
            # img/script decoration, so extract.py must not rank them as noise.
            source = "iframe-src" if tag.name == "iframe" else "src"
            result.links.append(Link(href=src, text="", source=source))

    # Split hidden subtrees out, then read visible text from what remains.
    for tag in soup.find_all(_is_hidden):
        hidden = tag.get_text(" ", strip=True)
        if hidden:
            result.hidden_texts.append(hidden)
        tag.decompose()
    for invisible in soup.find_all(("style", "script", "head", "title")):
        invisible.decompose()

    text = soup.get_text("\n", strip=True)
    for zw in ZERO_WIDTH:
        text = text.replace(zw, "")
    result.visible_text = re.sub(r"\n{3,}", "\n\n", text)
    return result
