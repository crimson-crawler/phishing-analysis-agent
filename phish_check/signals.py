"""Stage 3: deterministic checks over the parsed email -> Evidence list.

Everything here is parser work: no network, no LLM. Social-engineering
judgment (tone, lure plausibility) is deliberately left to the judge stage.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .defang import defang, strip_controls
from .extract import _clean_url, has_public_suffix, numeric_ip_host, registered_domain
from .models import Evidence, Indicator, ParsedEmail
from .unwrap import is_known_gateway, is_undecodable_rewrapper, unwrap_gateways

FREEMAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "yahoo.com",
    "aol.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
    "gmx.com",
    "gmx.net",
    "mail.com",
    "mail.ru",
    "yandex.com",
    "yandex.ru",
    "zoho.com",
    "qq.com",
    "163.com",
    # freemail ccTLD / regional variants and common webmail aliases — a
    # Reply-To on any of these against a corporate From is the same BEC signal.
    "ymail.com",
    "rocketmail.com",
    "msn.com",
    "me.com",
    "mac.com",
    "pm.me",
    "yahoo.co.uk",
    "yahoo.co.jp",
    "yahoo.co.in",
    "yahoo.com.au",
    "yahoo.ca",
    "yahoo.fr",
    "yahoo.de",
    "yahoo.es",
    "yahoo.it",
    "hotmail.co.uk",
    "hotmail.fr",
    "hotmail.de",
    "hotmail.it",
    "hotmail.es",
    "live.co.uk",
    "outlook.de",
    "outlook.fr",
    "outlook.es",
    "gmx.de",
    "gmx.at",
    "gmx.ch",
    "web.de",
    "t-online.de",
    "freenet.de",
}

URL_SHORTENERS = {
    "bit.ly",
    "t.co",
    "tinyurl.com",
    "goo.gl",
    "is.gd",
    "buff.ly",
    "ow.ly",
    "rebrand.ly",
    "cutt.ly",
    "t.ly",
    "rb.gy",
    "shorturl.at",
    "tiny.cc",
}

# Attachment extension tiers.
EXT_HIGH = {
    ".exe",
    ".scr",
    ".pif",
    ".cpl",
    ".msi",
    ".bat",
    ".cmd",
    ".com",
    ".js",
    ".jse",
    ".vbs",
    ".vbe",
    ".wsf",
    ".hta",
    ".ps1",
    ".lnk",
    ".jar",
}
EXT_MEDIUM = {
    ".docm",
    ".xlsm",
    ".pptm",
    ".xlam",
    ".doc",
    ".xls",
    ".ppt",
    ".iso",
    ".img",
    ".vhd",
    ".vhdx",
    ".udf",
    ".zip",
    ".rar",
    ".7z",
    ".gz",
    ".tar",
    ".ace",
}
EXT_WATCH = {".html", ".htm", ".shtml", ".svg", ".one", ".eml", ".msg", ".ics", ".pdf"}

# Document/image extensions used as the fake "inner" extension of a double-
# extension lure (invoice.pdf.exe). Deliberately excludes archive suffixes so
# legitimate compound names (release.tar.gz) don't fire.
DECOY_EXTS = {
    ".pdf",
    ".txt",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".html",
    ".htm",
}

# Evidence descriptions are the judge's trusted zone, so any attacker-derived
# value quoted into one is kept shape-bounded (no spaces: a host, an address or
# a digest, never prose) *and* length-bounded. 120 chars keeps every realistic
# hostname and address intact.
MAX_TRUSTED_VALUE_CHARS = 120

_EMAIL_IN_DISPLAY_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_AI_INSTRUCTION_RE = re.compile(
    r"ignore (all|any|previous|above)|classify this (e-?mail|message)|"
    r"(mark|treat|flag) (this|it|the (e-?mail|message)) as (safe|legitimate|benign|not)|"
    r"\b(ai|llm|language model|assistant|classifier)\b.{0,40}\b(instruction|must|should|do not)",
    re.I,
)
_URL_SHAPED_RE = re.compile(r"(?:https?://)?(?:www\.)?[\w-]+(?:\.[\w-]+)+(?:/\S*)?", re.I)
_RTLO = "‮"


def _is_ip_host(host: str) -> bool:
    """True when a URL host is an IP literal in any form the browser resolves —
    dotted IPv4, obfuscated single-number/octal/hex IPv4, or an IPv6 literal
    (urlsplit has already stripped the brackets)."""
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host) or numeric_ip_host(host):
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


class _EvidenceBuilder:
    def __init__(self) -> None:
        self.items: list[Evidence] = []

    def add(
        self,
        category: str,
        severity: str,
        description: str,
        indicator: str | None = None,
        untrusted_detail: str | None = None,
    ):
        self.items.append(
            Evidence(
                id=f"E{len(self.items) + 1}",
                category=category,
                severity=severity,
                description=description,
                indicator=indicator,
                untrusted_detail=untrusted_detail,
            )
        )


def _auth_checks(email: ParsedEmail, ev: _EvidenceBuilder) -> None:
    auth = email.auth_results
    if auth.raw is None and auth.spf is None:
        # No Authentication-Results and no Received-SPF fallback either.
        if not email.headers_only_input:
            ev.add(
                "auth",
                "info",
                "No Authentication-Results header present; SPF/DKIM/DMARC verdicts unavailable.",
            )
        return
    # "Topmost" does not prove the receiving MTA added the header. Say so when
    # nothing in the message backs it up, and shout when the header stack
    # contradicts itself — a forged copy pre-inserted by the sender, with the
    # real MTA's verdict sitting below it.
    if auth.conflicts:
        ev.add(
            "auth",
            "medium",
            f"Authentication-Results headers disagree ({auth.header_count} present) on "
            f"{', '.join(sorted(auth.conflicts)).upper()} — a sender can pre-insert a forged "
            "copy, so the topmost result may not be your MTA's. Compare the headers by hand.",
        )
    if auth.raw and not auth.corroborated and email.received:
        claimed = auth.authserv_id or "(no authentication-service id)"
        ev.add(
            "auth",
            "low",
            "Authentication-Results claims to come from "
            f"{defang(claimed[:MAX_TRUSTED_VALUE_CHARS], 'domain')}, which is not a host that "
            "received this message — the SPF/DKIM/DMARC results below are self-asserted by "
            "the message and may be forged.",
        )

    source = "topmost Authentication-Results" if auth.raw else "Received-SPF header"
    for method, verdict in (("SPF", auth.spf), ("DKIM", auth.dkim), ("DMARC", auth.dmarc)):
        if verdict is None:
            continue
        if verdict == "fail":
            sev = "high" if method == "DMARC" else "medium"
            ev.add("auth", sev, f"{method} check failed (from {source}).")
        elif verdict in ("softfail", "permerror", "temperror"):
            ev.add("auth", "low", f"{method} result: {verdict}.")
        elif verdict == "none" and method == "DMARC":
            ev.add(
                "auth",
                "low",
                "No DMARC policy for the sending domain — the From address is spoofable.",
            )


def _header_checks(email: ParsedEmail, ev: _EvidenceBuilder) -> None:
    from_dom = email.from_domain
    reply_dom = email.reply_to_domain

    if reply_dom and from_dom and registered_domain(reply_dom) != registered_domain(from_dom):
        if reply_dom in FREEMAIL_DOMAINS:
            # Domains, not the full addresses: a local part is attacker-chosen
            # free text (an RFC 5321 quoted string can hold a sentence) and a
            # description lands in the judge's trusted EVIDENCE zone. Same rule
            # as the display name below and hidden text in _content_checks.
            ev.add(
                "header",
                "high",
                f"Reply-To is a freemail address on {defang(reply_dom, 'domain')}, "
                f"a different domain than From ({defang(from_dom, 'domain')}) "
                "— canonical BEC pattern. (Addresses not quoted; "
                "see --json email.reply_to_addr.)",
                email.reply_to_addr,
            )
        else:
            ev.add(
                "header",
                "medium",
                f"Reply-To domain ({defang(reply_dom, 'domain')}) differs from "
                f"From domain ({defang(from_dom, 'domain')}).",
                email.reply_to_addr,
            )

    rp_dom = email.return_path_domain
    if rp_dom and from_dom and registered_domain(rp_dom) != registered_domain(from_dom):
        ev.add(
            "header",
            "info",
            f"Return-Path domain ({defang(rp_dom, 'domain')}) differs from "
            f"From domain ({defang(from_dom, 'domain')}) — "
            "common for mailing services, notable when combined with other signals.",
        )

    embedded = _EMAIL_IN_DISPLAY_RE.search(email.from_display)
    # rstrip trailing punctuation: the regex's domain class swallows a
    # sentence-ending period ("Reply to bob@corp.example. Thanks!"), which would
    # otherwise never equal from_addr and fire a false address-spoof signal.
    embedded_addr = embedded.group(0).rstrip(". ").lower() if embedded else None
    if embedded and embedded_addr != email.from_addr:
        # Quote only the regex-constrained (space-free, length-bounded) embedded
        # address, never the whole display name, and only the *domain* of the
        # real sender — a parseaddr local part can be an RFC 5321 quoted string
        # carrying a sentence, and this text lands in the judge's trusted
        # EVIDENCE zone (same rule as hidden text below).
        ev.add(
            "header",
            "high",
            "Display name contains an email address "
            f"({defang(embedded_addr[:MAX_TRUSTED_VALUE_CHARS], 'email')}) that is not the "
            f"actual sender, whose domain is {defang(from_dom or '(none)', 'domain')} — "
            "address-spoofing trick. (Display name not quoted; "
            "see --json email.from_display.)",
            email.from_addr,
        )

    if not email.message_id and not email.headers_only_input and email.from_addr:
        ev.add("header", "low", "Message-ID header is missing.")
    elif email.message_id and from_dom:
        mid_dom = email.message_id.rsplit("@", 1)[-1].strip("<> ").lower()
        if mid_dom and registered_domain(mid_dom) != registered_domain(from_dom):
            ev.add(
                "header",
                "info",
                f"Message-ID domain ({defang(mid_dom, 'domain')}) differs from "
                f"From domain ({defang(from_dom, 'domain')}).",
            )

    if email.has_list_unsubscribe:
        ev.add(
            "header",
            "info",
            "List-Unsubscribe header present — sent via bulk-mail tooling "
            "(typical of legitimate newsletters).",
        )


def _punycode_checks(indicators: list[Indicator], email: ParsedEmail, ev: _EvidenceBuilder):
    seen: set[str] = set()
    domains = [i.value for i in indicators if i.type in ("domain", "hostname")]
    domains += [d for d in (email.from_domain, email.reply_to_domain) if d]
    for dom in domains:
        if "xn--" in dom and dom not in seen:
            seen.add(dom)
            ev.add(
                "link",
                "high",
                f"Punycode (IDN) domain: {defang(dom, 'domain')} — often used for homoglyph "
                "lookalikes of trusted brands.",
                dom,
            )


def _link_checks(email: ParsedEmail, indicators: list[Indicator], ev: _EvidenceBuilder):
    for link in email.html.links:
        href = link.href.strip()
        # Same normalization as extract.py: scheme-relative (and WHATWG
        # backslash-variant) links resolve as https in webmail — without this
        # the anchor-text-mismatch check below never sees them.
        if re.match(r"^[/\\]{2}", href):
            href = "https:" + href.replace("\\", "/")
        low = href.lower()
        if low.startswith("javascript:") or (low.startswith("data:") and link.source == "href"):
            ev.add(
                "link",
                "high",
                f"Link uses a {low.split(':', 1)[0]}: URI — "
                "executes content instead of navigating.",
            )
            continue
        if not low.startswith(("http://", "https://")):
            continue
        text = (link.text or "").strip()
        m = _URL_SHAPED_RE.fullmatch(text)
        if m and text:
            # Compare against the gateway-unwrapped target, or SafeLinks-style
            # rewrapping of legitimate links would always look like a mismatch.
            target = _clean_url(unwrap_gateways(href))
            text_host = re.sub(r"^https?://", "", text, flags=re.I).split("/")[0].split("?")[0]
            href_host = re.sub(r"^https?://", "", target, flags=re.I).split("/")[0].split("?")[0]
            if (
                # Require a real public suffix: without it, dotted non-domain
                # anchor text ("Node.js", "v2.0") is not a hostname and
                # registered_domain() would echo it back as a false mismatch.
                has_public_suffix(text_host.lower())
                and registered_domain(text_host.lower()) != registered_domain(href_host)
            ):
                # The host out of the anchor text, not the anchor text itself:
                # _URL_SHAPED_RE allows a path, and a path is attacker-authored
                # free text in what becomes the judge's trusted zone.
                ev.add(
                    "link",
                    "high",
                    "Anchor text looks like a URL on "
                    f'"{defang(text_host[:MAX_TRUSTED_VALUE_CHARS], "domain")}" but the link '
                    "actually points to a different domain "
                    f"({defang(registered_domain(href_host), 'domain')}).",
                    target,
                )

    for ind in indicators:
        if ind.type != "url":
            continue
        host = re.sub(r"^https?://", "", ind.value, flags=re.I).split("/")[0].split("?")[0]
        if registered_domain(host) in URL_SHORTENERS:
            shortener = defang(registered_domain(host), "domain")
            ev.add(
                "link",
                "medium",
                f"Link uses a URL shortener ({shortener}) — final destination is hidden.",
                ind.value,
            )
        if ind.unwrapped_from and is_known_gateway(ind.unwrapped_from):
            ev.add(
                "link",
                "info",
                "Link was rewritten by a security gateway and has been unwrapped "
                "to its real target.",
                ind.value,
            )
        elif ind.unwrapped_from:
            ev.add(
                "link",
                "info",
                "URL was found as a redirect target inside another link's query string.",
                ind.value,
            )
        if is_undecodable_rewrapper(ind.value):
            ev.add(
                "link",
                "info",
                "Link was rewritten by a gateway whose links cannot be decoded "
                "offline (e.g. Mimecast) — the real target is unknown.",
                ind.value,
            )
        # Host-derived, not a prefix regex: catches `?`/`#` right after the
        # quad, ports, userinfo tricks, single-number IP forms, and IPv6.
        try:
            link_host = urlsplit(ind.value).hostname or ""
        except ValueError:
            link_host = ""
        if link_host and _is_ip_host(link_host):
            ev.add(
                "link",
                "high",
                "Link points directly at an IP address instead of a domain name.",
                ind.value,
            )

    if email.html.form_actions:
        # The submit target's host, not the whole action URL: its path and query
        # are attacker-authored free text and this description reaches the
        # judge's trusted zone. The full URL travels as the indicator (and so
        # into the report and --json), where it is rendered host-only for the
        # prompt — see judge._trusted_indicator.
        action = email.html.form_actions[0]
        try:
            action_host = urlsplit(action).hostname or ""
        except ValueError:
            action_host = ""
        where = (
            f"to {defang(action_host[:MAX_TRUSTED_VALUE_CHARS], 'domain')}"
            if action_host
            else "to a relative or malformed target"
        )
        ev.add(
            "content",
            "high",
            f"Email body contains an HTML <form> that submits data {where} — "
            "emails should never collect input directly.",
            action if action_host else None,
        )

    for link in email.html.links:
        if link.source == "meta-refresh":
            ev.add("content", "medium", "HTML body uses a meta-refresh redirect.", link.href)
            break


def _content_checks(email: ParsedEmail, ev: _EvidenceBuilder) -> None:
    # Never quote hidden text: it is attacker-controlled and Evidence
    # descriptions reach the judge's trusted zone (and the terminal report).
    for hidden in email.html.hidden_texts:
        if _AI_INSTRUCTION_RE.search(hidden):
            ev.add(
                "content",
                "high",
                "Hidden text contains instructions apparently aimed at an AI/security "
                "classifier — prompt-injection attempt; strong indicator of malice. "
                f"({len(hidden)} chars, not quoted; see --json html.hidden_texts.)",
            )
        else:
            ev.add(
                "content",
                "medium",
                "Body contains text hidden from the reader "
                f"({len(hidden)} chars, not quoted; see --json html.hidden_texts).",
            )
    if email.html.has_zero_width_chars:
        ev.add(
            "content",
            "medium",
            "Body contains zero-width characters — a common filter-evasion trick.",
        )


# A filename is unbounded attacker-authored text, so a crafted one must not be
# able to flood the report either. 120 chars keeps every realistic name intact.
MAX_FILENAME_CHARS = 120


def _filename_detail(filename: str) -> str:
    """Render an attacker-controlled filename for the *report only*.

    Defanged (dots and at-signs — "paypal.com-invoice@evil.example.pdf.exe"
    embeds a live domain and a live address), control- and bidi-stripped,
    whitespace-collapsed (strip_controls deliberately keeps \\n and \\t) and
    length-bounded.

    This is never interpolated into an Evidence description. Descriptions reach
    the judge as verified facts, so unbounded prose there is a prompt-injection
    channel — the same rule `_header_checks` applies to the display name and
    `_content_checks` applies to hidden text. It travels as `untrusted_detail`,
    which `judge.build_user_prompt` deliberately does not render.
    """
    name = " ".join(strip_controls(filename).split())
    name = name.replace(".", "[.]").replace("@", "[@]")
    if len(name) > MAX_FILENAME_CHARS:
        name = name[:MAX_FILENAME_CHARS] + "..."
    return f'filename: "{name}"'


def _attachment_checks(email: ParsedEmail, ev: _EvidenceBuilder) -> None:
    body = (email.text_body + " " + email.html.visible_text).lower()
    for att in email.attachments:
        detail = _filename_detail(att.filename)
        # Windows strips trailing dots/spaces before executing, and zero-width
        # chars (which strip_controls leaves) can be slipped into an extension
        # ("malware.exe.", "malware.ex​e") to dodge the tier lookup below.
        # Normalize before splitting so those all resolve to the real extension.
        lower = re.sub(r"[\u200b-\u200d\ufeff]", "", att.filename.lower()).rstrip(". ")
        parts = lower.rsplit(".", 2)
        # Only ever a member of the tier sets below, so this is safe to interpolate.
        ext = "." + parts[-1] if len(parts) > 1 else ""

        sha = att.sha256 or None  # forwarded-message containers carry no hash
        if _RTLO in att.filename:
            ev.add(
                "attachment",
                "high",
                "Attachment filename contains a right-to-left-override character "
                "— displayed extension is spoofed.",
                sha,
                detail,
            )
        if len(parts) == 3 and "." + parts[1] in DECOY_EXTS and ext in EXT_HIGH:
            ev.add(
                "attachment",
                "high",
                "Attachment has a double extension disguising an executable.",
                sha,
                detail,
            )

        if ext in EXT_HIGH:
            ev.add(
                "attachment",
                "high",
                f"Attachment is an executable/script type ({ext}).",
                sha,
                detail,
            )
        elif ext in EXT_MEDIUM:
            sev = "medium"
            desc = f"Attachment is a {ext} file — "
            desc += (
                "macro-capable Office document."
                if ext.startswith((".d", ".x", ".p"))
                else "container/archive format often used to smuggle payloads."
            )
            if ext in {".zip", ".rar", ".7z"} and "password" in body:
                sev = "high"
                desc += (
                    " The body mentions a password — password-protected archives with the "
                    "password in the email are a classic AV-evasion pattern."
                )
            ev.add("attachment", sev, desc, sha, detail)
        elif ext in EXT_WATCH:
            ev.add(
                "attachment",
                "low",
                f"Attachment ({ext}) can carry active content (HTML smuggling, embedded links/QR).",
                sha,
                detail,
            )


def run_signals(email: ParsedEmail, indicators: list[Indicator]) -> list[Evidence]:
    ev = _EvidenceBuilder()
    _auth_checks(email, ev)
    _header_checks(email, ev)
    _punycode_checks(indicators, email, ev)
    _link_checks(email, indicators, ev)
    _content_checks(email, ev)
    _attachment_checks(email, ev)
    return ev.items
