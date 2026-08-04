"""Stage 2: turn a ParsedEmail into a normalized, deduplicated Indicator list."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

import tldextract

from .defang import refang
from .models import Indicator, ParsedEmail
from .unwrap import is_known_gateway, unwrap

# Suppressed from the report by default (still enriched when budget allows).
# Rank-lowering only — noise status never exempts an IOC from analysis.
NOISE_DOMAINS = {
    "schema.org",
    "w3.org",
    "www.w3.org",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "gstatic.com",
    "googleapis.com",
    "doubleclick.net",
    "google-analytics.com",
    "list-manage.com",  # mailchimp unsubscribe infra
}

_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
# URL-shaped tokens in plain text. Runs over refang()ed text, so a defanged
# paste ("hxxps://evil[.]example/x") is caught too. Deliberately greedy to the
# next whitespace or quote — _clean_url trims the trailing punctuation a URL
# picks up at the end of a sentence.
_TEXT_URL_RE = re.compile(r"https?://[^\s<>\"'`]+", re.I)

_TLDX = tldextract.TLDExtract(suffix_list_urls=())  # offline: bundled PSL snapshot


def registered_domain(host: str) -> str:
    ext = _TLDX(host)
    return ext.top_domain_under_public_suffix or host


def has_public_suffix(host: str) -> bool:
    """True only when `host` ends in a real public suffix. Distinguishes a
    domain ("evil.com") from a dotted non-domain token ("Node.js", "v2.0")."""
    return bool(_TLDX(host).suffix)


def is_public_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def numeric_ip_host(host: str) -> str | None:
    """Canonical dotted-quad form of a numeric IPv4 host — browsers resolve
    these inet_aton-style, and all of them are classic URL obfuscation:
    single-number (http://2130706433/, 0x7f000001), octal/hex octets
    (0177.0.0.1, 0x7f.0x0.0x0.0x1), and short forms (0x7f.1) where the last
    part covers the remaining bytes."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4:
        return None
    nums = []
    for part in parts:
        if re.fullmatch(r"0[xX][0-9a-fA-F]+", part):
            nums.append(int(part, 16))
        elif re.fullmatch(r"0[0-7]*", part):  # leading 0 = octal; "0" is zero
            nums.append(int(part, 8))
        elif re.fullmatch(r"[1-9]\d*", part):
            nums.append(int(part))
        else:
            return None
    *heads, last = nums
    if any(n > 255 for n in heads) or last >= 256 ** (4 - len(heads)):
        return None
    for i, n in enumerate(heads):
        last += n << (8 * (3 - i))
    return str(ipaddress.IPv4Address(last))


def _clean_url(url: str) -> str:
    url = url.strip().strip("\"'<>").rstrip(".,;:)]}")
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
    except ValueError:
        # Malformed host (e.g. an invalid IPv6 literal "http://[test]/") — a
        # crafted anchor must not crash the whole analysis. Keep the raw string.
        return url
    if hostname:
        # Lowercase scheme+host, preserve path/query case.
        rebuilt = parsed._replace(scheme=parsed.scheme.lower(), netloc=parsed.netloc.lower())
        return rebuilt.geturl()
    return url


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


class _Collector:
    def __init__(self) -> None:
        self.indicators: dict[tuple[str, str], Indicator] = {}

    def add(self, ind: Indicator) -> None:
        key = (ind.type, ind.value)
        existing = self.indicators.get(key)
        if existing is None:
            self.indicators[key] = ind
            return
        # Keep the richest copy: prefer one with display text / unwrap info,
        # and let any non-noise sighting clear the noise flag.
        if ind.display_text and not existing.display_text:
            existing.display_text = ind.display_text
        if ind.unwrapped_from and not existing.unwrapped_from:
            existing.unwrapped_from = ind.unwrapped_from
        existing.noise = existing.noise and ind.noise

    def _add_url(self, url: str, source: str, display_text: str | None, noise: bool) -> None:
        final, chain = unwrap(_clean_url(url))
        final = _clean_url(final)
        # Generic-fallback hops are untrusted: the "wrapper" may itself be the
        # phishing host hiding behind a benign URL in a query param, so it is
        # kept as an indicator. Known-gateway hops (SafeLinks & co) are vetted
        # infra and dropped. Anchor text stays with the URL the user clicks.
        for wrapped in chain:
            if not is_known_gateway(wrapped):
                self._add_url_forms(_clean_url(wrapped), source, display_text, noise)
                display_text = None
        self._add_url_forms(
            final, source, display_text, noise, unwrapped_from=chain[0] if chain else None
        )

    def _add_url_forms(
        self,
        url: str,
        source: str,
        display_text: str | None,
        noise: bool,
        unwrapped_from: str | None = None,
    ) -> None:
        host = _host_of(url)
        # Single-number IP hosts classify by their real address; the URL
        # indicator keeps the original form (that's what the user clicks).
        numeric = numeric_ip_host(host) if host else None
        if numeric:
            host = numeric
        # Dotless non-IP "hosts" are extraction junk (e.g. a bare "https://www"
        # left behind by a truncated or percent-encoded link).
        if not host or ("." not in host and not is_public_ip(host)):
            return
        self.add(
            Indicator(
                value=url,
                type="url",
                source=source,
                display_text=display_text or None,
                unwrapped_from=unwrapped_from,
                noise=noise or registered_domain(host) in NOISE_DOMAINS,
            )
        )
        if is_public_ip(host):
            self.add(Indicator(value=host, type="ip", source=source, noise=noise))
        elif _is_ip_literal(host):
            # Private/reserved IP host: not a routable IOC, and typing it as a
            # domain would send CC a malformed query. The URL indicator stays.
            pass
        else:
            domain = registered_domain(host)
            is_noise = noise or domain in NOISE_DOMAINS
            self.add(Indicator(value=domain, type="domain", source=source, noise=is_noise))
            if host != domain:
                self.add(Indicator(value=host, type="hostname", source=source, noise=is_noise))


def extract_indicators(email: ParsedEmail) -> list[Indicator]:
    c = _Collector()

    # HTML links are the primary source: they carry anchor-text context.
    for link in email.html.links:
        href = link.href.strip()
        # Scheme-relative links resolve against the page scheme — webmail is
        # https. WHATWG URL parsing treats \ as / for special schemes, so
        # "/\evil.com" and "\\evil.com" are the same link to a browser.
        if re.match(r"^[/\\]{2}", href):
            href = "https:" + href.replace("\\", "/")
        if href.lower().startswith(("javascript:", "data:", "mailto:", "tel:", "cid:")):
            continue  # javascript:/data: are flagged as evidence in signals.py
        if not href.lower().startswith(("http://", "https://")):
            continue
        c._add_url(href, "body-html", link.text, noise=link.source == "src")

    # Plain-text fallback — covers text bodies, HTML-only emails that show a
    # URL as bare (non-hyperlinked) text, and refangs defanged pasted text.
    for text in (email.text_body, email.html.visible_text):
        for match in _TEXT_URL_RE.finditer(refang(text)):
            c._add_url(match.group(0), "body-text", None, noise=False)

    for text in (email.text_body, email.html.visible_text):
        for sha256 in _SHA256_RE.findall(text):
            c.add(Indicator(value=sha256.lower(), type="sha256", source="body-text"))
        for sha1 in _SHA1_RE.findall(text):
            c.add(Indicator(value=sha1.lower(), type="sha1", source="body-text"))

    if email.origin_ip:
        c.add(Indicator(value=email.origin_ip, type="ip", source="header-received"))

    for addr, src in ((email.from_addr, "header-sender"), (email.reply_to_addr, "header-sender")):
        if addr and "@" in addr:
            c.add(Indicator(value=addr, type="email", source=src))
            domain = registered_domain(addr.rsplit("@", 1)[1])
            c.add(Indicator(value=domain, type="domain", source=src))

    for att in email.attachments:
        # No hashes for re-serialized forwarded-message containers — see
        # parser._walk_attachments.
        if att.size == 0 or not att.sha256:
            continue
        c.add(Indicator(value=att.sha256, type="sha256", source="attachment"))
        c.add(Indicator(value=att.md5, type="md5", source="attachment"))

    return rank_indicators(list(c.indicators.values()))


_TYPE_PRIORITY = {
    "sha256": 0,
    "md5": 1,
    "sha1": 1,
    "url": 2,
    "domain": 3,
    "hostname": 4,
    "ip": 5,
    "email": 6,
}
_SOURCE_PRIORITY = {
    "attachment": 0,
    "body-html": 1,
    "body-text": 2,
    "header-sender": 3,
    "header-received": 4,
}


def rank_indicators(indicators: list[Indicator]) -> list[Indicator]:
    """Non-noise first, then by type/source priority — the order used when
    truncating to the enrichment batch cap."""
    return sorted(
        indicators,
        key=lambda i: (
            i.noise,
            _TYPE_PRIORITY.get(i.type, 9),
            _SOURCE_PRIORITY.get(i.source, 9),
            i.value,
        ),
    )
