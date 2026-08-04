"""Unwrap security-gateway rewritten URLs (SafeLinks, Proofpoint, ...) to their targets.

`unwrap(url)` recursively decodes known rewrappers plus a generic
"query param that is itself an absolute URL" fallback, returning the final
target and the chain of intermediate forms. Known-gateway hops are vetted
infra; generic hops are untrusted (the wrapper may be the phishing host), so
extract.py keeps generic wrappers as indicators and `unwrap_gateways()`
follows only the vetted hops. Mimecast links are opaque (API-only decode)
and are reported as rewritten-but-undecodable.
"""

from __future__ import annotations

import base64
import re
from urllib.parse import ParseResult, parse_qs, unquote, urlparse

MAX_DEPTH = 5

_EMPTY_PARSE = ParseResult("", "", "", "", "", "")


def _safe_urlparse(url: str) -> ParseResult:
    """urlparse that never raises. Python's urlsplit validates bracketed hosts
    and throws ValueError on malformed IPv6 literals ("http://[test]/"); a
    single crafted anchor must not crash the whole analysis."""
    try:
        return urlparse(url)
    except ValueError:
        return _EMPTY_PARSE


# Hosts whose links are rewritten but cannot be decoded offline.
UNDECODABLE_HOSTS = re.compile(r"(^|\.)protect-\w+\.mimecast\.com$", re.I)

_PPV3_RE = re.compile(r"^https?://urldefense\.com/v3/__(?P<url>.+?)__;(?P<enc>[^!]*)!!", re.I)
_PPV3_RUN_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def _decode_ppv3(url: str) -> str | None:
    """Proofpoint v3: URL between __..__; '*' placeholders restored from the b64 segment."""
    m = _PPV3_RE.match(url)
    if not m:
        return None
    target = m.group("url")
    enc = m.group("enc")
    if "*" in target and enc:
        try:
            pad = "=" * (-len(enc) % 4)
            chars = base64.urlsafe_b64decode(enc + pad).decode("utf-8", "replace")
        except Exception:
            return target.replace("*", "")
        it = iter(chars)
        out: list[str] = []
        i = 0
        while i < len(target):
            ch = target[i]
            if target.startswith("**", i):
                # '**A' = run-length: A encodes how many chars to substitute
                i += 2
                run = target[i] if i < len(target) else ""
                i += 1
                # Run chars map A-Z -> 2-27 and a-z -> 28-53.
                idx = _PPV3_RUN_CHARS.find(run)
                count = idx + 2 if idx != -1 else (1 if run else 0)
                out.extend(next(it, "") for _ in range(count))
            elif ch == "*":
                out.append(next(it, ""))
                i += 1
            else:
                out.append(ch)
                i += 1
        target = "".join(out)
    return target


def _decode_known(url: str) -> str | None:
    """Decode `url` if it is a known (vetted) gateway rewrapper, else None."""
    parsed = _safe_urlparse(url)
    host = (parsed.hostname or "").lower()
    qs = parse_qs(parsed.query)

    # parse_qs has already percent-decoded the values once; decoding again
    # corrupts targets whose own escapes (%20, %2B...) were legitimately
    # double-encoded by the gateway. Only decoders that *introduce* fresh
    # %-escapes (Proofpoint v2's -/_ substitution, Cisco's path form) unquote.
    def q(name: str) -> str | None:
        vals = qs.get(name)
        return vals[0] if vals else None

    if host.endswith(".safelinks.protection.outlook.com") and q("url"):
        return q("url")

    if host == "urldefense.proofpoint.com":
        u = q("u")
        if u and "/v2/" in parsed.path:
            return unquote(u.replace("-", "%").replace("_", "/"))
        if u:  # v1
            return u

    if host == "urldefense.com":
        decoded = _decode_ppv3(url)
        if decoded:
            return decoded

    if host == "linkprotect.cudasvc.com" and q("a"):
        return q("a")

    if host == "secure-web.cisco.com":
        # Path shape: /<token>/<url-without-scheme> or /<token>/https://...
        parts = parsed.path.split("/", 2)
        if len(parts) == 3 and parts[2]:
            tail = unquote(parts[2])
            return tail if tail.startswith(("http://", "https://")) else "https://" + tail

    if host == "clicktime.symantec.com" and q("u"):
        return q("u")

    if host in ("google.com", "www.google.com") and parsed.path == "/url" and (q("q") or q("url")):
        return q("q") or q("url")

    return None


def _decode_generic(url: str) -> str | None:
    """Generic fallback: any query-param value that is itself an absolute URL.

    Untrusted — the "wrapper" host may itself be the phishing site hiding
    behind a benign-looking redirect target, so callers must keep the wrapper
    as an indicator too (extract.py does).
    """
    for vals in parse_qs(_safe_urlparse(url).query).values():
        for v in vals:  # parse_qs already percent-decoded once — see _decode_known
            if v.lower().startswith(("http://", "https://")):
                return v
            # Double-encoded redirect target (dest=https%253A%252F...): apply
            # the extra decode only when it's what reveals a URL, so ordinary
            # targets' own escapes are never corrupted.
            decoded = unquote(v)
            if decoded != v and decoded.lower().startswith(("http://", "https://")):
                return decoded
    return None


def _decode_one(url: str) -> str | None:
    return _decode_known(url) or _decode_generic(url)


def is_known_gateway(url: str) -> bool:
    """True when `url` is a recognized vendor rewrapper (its host is vetted infra)."""
    return _decode_known(url) is not None


def unwrap_gateways(url: str) -> str:
    """Follow only known-gateway hops. Use where a generic redirect target must
    not mask the host the user actually clicks (e.g. anchor-text mismatch checks)."""
    current = url
    for _ in range(MAX_DEPTH):
        decoded = _decode_known(current)
        if not decoded or decoded == current:
            break
        current = decoded
    return current


def is_undecodable_rewrapper(url: str) -> bool:
    host = _safe_urlparse(url).hostname or ""
    return bool(UNDECODABLE_HOSTS.search(host))


def unwrap(url: str) -> tuple[str, list[str]]:
    """Recursively unwrap. Returns (final_url, chain_of_wrapped_forms).

    chain is empty when the URL wasn't wrapped at all.
    """
    chain: list[str] = []
    current = url
    for _ in range(MAX_DEPTH):
        decoded = _decode_one(current)
        if not decoded or decoded == current:
            break
        chain.append(current)
        current = decoded
    return current, chain
