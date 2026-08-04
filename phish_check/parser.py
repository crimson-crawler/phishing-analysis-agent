"""Stage 1: parse a raw .eml (or pasted headers+body) into a ParsedEmail."""

from __future__ import annotations

import hashlib
import re
from email import message_from_bytes, policy
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr

from .extract import is_public_ip, registered_domain
from .html_analysis import analyze_html
from .models import Attachment, AuthResults, ParsedEmail

_AUTH_METHOD_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)")
# "by <host>" out of a Received hop — the host that took delivery of that hop.
_RECEIVED_BY_RE = re.compile(r"\bby\s+([A-Za-z0-9._-]+)", re.I)
# RFC 7208 §2.6 result keywords. Received-SPF's first token is attacker text
# otherwise, and it lands in the report and in --json as auth_results.spf.
_SPF_RESULT_RE = re.compile(r"(none|neutral|pass|fail|softfail|temperror|permerror)\b", re.I)
# Boundaries stop dotted SMTP-id tokens ("id q6789.1234.5.6.78") from
# fabricating dotted-quads out of their tails.
_IP_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
# Pasted input counts as a real message only when it starts with a header name
# an email would actually have — a generic word+colon (e.g. "Urgent:") is body.
_HEADER_LINE_RE = re.compile(
    r"^(From|To|Cc|Bcc|Subject|Date|Received|Return-Path|Reply-To|Message-ID|Sender|"
    r"MIME-Version|Content-Type|Delivered-To|Authentication-Results|Received-SPF|"
    r"DKIM-Signature|ARC-[\w-]+|List-[\w-]+|X-[\w-]+):",
    re.I,
)


def _read_methods(raw: str) -> dict[str, str]:
    """Method -> verdict for one Authentication-Results header."""
    out: dict[str, str] = {}
    for method, verdict in _AUTH_METHOD_RE.findall(raw):
        # RFC 8601 allows several results per method. For DKIM any pass counts
        # (dual-signed mail with one broken second signature is common, and an
        # unaligned attacker signature is DMARC's job to catch). SPF/DMARC keep
        # the first result — any-pass-wins there would let an
        # attacker-influenced later token mask a fail.
        method, verdict = method.lower(), verdict.lower()
        current = out.get(method)
        if current is None or (method == "dkim" and current != "pass" and verdict == "pass"):
            out[method] = verdict
    return out


def _receiving_hosts(received: list[str]) -> set[str]:
    """Registered domains of the hosts that claim to have *received* each hop.

    A genuine Authentication-Results header is stamped by a host that also
    appears in a Received "by" clause, so this is what the header's authserv-id
    can be checked against without asking the user to configure anything.
    """
    hosts = set()
    for hop in received:
        for host in _RECEIVED_BY_RE.findall(hop):
            hosts.add(registered_domain(host.lower().strip(".")))
    return {h for h in hosts if h}


def _parse_auth_results(msg: EmailMessage, received: list[str]) -> AuthResults:
    # The topmost Authentication-Results header is the one whose results are
    # used — attackers pre-insert forged copies, which end up *below* the
    # receiving MTA's stamp. But position is not proof: in an arbitrary .eml
    # there may be no MTA stamp at all, in which case the topmost header is the
    # attacker's. So record two trust signals for signals.py to report on: does
    # the header's authserv-id match a host that received a hop, and do any
    # lower headers contradict it.
    headers = [str(h) for h in (msg.get_all("Authentication-Results") or [])]
    result = AuthResults(header_count=len(headers))
    if headers:
        raw = headers[0]
        result.raw = raw
        result.authserv_id = raw.split(";", 1)[0].split()[0].strip().lower() if raw.strip() else ""
        for method, verdict in _read_methods(raw).items():
            setattr(result, method, verdict)
        if result.authserv_id:
            claimed = registered_domain(result.authserv_id.strip("."))
            result.corroborated = bool(claimed) and claimed in _receiving_hosts(received)
        for lower in headers[1:]:
            for method, verdict in _read_methods(lower).items():
                if getattr(result, method) != verdict and method not in result.conflicts:
                    result.conflicts.append(method)
    if result.spf is None:
        received_spf = msg.get("Received-SPF")
        if received_spf:
            # Only a recognized RFC 7208 result keyword, never the header's
            # first whitespace-delimited token: that token is attacker text and
            # reaches both the report and the JSON output as `auth_results.spf`.
            match = _SPF_RESULT_RE.match(str(received_spf).strip())
            if match:
                result.spf = match.group(1).lower()
    return result


def _origin_ip(received: list[str]) -> str:
    # Walk bottom-up (oldest hop first); first public IP is the likely origin.
    for hop in reversed(received):
        for candidate in _IP_RE.findall(hop):
            if is_public_ip(candidate):
                return candidate
    return ""


def _walk_bodies(msg: EmailMessage, parsed: ParsedEmail) -> None:
    html_parts: list[str] = []
    text_parts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        if part.is_attachment():
            continue
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", "replace")
        # A part with no declared charset (or a lying one) decodes as us-ascii
        # under the stdlib default, turning every non-ASCII byte into U+FFFD —
        # which silently destroys zero-width / homoglyph tripwires. Real clients
        # treat unlabeled parts as UTF-8; re-decode when that recovers bytes.
        if "�" in content or part.get_content_charset() is None:
            payload = part.get_payload(decode=True)
            if payload is not None:
                redecoded = payload.decode("utf-8", "replace")
                if redecoded.count("�") <= content.count("�"):
                    content = redecoded
        if ctype == "text/html":
            html_parts.append(content)
        else:
            text_parts.append(content)
    parsed.text_body = "\n\n".join(text_parts).strip()
    if html_parts:
        parsed.html = analyze_html("\n".join(html_parts))


# Nested-forward depth cap: recursing costs one full re-serialization per
# level, so unbounded depth is quadratic — a crafted eml of thousands of
# nested message/rfc822 shells would pin the CPU for minutes.
MAX_FORWARD_DEPTH = 3


def _add_attachment(
    parsed: ParsedEmail,
    filename: str,
    content_type: str,
    payload: bytes,
    hashable: bool = True,
) -> None:
    # usedforsecurity=False: MD5/SHA-1 are IOC identifiers here (CC keys hash
    # lookups on MISP attribute types by digest length), not security
    # primitives. Without the flag, hashlib raises on a FIPS-mode build and
    # every message with an attachment fails to analyze.
    parsed.attachments.append(
        Attachment(
            filename=filename,
            content_type=content_type,
            size=len(payload),
            md5=hashlib.md5(payload, usedforsecurity=False).hexdigest() if hashable else "",
            sha1=hashlib.sha1(payload, usedforsecurity=False).hexdigest() if hashable else "",
            sha256=hashlib.sha256(payload).hexdigest() if hashable else "",
        )
    )


def _walk_attachments(msg: EmailMessage, parsed: ParsedEmail, depth: int = 0) -> None:
    for part in msg.iter_attachments():
        if part.get_content_type() == "message/rfc822" and depth < MAX_FORWARD_DEPTH:
            # Forwarded-as-attachment ("user sends the phish to the SOC"):
            # get_payload(decode=True) is None for message/rfc822, and
            # iter_attachments never descends — without recursing, a payload
            # nested in the forwarded message would escape hashing and the
            # attachment checks entirely. The container itself is recorded
            # WITHOUT hashes: as_bytes() re-serializes (refolded headers, new
            # line endings), and a hash of bytes that never existed sends an
            # analyst pivoting to VirusTotal/CC to a false "no hits".
            for inner in part.get_payload() or []:
                try:
                    payload = inner.as_bytes()
                except Exception:
                    payload = b""
                _add_attachment(
                    parsed,
                    part.get_filename() or "(forwarded message)",
                    part.get_content_type(),
                    payload,
                    hashable=False,
                )
                _walk_attachments(inner, parsed, depth + 1)
            continue
        _add_attachment(
            parsed,
            part.get_filename() or "(unnamed)",
            part.get_content_type(),
            part.get_payload(decode=True) or b"",
        )


def parse_email(raw: bytes) -> ParsedEmail:
    """Parse raw .eml bytes, or pasted text that may lack proper headers."""
    # A UTF-8 BOM or leading blank bytes break both the offset-0 header test
    # below and message_from_bytes' first header — a one-byte evasion of the
    # entire header/auth stage. Strip to a fixpoint: BOMs and whitespace can
    # be interleaved, and one pass of each is bypassable.
    while True:
        cleaned = raw.removeprefix(b"\xef\xbb\xbf").lstrip(b"\r\n\t ")
        if cleaned == raw:
            break
        raw = cleaned
    text_preview = raw[:2048].decode("utf-8", "replace")
    looks_like_message = bool(_HEADER_LINE_RE.match(text_preview))

    parsed = ParsedEmail()
    if not looks_like_message:
        # Treat the whole input as a body (headers unavailable).
        parsed.headers_only_input = True
        body = raw.decode("utf-8", "replace")
        if "<html" in body.lower() or "<a " in body.lower():
            parsed.html = analyze_html(body)
        parsed.text_body = body
        return parsed

    msg = message_from_bytes(raw, policy=policy.default)

    parsed.subject = str(msg.get("Subject", ""))
    display, addr = parseaddr(str(msg.get("From", "")))
    parsed.from_display = display
    parsed.from_addr = addr.lower()
    _, reply_to = parseaddr(str(msg.get("Reply-To", "")))
    parsed.reply_to_addr = reply_to.lower()
    _, return_path = parseaddr(str(msg.get("Return-Path", "")))
    parsed.return_path = return_path.lower()
    parsed.to_addrs = [a.lower() for _, a in getaddresses([str(msg.get("To", ""))]) if a]
    parsed.message_id = str(msg.get("Message-ID", "")).strip()
    parsed.date = str(msg.get("Date", ""))
    parsed.received = [str(h) for h in (msg.get_all("Received") or [])]
    parsed.origin_ip = _origin_ip(parsed.received)
    parsed.auth_results = _parse_auth_results(msg, parsed.received)
    parsed.has_list_unsubscribe = msg.get("List-Unsubscribe") is not None

    _walk_bodies(msg, parsed)
    _walk_attachments(msg, parsed)
    return parsed
