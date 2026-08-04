"""Shared endpoint validation: never attach an API key to a plaintext endpoint.

Both API base URLs can come from the environment — and therefore from a `.env`
in the invocation directory — so an unvalidated one is a credential-exfiltration
path: the key would go wherever it points, in the clear. This module is the one
place that decides which endpoints a key may travel to, so the Crimson Crawler
and OpenAI paths cannot drift apart.

Deliberately dependency-free (stdlib only): `judge.py` imports it, and `judge`
is imported eagerly by `cli.py`, so pulling `httpx` in here would break the
"an offline run never imports the network paths" property.
"""

from __future__ import annotations

from urllib.parse import urlparse

# Plaintext is tolerated only where the connection cannot leave the host, which
# keeps local mock servers usable for development.
LOOPBACK_HOSTS = ("localhost", "127.0.0.1", "::1")


def safe_display_url(base_url: str) -> str:
    """The parts of a base URL that are safe to print.

    A configured endpoint reaches stderr (the redirect warning), exception text
    and `--json` error output, and the README encourages pasting that into a
    ticket. Userinfo and query strings can carry gateway credentials, so
    diagnostics get scheme, host, port and path only.
    """
    try:
        parsed = urlparse(base_url)
    except ValueError:
        return "(unparseable URL)"
    if not parsed.scheme or not parsed.netloc:
        return "(no scheme or host)"
    netloc = parsed.hostname or ""
    if parsed.password or parsed.username:
        netloc = f"[credentials redacted]@{netloc}"
    try:
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
    except ValueError:  # non-numeric port
        netloc = f"{netloc}:[invalid port]"
    shown = f"{parsed.scheme}://{netloc}{parsed.path}"
    return shown + ("?[query redacted]" if parsed.query else "")


def checked_base_url(base_url: str, var_name: str) -> str:
    """Return `base_url` if a key may be sent there; raise ValueError otherwise.

    `var_name` is the environment variable the value came from, so the refusal
    message tells the user which setting to fix.
    """
    parsed = urlparse(base_url)
    if parsed.username or parsed.password:
        # An API key travels in a header here, so URL userinfo has no legitimate
        # use — and it would be printed by the redirect warning and copied into
        # httpx exception text. Refuse rather than carry a credential around.
        raise ValueError(
            f"refusing to use {safe_display_url(base_url)}: {var_name} must not "
            "embed credentials in the URL"
        )
    if parsed.query or parsed.fragment:
        # httpx keeps a base_url query and appends the request path *after* it
        # ("…/v1?token=X/v1/assess/…"), so a token there both breaks every
        # request and travels into exception text that reaches --json output.
        raise ValueError(
            f"refusing to use {safe_display_url(base_url)}: {var_name} must not "
            "carry a query string or fragment"
        )
    if parsed.scheme == "https":
        return base_url
    if parsed.scheme == "http" and (parsed.hostname or "") in LOOPBACK_HOSTS:
        return base_url
    # Redacted, never verbatim: the rejected value can itself carry a token in
    # its query string, and this message reaches stderr and --json.
    raise ValueError(
        f"refusing to send the API key to {safe_display_url(base_url)}: {var_name} must be "
        "https (http is allowed only for localhost)"
    )
