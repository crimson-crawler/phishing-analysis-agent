"""phish-check CLI: paste a suspicious email, get "phishy or not, and here's why"."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from dotenv import dotenv_values
from rich.console import Console
from rich.text import Text

from . import __version__
from .defang import strip_controls
from .endpoints import safe_display_url
from .extract import extract_indicators
from .judge import DEFAULT_MODEL, llm_verdict, rules_verdict
from .models import EnrichmentMeta, Report
from .parser import parse_email
from .report import render_json, render_terminal
from .signals import run_signals

# A whole email is read into memory, so an absurdly large input would exhaust it
# before parsing ever reports a problem. Read one byte past the cap to tell
# "exactly at the limit" from "over it", and fail in the error range.
MAX_INPUT_BYTES = 64 * 1024 * 1024

EXIT_BENIGN = 0
EXIT_SUSPICIOUS = 1
EXIT_MALICIOUS = 2
EXIT_ERROR = 10

_VERDICT_EXIT = {
    "benign": EXIT_BENIGN,
    "inconclusive": EXIT_BENIGN,
    "suspicious": EXIT_SUSPICIOUS,
    "malicious": EXIT_MALICIOUS,
}

# The only names ./.env may set. Everything else it contains is ignored — see
# _load_local_dotenv().
_DOTENV_ALLOWED = ("CRIMSON_CRAWLER_API_KEY", "OPENAI_API_KEY")

# Where the API keys travel. A .env may supply the keys themselves — that is what
# the auto-load is for — but never these: see _load_local_dotenv().
_ENDPOINT_VARS = ("CRIMSON_CRAWLER_BASE_URL", "OPENAI_BASE_URL")


class _Console(Console):
    def on_broken_pipe(self) -> None:
        # rich's default raises SystemExit(1) — which this tool's contract
        # reads as "suspicious". Convert back to BrokenPipeError so main()'s
        # quiet-exit handler decides the exit code.
        self.quiet = True
        raise BrokenPipeError


class _ArgumentParser(argparse.ArgumentParser):
    """argparse exits 2 on usage errors — which this tool's contract defines
    as "malicious". Remap to the error range so a typo'd flag can't read as
    "quarantine this email" to a calling script."""

    def error(self, message: str):
        self.print_usage(sys.stderr)
        self.exit(EXIT_ERROR, f"{self.prog}: error: {message}\n")


def _nonneg_int(value: str) -> int:
    n = int(value)
    if n < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return n


def _build_parser() -> argparse.ArgumentParser:
    p = _ArgumentParser(
        prog="phish-check",
        description="Analyze a suspicious email (.eml or pasted headers+body) for phishing: "
        "extract & defang IOCs, enrich via Crimson Crawler, LLM verdict with citations.",
        epilog="Env vars (auto-loaded from ./.env if present): "
        "CRIMSON_CRAWLER_API_KEY (free key: crimsoncrawler.com), "
        "OPENAI_API_KEY, CRIMSON_CRAWLER_BASE_URL. "
        "Exit codes: 0 benign/inconclusive, 1 suspicious, 2 malicious, >=10 error.",
    )
    p.add_argument("eml", nargs="?", help=".eml file to analyze (default: read stdin)")
    p.add_argument("--json", action="store_true", help="emit the full report as JSON")
    p.add_argument("--no-llm", action="store_true", help="skip the LLM verdict (rule-based only)")
    p.add_argument("--no-enrich", action="store_true", help="skip Crimson Crawler enrichment")
    p.add_argument(
        "--deep",
        type=_nonneg_int,
        default=0,
        metavar="N",
        help="per-IOC deep enrichment for the top N suspects (extra API calls)",
    )
    p.add_argument("--model", default=DEFAULT_MODEL, help=f"OpenAI model (default {DEFAULT_MODEL})")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _fail(message: str, console: Console, as_json: bool) -> int:
    # Messages interpolate filenames/exception text: neutralize control chars,
    # and Text() so nothing parses as rich markup.
    message = strip_controls(message)
    if as_json:
        print(json.dumps({"error": message}))
    console.print(Text(f"error: {message}", style="red"))
    return EXIT_ERROR


def _load_local_dotenv(console: Console) -> None:
    """Take the two API keys from ./.env, and nothing else from it.

    Keys usually live in ./.env during development — read it so users don't have
    to source it by hand. Deliberately NOT find_dotenv(): that walks *upward* to
    the filesystem root, so running the tool inside an extracted archive or a
    cloned repo could load a .env someone else authored. Only the invocation
    directory's own .env is consulted, and a variable already in the environment
    always wins.

    That still leaves the archive's *own* .env, which the victim reaches just by
    cd-ing into it. `.env` is therefore treated as attacker-supplied data, and
    dotenv_values() parses it *without* touching os.environ so nothing in it
    takes effect by default. Only `_DOTENV_ALLOWED` is copied across, because
    other names in that file are a credential-exfiltration path in two ways:

    - `*_BASE_URL` would send real keys to the attacker's host, and the
      https/loopback gate in `endpoints.py` doesn't help — an attacker can serve
      https. An endpoint override is accepted only from the real environment,
      where a person had to type it.
    - httpx (and the OpenAI SDK on top of it) trusts the environment for proxy
      and TLS settings, so `HTTPS_PROXY` plus `SSL_CERT_FILE` pointing at a CA
      bundle shipped in the same archive is a complete interception of both API
      calls, with the destination still looking like the real https endpoint.
      An allowlist closes that whole class rather than naming the vars of the
      day, so a future httpx or SDK setting cannot reopen it.
    """
    try:
        values = dotenv_values(Path.cwd() / ".env")
    except OSError:  # unreadable .env is not an error — the keys may be exported
        return
    ignored = []
    for var, value in values.items():
        if value is None:
            continue
        if var in _DOTENV_ALLOWED:
            os.environ.setdefault(var, value)  # the real environment wins
        else:
            ignored.append(var)
    for var in ignored:
        if var in _ENDPOINT_VARS:
            console.print(
                Text(
                    f"note: ignoring {var} from ./.env — an endpoint override must "
                    "come from the environment, not a file",
                    style="yellow",
                )
            )
    # Named, not silent: someone who put HTTPS_PROXY in ./.env needs to know it
    # had no effect. Bounded, because .env is attacker-authored here.
    other = sorted(v for v in ignored if v not in _ENDPOINT_VARS)
    if other:
        names = ", ".join(strip_controls(v)[:40] for v in other[:5])
        if len(other) > 5:
            names += f", and {len(other) - 5} more"
        console.print(
            Text(
                f"note: ignoring {names} from ./.env — only "
                + " and ".join(_DOTENV_ALLOWED)
                + " are read from a file",
                style="yellow",
            )
        )


def run(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    console = _Console(stderr=True)
    _load_local_dotenv(console)
    try:
        return _analyze(args, console)
    except BrokenPipeError:
        raise  # main() handles this quietly — printing again would re-raise
    except Exception as exc:  # contract: errors exit >=10, never 1/2
        return _fail(f"unexpected failure: {exc}", console, args.json)


def _warn_redirected_endpoints(console: Console) -> None:
    """A non-default API endpoint means credentials leave for somewhere other
    than the documented service. That is a legitimate thing to want (local mock,
    corporate gateway) but it must never be silent — a shell profile or CI config
    can set it just as easily as the person at the keyboard."""
    for var in _ENDPOINT_VARS:
        value = os.environ.get(var)
        if value:
            # Redacted: a gateway URL can carry credentials in its userinfo or
            # query string, and this line goes to stderr — i.e. into CI logs.
            console.print(
                Text(
                    f"note: {var} is set — API calls go to {safe_display_url(value)}",
                    style="yellow",
                )
            )


def _analyze(args: argparse.Namespace, console: Console) -> int:
    if args.eml:
        try:
            with open(args.eml, "rb") as fh:
                raw = fh.read(MAX_INPUT_BYTES + 1)
        except OSError as exc:
            return _fail(f"cannot read {args.eml}: {exc}", console, args.json)
    else:
        if sys.stdin.isatty():
            console.print("Paste the email (headers+body or raw .eml), then Ctrl-D:")
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        return _fail(
            f"input larger than {MAX_INPUT_BYTES // (1024 * 1024)} MiB — refusing to parse",
            console,
            args.json,
        )
    if not raw.strip():
        return _fail("empty input", console, args.json)

    _warn_redirected_endpoints(console)

    email = parse_email(raw)
    indicators = extract_indicators(email)
    evidence = run_signals(email, indicators)

    cc_key = os.environ.get("CRIMSON_CRAWLER_API_KEY", "")
    meta = EnrichmentMeta(enabled=False, disabled_by_flag=args.no_enrich)
    if not args.no_enrich and cc_key:
        from .enrich import enrich  # deferred so offline runs never import httpx paths

        try:
            # status(): transient spinner on stderr — animates on a terminal,
            # erased once done, emits nothing when piped/redirected.
            with console.status(f"Enriching {len(indicators)} indicator(s) via Crimson Crawler..."):
                new_evidence, meta = enrich(indicators, evidence, cc_key, deep=args.deep)
            evidence.extend(new_evidence)
        except Exception as exc:  # enrichment is best-effort; analysis continues
            meta = EnrichmentMeta(enabled=True, errors=[str(exc)])

    openai_key = os.environ.get("OPENAI_API_KEY", "")
    if args.no_llm or not openai_key:
        verdict = rules_verdict(evidence)
        if not args.no_llm and not openai_key:
            console.print("[dim]OPENAI_API_KEY not set — using rule-based verdict.[/dim]")
    else:
        try:
            with console.status(f"Weighing the evidence with {args.model}..."):
                verdict = llm_verdict(
                    email, indicators, evidence, model=args.model, api_key=openai_key
                )
        except Exception as exc:
            # Text(): API error strings can contain bracketed markup-lookalikes.
            console.print(
                Text(f"LLM verdict failed ({exc}); falling back to rules.", style="yellow")
            )
            verdict = rules_verdict(evidence)

    report = Report(
        email=email, indicators=indicators, evidence=evidence, verdict=verdict, enrichment=meta
    )
    if args.json:
        print(render_json(report))
    else:
        render_terminal(report, _Console())
    return _VERDICT_EXIT.get(verdict.verdict, EXIT_ERROR)


def main() -> None:
    try:
        sys.exit(run())
    except BrokenPipeError:
        # Output piped to something like `head` that exited early; the verdict
        # exit code is unrecoverable at this point, so just leave quietly.
        # Point stdout at devnull first (python.org signal-handling recipe):
        # the interpreter flushes stdout at shutdown, and a second
        # BrokenPipeError there would override the exit code.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(EXIT_ERROR + 1)


if __name__ == "__main__":
    main()
