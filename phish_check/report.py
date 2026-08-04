"""Stage 6: render the analysis as a rich terminal report or JSON."""

from __future__ import annotations

import json

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .defang import defang, defang_text, strip_controls
from .models import Report, severity_rank

VERDICT_STYLES = {
    "malicious": "bold white on red",
    "suspicious": "bold black on yellow",
    "inconclusive": "bold white on grey37",
    "benign": "bold white on green",
}
SEVERITY_STYLES = {"high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}


def _defang_any(value: str, type_by_value: dict[str, str]) -> str:
    """Defang a value whose IOC type is known from the indicator list when
    possible, by shape otherwise."""
    ioc_type = type_by_value.get(value)
    if ioc_type:
        return defang(value, ioc_type)
    if "://" in value or value.lower().startswith("www."):
        return defang(value, "url")
    if "@" in value:
        return defang(value, "email")
    if "." in value and " " not in value:
        # Bare domain or scheme-less URL-with-path (meta-refresh "evil.com/x")
        # — defanging the dots neutralizes both.
        return defang(value, "domain")
    return defang_text(value)


def _safe_text(text: str) -> str:
    return defang_text(strip_controls(text))


def _defang_labels(values: list[str], limit: int) -> str:
    """Defang a list of CC-echoed labels (tags, warninglists) for terminal
    display — the same treatment render_json's _defang_enrichment applies."""
    return ", ".join(_defang_any(_safe_text(v), {}) for v in values[:limit])


def _defang_feed_hits(hits: list[dict]) -> None:
    for hit in hits:
        hit["name"] = _safe_text(hit["name"])
        hit["provider"] = _safe_text(hit["provider"])
        if hit.get("url"):
            hit["url"] = defang(strip_controls(hit["url"]), "url")


def _defang_enrichment(enr: dict) -> None:
    """Defang an IndicatorEnrichment dict in place — feed URLs, tags, and
    threat fields are CC-response text and can carry live IOCs."""
    _defang_feed_hits(enr.get("feed_hits", []))
    for key in ("tags", "actors", "malware", "warninglists"):
        # _defang_any on top of _safe_text: tags like "domain:evil.com" are
        # bare-domain-shaped, which prose defanging deliberately leaves alone.
        enr[key] = [_defang_any(_safe_text(v), {}) for v in enr.get(key, [])]
    for key in ("threat_verdict", "first_seen", "last_seen"):
        if enr.get(key):
            enr[key] = _safe_text(enr[key])


def render_json(report: Report) -> str:
    # All indicator values are defanged in both output formats — the JSON
    # report must be as safe to paste into a ticket or chat as the terminal
    # one, so every field that can carry a live IOC is defanged here.
    d = report.to_dict()
    types = {i.value: i.type for i in report.indicators}
    for ind in d["indicators"]:
        ind["value"] = defang(ind["value"], ind["type"])
        if ind.get("display_text"):
            ind["display_text"] = _safe_text(ind["display_text"])
        if ind.get("unwrapped_from"):
            ind["unwrapped_from"] = defang(ind["unwrapped_from"], "url")
        if ind.get("enrichment"):  # None for every indicator in --no-enrich runs
            _defang_enrichment(ind["enrichment"])
    meta = d["enrichment"]
    _defang_feed_hits(meta.get("portfolio_feed_hits", []))
    # Build-time defang covers enrich.py's own errors, but cli.py's fallback
    # stores raw exception text; _safe_text is idempotent on defanged text.
    meta["errors"] = [_safe_text(e) for e in meta.get("errors", [])]
    # LLM-authored text can echo live IOCs straight out of the (raw) body.
    v = d["verdict"]
    v["summary"] = _safe_text(v["summary"])
    for r in v["reasons"]:
        r["explanation"] = _safe_text(r["explanation"])
    v["recommended_actions"] = [_safe_text(a) for a in v["recommended_actions"]]
    for ev in d["evidence"]:
        if ev.get("indicator"):
            ev["indicator"] = _defang_any(ev["indicator"], types)
        if ev.get("untrusted_detail"):
            ev["untrusted_detail"] = _safe_text(ev["untrusted_detail"])
    em = d["email"]
    # The authserv-id is whatever the message claimed; it is a hostname, so it
    # can carry a live domain into the JSON report.
    if em.get("auth_results", {}).get("authserv_id"):
        em["auth_results"]["authserv_id"] = defang(em["auth_results"]["authserv_id"], "domain")
    for key in ("from_addr", "reply_to_addr", "return_path"):
        if em.get(key):
            em[key] = defang(em[key], "email")
    em["to_addrs"] = [defang(a, "email") for a in em.get("to_addrs", [])]
    if em.get("origin_ip"):
        em["origin_ip"] = defang(em["origin_ip"], "ip")
    # Every free-text header that survives into the report. `date` is as
    # attacker-authored as `subject` — nothing validates it — and a URL in it
    # would otherwise arrive fanged and clickable in --json.
    for key in ("from_display", "subject", "message_id", "date"):
        if em.get(key):
            em[key] = _safe_text(em[key])
    for att in em.get("attachments", []):
        # content_type is a header value too, not a validated MIME type.
        att["filename"] = _safe_text(att["filename"])
        att["content_type"] = _safe_text(att["content_type"])
    html = em.get("html", {})
    html["hidden_texts"] = [_safe_text(t) for t in html.get("hidden_texts", [])]
    html["form_actions"] = [defang(u, "url") for u in html.get("form_actions", [])]
    for link in html.get("links", []):
        link["href"] = defang(link["href"], "url")
        if link.get("text"):
            link["text"] = _safe_text(link["text"])
    return json.dumps(d, indent=2, default=str)


def _auth_line(report: Report) -> Text:
    auth = report.email.auth_results
    t = Text()
    for name, val in (("SPF", auth.spf), ("DKIM", auth.dkim), ("DMARC", auth.dmarc)):
        val = val or "n/a"
        style = "green" if val == "pass" else ("red" if val == "fail" else "yellow")
        t.append(f"{name} ", style="bold")
        t.append(val, style=style)
        t.append("   ")
    if report.email.from_addr:
        t.append(
            f"From: {_safe_text(report.email.from_display)} "
            f"<{defang(report.email.from_addr, 'email')}>"
        )
    return t


def _evidence_table(report: Report) -> Table:
    table = Table(show_header=False, box=None, padding=(0, 1))
    table.add_column("id", style="bold", no_wrap=True)
    table.add_column("sev", no_wrap=True)
    table.add_column("desc", overflow="fold")
    ordered = sorted(report.evidence, key=lambda e: -severity_rank(e.severity))
    for ev in ordered:
        # Text(): defanged [.]/[@] must not parse as markup; strip_controls():
        # ESC/bidi chars from email content must not reach the terminal.
        desc = Text(strip_controls(ev.description))
        if ev.untrusted_detail:
            # Attacker-authored text kept out of the description (and out of the
            # judge's prompt) but still worth showing the analyst. Already
            # defanged and bounded at build time; strip_controls is idempotent.
            desc.append("\n" + strip_controls(ev.untrusted_detail), style="dim")
        table.add_row(
            ev.id,
            Text(f"[{ev.severity}]", style=SEVERITY_STYLES.get(ev.severity, "")),
            desc,
        )
    return table


def _indicator_table(report: Report) -> Table:
    table = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 1))
    table.add_column("type", no_wrap=True)
    table.add_column("indicator (defanged)", overflow="fold")
    table.add_column("crimson crawler", overflow="fold")
    shown = [i for i in report.indicators if not i.noise]
    for ind in shown:
        e = ind.enrichment
        # CC-echoed free text (feed names, tags, verdict, warninglists) can carry
        # live IOCs — defang it here exactly as render_json's _defang_enrichment
        # does, so the default terminal output is as safe to paste as --json.
        if e and e.feed_hits:
            cc = Text(
                " · ".join(
                    _safe_text(h.name) + (f" ({_safe_text(h.provider)})" if h.provider else "")
                    for h in e.feed_hits
                ),
                style="red",
            )
            extras = []
            if e.tags:
                extras.append("tags: " + _defang_labels(e.tags, 4))
            if e.last_seen:
                extras.append(f"last seen {_safe_text(e.last_seen)}")
            if e.threat_verdict:
                extras.append(f"CC verdict: {_safe_text(e.threat_verdict.replace('_', ' '))}")
            if extras:
                cc.append("\n" + "  ·  ".join(extras), style="dim")
        elif e and e.misp_matched and not e.on_warninglist:
            cc = Text("MISP event match", style="red")
            if e.tags:
                cc.append("\ntags: " + _defang_labels(e.tags, 4), style="dim")
            if e.threat_verdict:
                cc.append(
                    "\nCC verdict: " + _safe_text(e.threat_verdict.replace("_", " ")), style="dim"
                )
        elif e and e.on_warninglist:
            cc = Text("warninglist: " + _defang_labels(e.warninglists, 2), style="dim")
        elif report.enrichment.enabled and report.enrichment.api_calls:
            cc = Text("no feed hits", style="dim")
        else:
            cc = Text("—", style="dim")
        table.add_row(ind.type, Text(strip_controls(defang(ind.value, ind.type))), cc)
    hidden = len(report.indicators) - len(shown)
    if hidden:
        note = f"(+{hidden} low-priority infrastructure indicators, --json shows all)"
        table.add_row("", Text(note, style="dim"), "")
    return table


def render_terminal(report: Report, console: Console | None = None) -> None:
    console = console or Console()
    v = report.verdict

    parts: list = []
    verdict_text = Text()
    verdict_text.append(f" {v.verdict.upper()} ", style=VERDICT_STYLES.get(v.verdict, "bold"))
    verdict_text.append(f"  confidence {v.confidence:.2f}")
    verdict_text.append(f"  ·  {v.source} verdict", style="dim")
    parts.append(verdict_text)
    # _safe_text, not just strip_controls: LLM prose can echo live IOCs from
    # the raw body — defang in the terminal exactly like in --json.
    parts.append(Text(_safe_text(v.summary), style="italic"))

    if v.reasons:
        reasons = Table(show_header=False, box=None, padding=(0, 1))
        reasons.add_column("id", style="bold", no_wrap=True)
        reasons.add_column("why", overflow="fold")
        for r in v.reasons:
            reasons.add_row(f"{r.evidence_id} ({r.weight})", Text(_safe_text(r.explanation)))
        parts.append(Text("\nWhy:", style="bold"))
        parts.append(reasons)

    if v.recommended_actions:
        parts.append(Text("\nRecommended:", style="bold"))
        for action in v.recommended_actions:
            parts.append(Text(f"  • {_safe_text(action)}"))

    console.print(Panel(Group(*parts), title="phish-check report", title_align="left"))

    console.print(Panel(_auth_line(report), title="authentication", title_align="left"))
    if report.evidence:
        console.print(
            Panel(
                _evidence_table(report),
                title=f"evidence ({len(report.evidence)})",
                title_align="left",
            )
        )
    if report.indicators:
        console.print(
            Panel(
                _indicator_table(report),
                title=f"indicators ({len(report.indicators)})",
                title_align="left",
            )
        )

    meta = report.enrichment
    if meta.enabled:
        line = (
            f"Enriched by Crimson Crawler · {meta.api_calls} API call(s) · "
            f"{meta.indicators_submitted} indicators submitted"
        )
        if meta.portfolio_feed_hits:
            line += f" · {len(meta.portfolio_feed_hits)} feed correlation(s)"
        if meta.indicators_truncated:
            line += f" · {meta.indicators_truncated} truncated (batch cap 50)"
        if meta.errors:
            line += f" · [red]{len(meta.errors)} error(s)[/red]"
        console.print(Text.from_markup(f"[dim]{line} · crimsoncrawler.com[/dim]"))
    elif meta.disabled_by_flag:
        console.print("[dim]Enrichment skipped (--no-enrich).[/dim]")
    else:
        console.print(
            "[dim]Enrichment skipped — set CRIMSON_CRAWLER_API_KEY for threat-feed citations. "
            "Free keys at [/dim][link=https://crimsoncrawler.com]crimsoncrawler.com[/link]"
        )
    for err in meta.errors:
        # _safe_text, not just strip_controls: cli.py's enrichment fallback
        # stores raw exception text, and httpx exception strings carry the
        # request URL. The default terminal report must be as safe to paste as
        # --json, which has always defanged this field.
        # Text(): defanged [.]/[@] must not parse as rich markup.
        warning = Text("enrichment warning: ", style="red")
        warning.append(_safe_text(err))
        console.print(warning)
