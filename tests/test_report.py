from phish_check.defang import defang_text
from phish_check.report import _defang_any


def test_defang_any_schemeless_url_with_path():
    # meta-refresh evidence carries "evil.com/login" — no scheme, not in the
    # indicator type map; it must still come out non-clickable.
    assert _defang_any("evil.com/login", {}) == "evil[.]com/login"


def test_defang_any_prefers_known_type():
    types = {"https://evil.example/x": "url"}
    assert _defang_any("https://evil.example/x", types) == "hxxps://evil[.]example/x"


def test_defang_any_hash_passthrough():
    sha = "a" * 64
    assert _defang_any(sha, {sha: "sha256"}) == sha


def test_defang_text_covers_bare_ips():
    # CC summaries / auth text can name bare IPs — prose defanging must
    # neutralize them, not just URL/email shapes.
    assert defang_text("client-ip=192.88.99.66 rejected") == "client-ip=192[.]88[.]99[.]66 rejected"
    # ...without mangling short dotted version strings.
    assert defang_text("released in v1.2") == "released in v1.2"


def test_render_json_defangs_enrichment_fields():
    import json

    from phish_check.models import (
        EnrichmentMeta,
        FeedHit,
        Indicator,
        IndicatorEnrichment,
        ParsedEmail,
        Report,
        Verdict,
    )
    from phish_check.report import render_json

    enr = IndicatorEnrichment(
        misp_matched=True,
        feed_hits=[
            FeedHit(name="URLhaus", provider="abuse.ch", url="https://urlhaus.abuse.ch/url/12345/")
        ],
        tags=["domain:evil.example", "phishing"],
        actors=["APT\x1b[2Jevil"],
        malware=["dropper via http://payload.example/x"],
        threat_verdict="bad — see http://evil.example/w",
        first_seen="2026-07-01",
    )
    report = Report(
        email=ParsedEmail(),
        indicators=[
            Indicator(
                value="https://evil.example/x", type="url", source="body-html", enrichment=enr
            )
        ],
        evidence=[],
        verdict=Verdict(verdict="malicious", confidence=0.9, summary="s"),
        enrichment=EnrichmentMeta(
            enabled=True,
            api_calls=1,
            portfolio_feed_hits=[FeedHit(name="IPsum", url="https://raw.example/ipsum.txt")],
            errors=["fallback: connect to http://evil.example failed"],
        ),
    )
    out = render_json(report)
    # No live URL/domain anywhere in the JSON, no control chars either.
    assert "https://" not in out and "http://" not in out
    assert "evil.example" not in out.replace("evil[.]example", "")
    assert "\x1b" not in out
    # The data is still present, defanged.
    parsed = json.loads(out)
    ind = parsed["indicators"][0]
    assert ind["enrichment"]["feed_hits"][0]["url"] == "hxxps://urlhaus[.]abuse[.]ch/url/12345/"
    assert "domain:evil[.]example" in ind["enrichment"]["tags"]
    assert (
        parsed["enrichment"]["portfolio_feed_hits"][0]["url"] == "hxxps://raw[.]example/ipsum[.]txt"
    )
    assert "hxxp://evil[.]example" in parsed["enrichment"]["errors"][0]


def test_render_json_without_enrichment_still_works():
    # --no-enrich runs leave every Indicator.enrichment as None; render_json
    # must not assume the dict exists.
    from phish_check.models import EnrichmentMeta, Indicator, ParsedEmail, Report, Verdict
    from phish_check.report import render_json

    report = Report(
        email=ParsedEmail(),
        indicators=[Indicator(value="https://x.example/a", type="url", source="body-html")],
        evidence=[],
        verdict=Verdict(verdict="benign", confidence=0.5, summary="s"),
        enrichment=EnrichmentMeta(),
    )
    assert "hxxps://x[.]example/a" in render_json(report)


def test_verdict_text_is_defanged_in_both_renderers():
    # LLM prose can echo live IOCs straight out of the raw body — both output
    # formats must neutralize them.
    from rich.console import Console

    from phish_check.models import EnrichmentMeta, ParsedEmail, Reason, Report, Verdict
    from phish_check.report import render_json, render_terminal

    report = Report(
        email=ParsedEmail(),
        indicators=[],
        evidence=[],
        verdict=Verdict(
            verdict="malicious",
            confidence=0.9,
            summary="Credential lure pointing at https://evil.example/login.",
            reasons=[
                Reason(
                    evidence_id="E1",
                    weight="high",
                    explanation="link to https://evil.example/login",
                )
            ],
            recommended_actions=["Do not visit https://evil.example/login"],
            source="llm",
        ),
        enrichment=EnrichmentMeta(),
    )
    out = render_json(report)
    assert "https://evil.example" not in out
    assert out.count("hxxps://evil[.]example/login") == 3

    console = Console(record=True, width=100)
    render_terminal(report, console=console)
    text = console.export_text()
    assert "https://evil.example" not in text
    assert "hxxps://evil[.]example/login" in text


def test_terminal_defangs_enrichment_fields():
    # Regression: CC-echoed feed names, tags, verdict, and last_seen were
    # defanged in --json but rendered live in the default terminal output.
    import io

    from rich.console import Console

    from phish_check.models import (
        EnrichmentMeta,
        FeedHit,
        Indicator,
        IndicatorEnrichment,
        ParsedEmail,
        Report,
        Verdict,
    )
    from phish_check.report import render_terminal

    enr = IndicatorEnrichment(
        feed_hits=[FeedHit(name="see https://evil.example/feed", provider="corp.badnet")],
        tags=["url:https://evil2.example/x", "domain:bad.example"],
        threat_verdict="malicious http://c2.evil.example",
        last_seen="2026-07-05 see http://evil3.example/",
    )
    report = Report(
        email=ParsedEmail(),
        indicators=[
            Indicator(value="bad.example", type="domain", source="body-text", enrichment=enr)
        ],
        evidence=[],
        verdict=Verdict(verdict="malicious", confidence=0.9, summary="s"),
        enrichment=EnrichmentMeta(enabled=True, api_calls=1),
    )
    buf = io.StringIO()
    render_terminal(report, Console(file=buf, width=200, force_terminal=False))
    out = buf.getvalue()
    assert "https://" not in out and "http://" not in out
    assert "evil.example" not in out.replace("evil[.]example", "")


LIVE = "https://payload.example/verify?id=1"


def _string_leaves(node, path="$"):
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from _string_leaves(value, f"{path}.{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from _string_leaves(value, f"{path}[{i}]")


def _crafted_eml() -> bytes:
    # A live URL in every attacker-authored header that survives into the report.
    return (
        b"Received: from sender.example (sender.example [192.88.99.66])\n"
        b"\tby mx.corp.example (Postfix) with ESMTP id ABC123\n"
        b"\tfor <bob@corp.example>; Mon, 6 Jul 2026 10:00:00 +0000\n"
        b"Authentication-Results: mx.attacker.example; spf=fail; dmarc=fail\n"
        b'From: "Support ' + LIVE.encode() + b'" <alerts@sender.example>\n'
        b"Reply-To: billing@freemail-lookalike.example\n"
        b"Return-Path: <bounce@bounce.example>\n"
        b"Subject: Action required " + LIVE.encode() + b"\n"
        b"Message-ID: <" + LIVE.encode() + b">\n"
        # An unparseable Date survives verbatim: policy=default normalizes a
        # valid one, so a crafted header is the only shape that reaches output.
        b"Date: 32 Foo 2026 99:99:99 " + LIVE.encode() + b"\n"
        b"MIME-Version: 1.0\n"
        b'Content-Type: multipart/mixed; boundary="B"\n\n'
        b"--B\n"
        b'Content-Type: text/html; charset="utf-8"\n\n'
        b'<html><body><a href="' + LIVE.encode() + b'">click</a>'
        b'<div style="display:none">' + LIVE.encode() + b"</div>"
        b'<form action="' + LIVE.encode() + b'"><input name="pw"></form>'
        b"</body></html>\n"
        b"--B\n"
        b"Content-Type: application/payload.example\n"
        b'Content-Disposition: attachment; filename="invoice.' + LIVE.encode() + b'.exe"\n'
        b"Content-Transfer-Encoding: base64\n\nTVqQAA==\n"
        b"--B--\n"
    )


def test_no_serialized_json_field_is_left_fanged():
    # The audit's "audit all serialized string leaves centrally": rather than
    # naming the fields that were missed (date, attachment content_type), assert
    # the property itself over every string in the document. defang_text is
    # idempotent, so "already defanged" means it changes nothing.
    import json

    from phish_check.defang import strip_controls
    from phish_check.extract import extract_indicators
    from phish_check.judge import rules_verdict
    from phish_check.models import EnrichmentMeta, Report
    from phish_check.parser import parse_email
    from phish_check.report import render_json

    email = parse_email(_crafted_eml())
    indicators = extract_indicators(email)
    from phish_check.signals import run_signals

    evidence = run_signals(email, indicators)
    report = Report(
        email=email,
        indicators=indicators,
        evidence=evidence,
        verdict=rules_verdict(evidence),
        enrichment=EnrichmentMeta(enabled=True, errors=[f"connect failed to {LIVE}"]),
    )
    raw = render_json(report)
    assert "payload.example" in raw  # the IOC is reported, just not clickable
    assert "https://payload.example" not in raw
    for path, leaf in _string_leaves(json.loads(raw)):
        assert defang_text(leaf) == leaf, f"{path} is fanged: {leaf!r}"
        assert strip_controls(leaf) == leaf, f"{path} carries control characters: {leaf!r}"


def test_terminal_enrichment_errors_are_defanged(capsys):
    # --json has always defanged enrichment errors; the default terminal path
    # only stripped controls, so the weaker output was the default one.
    from phish_check.judge import rules_verdict
    from phish_check.models import EnrichmentMeta, ParsedEmail, Report
    from phish_check.report import render_terminal

    report = Report(
        email=ParsedEmail(),
        indicators=[],
        evidence=[],
        verdict=rules_verdict([]),
        enrichment=EnrichmentMeta(enabled=True, errors=[f"portfolio assessment failed: {LIVE}"]),
    )
    render_terminal(report)
    out = capsys.readouterr().out
    assert "enrichment warning" in out
    assert "https://payload.example" not in out
    assert "payload[.]example" in out
