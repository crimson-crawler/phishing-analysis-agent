import json

import pytest

from phish_check.endpoints import checked_base_url, safe_display_url

SECRET = "s3cr3t-gateway-token"


def test_https_and_loopback_are_accepted():
    for url in (
        "https://crimsoncrawler.com",
        "https://gateway.corp.example/cc/v1",
        "http://localhost:8080",
        "http://127.0.0.1:8080/v1",
    ):
        assert checked_base_url(url, "CRIMSON_CRAWLER_BASE_URL") == url


def test_userinfo_is_refused_and_never_echoed():
    # An API key travels in a header, so URL userinfo has no legitimate use here
    # — and the value is printed by the redirect warning and copied into httpx
    # exception text.
    with pytest.raises(ValueError) as exc:
        checked_base_url(f"https://user:{SECRET}@gateway.corp.example/", "CRIMSON_CRAWLER_BASE_URL")
    assert SECRET not in str(exc.value)
    assert "credentials" in str(exc.value)


def test_query_string_is_refused_and_never_echoed():
    with pytest.raises(ValueError) as exc:
        checked_base_url(f"https://gateway.corp.example/v1?token={SECRET}", "OPENAI_BASE_URL")
    assert SECRET not in str(exc.value)


def test_plaintext_refusal_does_not_echo_a_token():
    # The rejected value itself can carry a credential; the old message
    # interpolated it verbatim into an exception that reaches --json.
    with pytest.raises(ValueError) as exc:
        checked_base_url(f"http://gateway.corp.example/v1#{SECRET}", "CRIMSON_CRAWLER_BASE_URL")
    assert SECRET not in str(exc.value)


def test_safe_display_url_keeps_only_scheme_host_port_path():
    assert (
        safe_display_url(f"https://user:{SECRET}@gateway.corp.example:8443/cc/v1?k={SECRET}")
        == "https://[credentials redacted]@gateway.corp.example:8443/cc/v1?[query redacted]"
    )
    assert safe_display_url("https://mock.example/v1") == "https://mock.example/v1"
    assert safe_display_url("not-a-url") == "(no scheme or host)"
    assert safe_display_url("https://host.example:notaport/") == (
        "https://host.example:[invalid port]/"
    )


def test_credentialed_endpoint_is_not_printed_by_the_cli(capsys, monkeypatch):
    # The warning goes to stderr, which in CI means the build log.
    from pathlib import Path

    from phish_check.cli import run

    monkeypatch.setattr("phish_check.cli.dotenv_values", lambda *a, **k: {})
    monkeypatch.delenv("CRIMSON_CRAWLER_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("CRIMSON_CRAWLER_BASE_URL", f"https://user:{SECRET}@gateway.corp.example/")
    sample = Path(__file__).parent / "samples" / "benign.eml"
    code = run([str(sample), "--json", "--no-llm", "--no-enrich"])
    captured = capsys.readouterr()
    assert code == 0
    assert SECRET not in captured.err
    assert SECRET not in captured.out
    assert "gateway.corp.example" in captured.err  # the operator still learns where


def test_credentialed_endpoint_error_is_redacted_in_json(capsys, monkeypatch):
    # With a key set, enrichment builds the client, the gate raises, and the
    # message lands in enrichment.errors — which --json prints.
    from pathlib import Path

    from phish_check.cli import run

    monkeypatch.setattr("phish_check.cli.dotenv_values", lambda *a, **k: {})
    monkeypatch.setenv("CRIMSON_CRAWLER_API_KEY", "test-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("CRIMSON_CRAWLER_BASE_URL", f"https://user:{SECRET}@gateway.corp.example/")
    sample = Path(__file__).parent / "samples" / "benign.eml"
    run([str(sample), "--json", "--no-llm"])
    out = capsys.readouterr()
    assert SECRET not in out.out
    assert SECRET not in out.err
    report = json.loads(out.out)
    assert report["enrichment"]["errors"]  # the failure is still reported
