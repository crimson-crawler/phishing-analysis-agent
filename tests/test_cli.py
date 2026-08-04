import json
from pathlib import Path

import pytest

from phish_check.cli import run

SAMPLES = Path(__file__).parent / "samples"


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.delenv("CRIMSON_CRAWLER_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    # run() reads ./.env — the developer's real keys must not leak back into
    # these offline tests (live CC calls burn real API quota).
    monkeypatch.setattr("phish_check.cli.dotenv_values", lambda *a, **k: {})


def test_phishing_offline_json(capsys):
    code = run([str(SAMPLES / "phishing.eml"), "--json", "--no-llm", "--no-enrich"])
    raw_out = capsys.readouterr().out
    out = json.loads(raw_out)
    assert code == 2  # malicious
    assert out["verdict"]["verdict"] == "malicious"
    assert out["verdict"]["source"] == "rules"
    urls = [i["value"] for i in out["indicators"] if i["type"] == "url"]
    assert all(u.startswith("hxxp") for u in urls)
    assert any("micros0ft-support[.]xyz" in u for u in urls)
    # Raw body/HTML is not leaked into the JSON report.
    assert "text_body" not in out["email"]
    # Defanged in both formats. No live IOC anywhere in the JSON —
    # not in evidence[].indicator, links, hidden_texts, or email addresses.
    assert "micros0ft-support.xyz" not in raw_out
    assert "secure-account-check.top" not in raw_out
    assert "https://micros0ft" not in raw_out
    # The raw Authentication-Results header carries live domains/IPs the
    # defang pass can't reach — it must not appear in JSON at all.
    assert "raw" not in out["email"]["auth_results"]


def test_benign_offline(capsys):
    code = run([str(SAMPLES / "benign.eml"), "--json", "--no-llm", "--no-enrich"])
    out = json.loads(capsys.readouterr().out)
    assert code == 0
    assert out["verdict"]["verdict"] == "benign"


def test_terminal_render_smoke(capsys):
    code = run([str(SAMPLES / "phishing.eml"), "--no-llm", "--no-enrich"])
    stdout = capsys.readouterr().out
    assert code == 2
    assert "MALICIOUS" in stdout
    assert "hxxps://" in stdout or "[.]" in stdout  # defanged output only
    assert "micros0ft-support.xyz" not in stdout  # never print fanged IOCs
    assert "[@]" in stdout  # rich must not swallow defang brackets as markup


def test_dotenv_autoloaded_from_cwd(monkeypatch, tmp_path, capsys):
    # Keys in ./.env must work without the user sourcing the file by hand.
    import os

    from dotenv import dotenv_values as real_dotenv_values

    from phish_check.models import EnrichmentMeta

    monkeypatch.setattr("phish_check.cli.dotenv_values", real_dotenv_values)
    (tmp_path / ".env").write_text("CRIMSON_CRAWLER_API_KEY=dummy-key\n")
    monkeypatch.chdir(tmp_path)

    seen = {}

    def fake_enrich(indicators, evidence, key, deep=0):
        seen["key"] = key
        return [], EnrichmentMeta(enabled=True)

    monkeypatch.setattr("phish_check.enrich.enrich", fake_enrich)
    try:
        code = run([str(SAMPLES / "benign.eml"), "--json", "--no-llm"])
        out = json.loads(capsys.readouterr().out)
        assert code == 0
        assert seen["key"] == "dummy-key"
        assert out["enrichment"]["enabled"] is True
    finally:
        # _load_local_dotenv mutated os.environ outside monkeypatch's bookkeeping.
        os.environ.pop("CRIMSON_CRAWLER_API_KEY", None)


def test_parent_directory_dotenv_is_not_loaded(tmp_path, monkeypatch, capsys):
    # find_dotenv() walks upward to the filesystem root; that let a .env in any
    # ancestor directory — an extracted archive, a cloned repo — redirect real
    # API keys to an attacker's host. Only ./.env may be honored.
    import os

    from dotenv import dotenv_values as real_dotenv_values

    monkeypatch.setattr("phish_check.cli.dotenv_values", real_dotenv_values)
    (tmp_path / ".env").write_text("CRIMSON_CRAWLER_BASE_URL=http://attacker.invalid\n")
    workdir = tmp_path / "samples" / "unpacked"
    workdir.mkdir(parents=True)
    monkeypatch.chdir(workdir)
    monkeypatch.delenv("CRIMSON_CRAWLER_BASE_URL", raising=False)
    try:
        code = run([str(SAMPLES / "benign.eml"), "--json", "--no-llm", "--no-enrich"])
        assert code == 0
        assert os.environ.get("CRIMSON_CRAWLER_BASE_URL") is None
        assert "attacker.invalid" not in capsys.readouterr().out
    finally:
        os.environ.pop("CRIMSON_CRAWLER_BASE_URL", None)


def test_dotenv_cannot_redirect_the_endpoint(tmp_path, monkeypatch, capsys):
    # The .env in the *invocation* directory is honored, so unpacking an archive
    # and running the tool from inside it used to be enough to send a real key to
    # the attacker's host — the https gate doesn't help, an attacker can serve
    # https. Keys may come from .env; the endpoint they travel to may not.
    import os

    from dotenv import dotenv_values as real_dotenv_values

    monkeypatch.setattr("phish_check.cli.dotenv_values", real_dotenv_values)
    (tmp_path / ".env").write_text(
        "CRIMSON_CRAWLER_BASE_URL=https://evil.example\n"
        "OPENAI_BASE_URL=https://evil.example/v1\n"
        "CRIMSON_CRAWLER_API_KEY=dummy-key\n"
    )
    monkeypatch.chdir(tmp_path)
    for var in ("CRIMSON_CRAWLER_BASE_URL", "OPENAI_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    try:
        code = run([str(SAMPLES / "benign.eml"), "--json", "--no-llm", "--no-enrich"])
        assert code == 0
        # Dropped, not merely announced: the enrich/judge clients read os.environ.
        assert os.environ.get("CRIMSON_CRAWLER_BASE_URL") is None
        assert os.environ.get("OPENAI_BASE_URL") is None
        # The key itself still loads — that is what the auto-load is for.
        assert os.environ.get("CRIMSON_CRAWLER_API_KEY") == "dummy-key"
        err = capsys.readouterr().err
        assert "ignoring CRIMSON_CRAWLER_BASE_URL from ./.env" in err
        assert "ignoring OPENAI_BASE_URL from ./.env" in err
    finally:
        for var in ("CRIMSON_CRAWLER_BASE_URL", "OPENAI_BASE_URL", "CRIMSON_CRAWLER_API_KEY"):
            os.environ.pop(var, None)


def test_dotenv_cannot_plant_proxy_or_ca_trust_settings(tmp_path, monkeypatch, capsys):
    # httpx trusts the environment for proxy and TLS settings, so a .env in an
    # extracted archive carrying HTTPS_PROXY plus a CA bundle shipped alongside
    # it used to be a complete interception of both API calls — with the
    # destination still looking like the real https endpoint. Only the two API
    # keys may come from a file.
    import os

    from dotenv import dotenv_values as real_dotenv_values

    monkeypatch.setattr("phish_check.cli.dotenv_values", real_dotenv_values)
    (tmp_path / "attacker-ca.pem").write_text("-----BEGIN CERTIFICATE-----\n")
    (tmp_path / ".env").write_text(
        "HTTPS_PROXY=http://attacker.invalid:8080\n"
        "HTTP_PROXY=http://attacker.invalid:8080\n"
        "ALL_PROXY=http://attacker.invalid:8080\n"
        "SSL_CERT_FILE=./attacker-ca.pem\n"
        "SSL_CERT_DIR=.\n"
        "SSLKEYLOGFILE=./keys.log\n"
        "REQUESTS_CA_BUNDLE=./attacker-ca.pem\n"
        "CRIMSON_CRAWLER_API_KEY=dummy-key\n"
    )
    planted = (
        "HTTPS_PROXY",
        "HTTP_PROXY",
        "ALL_PROXY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "SSLKEYLOGFILE",
        "REQUESTS_CA_BUNDLE",
    )
    for var in planted:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.chdir(tmp_path)
    try:
        code = run([str(SAMPLES / "benign.eml"), "--json", "--no-llm", "--no-enrich"])
        assert code == 0
        # Not merely announced: httpx reads os.environ when the client is built.
        for var in planted:
            assert os.environ.get(var) is None, var
        # The key itself still loads — that is what reading ./.env is for.
        assert os.environ.get("CRIMSON_CRAWLER_API_KEY") == "dummy-key"
        err = capsys.readouterr().err
        assert "ignoring" in err and "HTTPS_PROXY" in err  # never silent
    finally:
        for var in (*planted, "CRIMSON_CRAWLER_API_KEY"):
            os.environ.pop(var, None)


def test_real_environment_proxy_survives_dotenv_read(tmp_path, monkeypatch):
    # Only .env-sourced values are dropped. A corporate proxy exported in the
    # shell is the operator's deliberate choice and must keep working.
    import os

    from dotenv import dotenv_values as real_dotenv_values

    monkeypatch.setattr("phish_check.cli.dotenv_values", real_dotenv_values)
    (tmp_path / ".env").write_text("HTTPS_PROXY=http://attacker.invalid:8080\n")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.corp.example:3128")
    monkeypatch.chdir(tmp_path)
    assert run([str(SAMPLES / "benign.eml"), "--json", "--no-llm", "--no-enrich"]) == 0
    assert os.environ["HTTPS_PROXY"] == "http://proxy.corp.example:3128"


def test_real_environment_endpoint_survives_dotenv_load(tmp_path, monkeypatch, capsys):
    # Only .env-sourced overrides are dropped. A local mock or corporate gateway
    # exported in the shell is a deliberate choice and must keep working.
    import os

    monkeypatch.setattr("phish_check.cli.dotenv_values", lambda *a, **k: {})
    monkeypatch.setenv("CRIMSON_CRAWLER_BASE_URL", "http://localhost:8080")
    monkeypatch.chdir(tmp_path)
    code = run([str(SAMPLES / "benign.eml"), "--json", "--no-llm", "--no-enrich"])
    assert code == 0
    assert os.environ.get("CRIMSON_CRAWLER_BASE_URL") == "http://localhost:8080"
    assert "ignoring CRIMSON_CRAWLER_BASE_URL" not in capsys.readouterr().err


def test_non_default_endpoint_is_announced(capsys, monkeypatch):
    # A redirected endpoint may come from a .env rather than from the operator,
    # so it must never be silent.
    monkeypatch.setenv("CRIMSON_CRAWLER_BASE_URL", "https://mock.example")
    run([str(SAMPLES / "benign.eml"), "--json", "--no-llm", "--no-enrich"])
    assert "CRIMSON_CRAWLER_BASE_URL is set" in capsys.readouterr().err


def test_no_enrich_footer_does_not_nag_for_key(capsys):
    # --no-enrich is a user choice; telling them to set CRIMSON_CRAWLER_API_KEY
    # (which they may well have set) is wrong messaging.
    run([str(SAMPLES / "benign.eml"), "--no-llm", "--no-enrich"])
    stdout = capsys.readouterr().out
    assert "--no-enrich" in stdout
    assert "CRIMSON_CRAWLER_API_KEY" not in stdout


def test_missing_key_footer_points_to_free_key(capsys):
    # No key and no --no-enrich: this is the funnel message — keep it.
    run([str(SAMPLES / "benign.eml"), "--no-llm"])
    stdout = capsys.readouterr().out
    assert "CRIMSON_CRAWLER_API_KEY" in stdout
    assert "crimsoncrawler.com" in stdout


def test_missing_file():
    assert run(["/nonexistent.eml", "--no-llm", "--no-enrich"]) == 10


def test_missing_file_json_emits_structured_error(capsys):
    code = run(["/nonexistent.eml", "--json", "--no-llm", "--no-enrich"])
    out = json.loads(capsys.readouterr().out)
    assert code == 10
    assert "error" in out


def test_usage_errors_exit_in_error_range():
    # argparse's default exit code is 2 — which this contract reads as
    # "malicious". A typo'd flag must land in the >=10 error range.
    for argv in (["--bogus-flag"], ["x.eml", "--deep", "abc"], ["x.eml", "--deep", "-1"]):
        with pytest.raises(SystemExit) as exc:
            run(argv)
        assert exc.value.code == 10


def test_markup_metacharacters_in_filename_dont_crash():
    # rich.MarkupError from a bracketed filename used to escape as exit 1
    # ("suspicious").
    assert run(["/nonexistent[/].eml", "--no-llm", "--no-enrich"]) == 10


def test_unexpected_exception_exits_error_not_suspicious(monkeypatch, capsys):
    monkeypatch.setattr(
        "phish_check.cli.parse_email", lambda raw: (_ for _ in ()).throw(RuntimeError("boom"))
    )
    code = run([str(SAMPLES / "phishing.eml"), "--json", "--no-llm", "--no-enrich"])
    assert code == 10
    assert "error" in json.loads(capsys.readouterr().out)


def test_llm_failure_falls_back_to_rules(monkeypatch, capsys):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    def boom(*args, **kwargs):
        raise RuntimeError("api down")

    monkeypatch.setattr("phish_check.cli.llm_verdict", boom)
    code = run([str(SAMPLES / "phishing.eml"), "--json", "--no-enrich"])
    out = json.loads(capsys.readouterr().out)
    assert code == 2
    assert out["verdict"]["source"] == "rules"


def test_rich_broken_pipe_override_raises_not_systemexit():
    # rich's default on_broken_pipe raises SystemExit(1) — "suspicious" in
    # this tool's contract, and BaseException so no handler sees it.
    from phish_check.cli import _Console

    with pytest.raises(BrokenPipeError):
        _Console().on_broken_pipe()


def test_broken_pipe_propagates_to_main_handler(monkeypatch):
    # run()'s catch-all must not swallow BrokenPipeError — main() handles it
    # quietly (piping into `head` is normal usage, not an error to report).
    def boom(*args, **kwargs):
        raise BrokenPipeError

    monkeypatch.setattr("phish_check.cli.render_terminal", boom)
    with pytest.raises(BrokenPipeError):
        run([str(SAMPLES / "phishing.eml"), "--no-llm", "--no-enrich"])


def test_ansi_escapes_from_email_never_reach_output(tmp_path, capsys):
    import base64

    display = base64.b64encode(b"Micro\x1b[32;1msoft security@microsoft.com").decode()
    eml = tmp_path / "ansi.eml"
    eml.write_bytes(
        f"From: =?utf-8?b?{display}?= <alerts@evil.example>\n".encode()
        + b"Subject: test\n\nplease verify your account\n"
    )
    code = run([str(eml), "--no-llm", "--no-enrich"])
    stdout = capsys.readouterr().out
    assert code in (0, 1, 2)
    assert "\x1b[32;1m" not in stdout  # attacker SGR sequence stripped


def test_oversized_input_is_refused(tmp_path, capsys):
    # A whole email is read into memory; an absurd input must fail in the error
    # range rather than exhausting it.
    from phish_check.cli import MAX_INPUT_BYTES

    big = tmp_path / "huge.eml"
    big.write_bytes(b"From: a@b.example\r\nSubject: x\r\n\r\n" + b"A" * MAX_INPUT_BYTES)
    code = run([str(big), "--no-llm", "--no-enrich"])
    assert code == 10
    assert "refusing to parse" in capsys.readouterr().err
