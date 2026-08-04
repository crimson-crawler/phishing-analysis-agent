import copy

import httpx
import pytest

from phish_check.enrich import (
    CC_TYPE_MAP,
    PORTFOLIO_INCLUDE,
    CrimsonCrawlerClient,
    _apply_attributes,
    _apply_warninglists,
    enrich,
)
from phish_check.judge import rules_verdict
from phish_check.models import Evidence, Indicator

# Mirrors the API response shape the client handles: per-attribute feed_hits
# are empty; feed correlations arrive in the top-level misp_feed_hits.
CANNED_PORTFOLIO = {
    "indicators_assessed": 2,
    "misp_attributes": [
        {
            "value": "https://secure-account-check.top/ms/portal",
            "type": "url",
            "tags": ["phishing", "credential-harvest", "tlp:white"],
            "to_ids": True,
            "first_seen": "2026-07-01",
            "last_seen": "2026-07-05",
            "sighting_count": 3,
            "feed_hits": [],
            "actors": [],
            "malware": ["tycoon2fa"],
        }
    ],
    "misp_feed_hits": [
        {
            "id": "65",
            "name": "URLhaus",
            "provider": "abuse.ch",
            "source_format": "misp",
            "url": "https://urlhaus.abuse.ch/downloads/misp/",
        },
        {"id": "31", "name": "Phishing.Database", "provider": "Mitchell Krog", "url": ""},
    ],
    "warninglist_hits": [
        {
            "value": "8.8.8.8",
            "is_on_warninglist": True,
            "warninglists": ["List of known google domains and IPs"],
            "categories": ["fp"],
        }
    ],
    "summary": "1 of 2 indicators correlated with active phishing feeds.",
    "errors": [],
}

CANNED_DEEP = {
    "value": "https://secure-account-check.top/ms/portal",
    "type": "url",
    "misp_attributes": CANNED_PORTFOLIO["misp_attributes"],
    "misp_feed_hits": CANNED_PORTFOLIO["misp_feed_hits"],
    "threat_assessment": {
        "verdict": "high_threat",
        "threat_score": 0.82,
        "confidence": 0.7,
        "event_count": 4,
        "technique_count": 1,
        "sighting_count": 3,
        "on_warninglist": False,
        "to_ids_ratio": 1.0,
        "recency_days": 2,
        "cross_feed_count": 2,
    },
    "errors": [],
}


def _indicators():
    return [
        Indicator(
            value="https://secure-account-check.top/ms/portal", type="url", source="body-html"
        ),
        Indicator(value="8.8.8.8", type="ip", source="header-received"),
    ]


def test_apply_attributes_matches_by_value():
    inds = _indicators()
    _apply_attributes(inds, CANNED_PORTFOLIO["misp_attributes"])
    url = inds[0]
    assert url.enrichment is not None
    assert url.enrichment.misp_matched
    assert "phishing" in url.enrichment.tags
    assert url.enrichment.malware == ["tycoon2fa"]
    assert inds[1].enrichment is None


def test_apply_warninglists():
    inds = _indicators()
    _apply_warninglists(inds, CANNED_PORTFOLIO["warninglist_hits"])
    assert inds[1].enrichment.on_warninglist


def test_enrich_portfolio_mocked(monkeypatch):
    calls = {}

    def fake_post(self, path, body):
        calls[path] = body
        return CANNED_PORTFOLIO

    monkeypatch.setattr("phish_check.enrich.CrimsonCrawlerClient._post", fake_post)
    inds = _indicators()
    prior = [Evidence(id="E1", category="auth", severity="high", description="DMARC fail")]
    new_evidence, meta = enrich(inds, prior, api_key="test-key")

    body = calls["/v1/assess/ioc-portfolio"]
    assert body["indicators"] == [
        {"value": "https://secure-account-check.top/ms/portal", "type": "url"},
        {"value": "8.8.8.8", "type": "ip-dst"},
    ]
    assert meta.api_calls == 1
    assert [h.name for h in meta.portfolio_feed_hits] == ["URLhaus", "Phishing.Database"]

    # Email-level feed correlation evidence continues the E-id sequence.
    assert new_evidence[0].id == "E2"
    # Provider names are CC-echoed free text and defanged at build time — a
    # domain-shaped provider ("abuse.ch") must not render as a live domain.
    assert "URLhaus (abuse[.]ch)" in new_evidence[0].description
    assert new_evidence[0].severity == "high"
    # Portfolio-matched indicator gets high-severity MISP-match evidence.
    misp_ev = [e for e in new_evidence if "MISP threat events" in e.description]
    assert misp_ev and misp_ev[0].severity == "high"
    assert misp_ev[0].indicator == "https://secure-account-check.top/ms/portal"
    warn_ev = [e for e in new_evidence if "warninglist" in e.description]
    assert warn_ev and warn_ev[0].severity == "info"


def test_enrich_deep_attaches_toplevel_feed_hits(monkeypatch):
    def fake_post(self, path, body):
        if path == "/v1/assess/ioc-portfolio":
            return CANNED_PORTFOLIO
        assert path == "/v1/enrich/ioc"
        assert body["value"] == "https://secure-account-check.top/ms/portal"
        return CANNED_DEEP

    monkeypatch.setattr("phish_check.enrich.CrimsonCrawlerClient._post", fake_post)
    inds = _indicators()
    new_evidence, meta = enrich(inds, [], api_key="test-key", deep=1)

    assert meta.api_calls == 2
    url = inds[0]
    # Deep run picked the MISP-matched indicator and attributed feeds to it.
    assert [h.name for h in url.enrichment.feed_hits] == ["URLhaus", "Phishing.Database"]
    assert url.enrichment.threat_verdict == "high_threat"
    feed_ev = [e for e in new_evidence if "listed on threat feed" in e.description]
    assert feed_ev and feed_ev[0].indicator == url.value
    ta_ev = [e for e in new_evidence if "threat assessment" in e.description]
    assert ta_ev and ta_ev[0].severity == "high"


def test_batch_cap(monkeypatch):
    submitted = {}

    def fake_post(self, path, body):
        submitted["n"] = len(body["indicators"])
        return {"misp_attributes": [], "warninglist_hits": [], "errors": []}

    monkeypatch.setattr("phish_check.enrich.CrimsonCrawlerClient._post", fake_post)
    inds = [
        Indicator(value=f"host{n}.example", type="domain", source="body-html", noise=n < 5)
        for n in range(60)
    ]
    _, meta = enrich(inds, [], api_key="test-key")
    assert submitted["n"] == 50
    assert meta.indicators_truncated == 10


def test_type_map_is_misp_compatible():
    assert CC_TYPE_MAP["ip"] == "ip-dst"
    assert CC_TYPE_MAP["sha256"] == "sha256"


def test_portfolio_include_omits_warninglist():
    # The portfolio endpoint does not accept "warninglist" as an include value
    # (warninglist_hits come back regardless) — a regression here passes the
    # suite but fails against a live API.
    assert "warninglist" not in PORTFOLIO_INCLUDE


def test_all_warninglisted_feed_hits_do_not_verdict_malicious(monkeypatch):
    # A benign email whose only MISP-matched IOC is warninglisted (8.8.8.8 in
    # an OSINT feed) used to get unconditional high email-level feed evidence
    # -> rules_verdict MALICIOUS 0.9 -> exit 2.
    canned = {
        "misp_attributes": [
            {"value": "8.8.8.8", "type": "ip-dst", "tags": ["osint"], "feed_hits": []},
        ],
        "misp_feed_hits": [{"id": "9", "name": "IPsum", "provider": "", "url": ""}],
        "warninglist_hits": [
            {
                "value": "8.8.8.8",
                "is_on_warninglist": True,
                "warninglists": ["List of known google domains and IPs"],
            },
        ],
        "errors": [],
    }
    monkeypatch.setattr(
        "phish_check.enrich.CrimsonCrawlerClient._post", lambda self, path, body: canned
    )
    inds = [Indicator(value="8.8.8.8", type="ip", source="header-received")]
    new_evidence, _ = enrich(inds, [], api_key="test-key")
    feed_ev = [e for e in new_evidence if "correlate with threat feed" in e.description]
    # Medium, not high (would tip rules_verdict to malicious) and not info
    # (feed hits aren't reliably attributable — must not vanish entirely).
    assert feed_ev and feed_ev[0].severity == "medium"
    assert "warninglist" in feed_ev[0].description
    assert rules_verdict(new_evidence).verdict != "malicious"


def test_string_entries_in_errors_array_do_not_crash(monkeypatch):
    canned = {
        "misp_attributes": [],
        "warninglist_hits": [],
        "errors": ["indicator rejected: bad type", {"message": "quota low"}],
    }
    monkeypatch.setattr(
        "phish_check.enrich.CrimsonCrawlerClient._post", lambda self, path, body: canned
    )
    _, meta = enrich(_indicators(), [], api_key="test-key")
    assert "indicator rejected: bad type" in meta.errors
    assert "quota low" in meta.errors


def test_non_json_response_degrades_gracefully(monkeypatch):
    def bad_json(self, path, body):
        raise ValueError("Expecting value: line 1 column 1 (char 0)")

    monkeypatch.setattr("phish_check.enrich.CrimsonCrawlerClient._post", bad_json)
    _, meta = enrich(_indicators(), [], api_key="test-key")
    assert meta.errors and "portfolio assessment failed" in meta.errors[0]


def test_negative_deep_makes_no_deep_calls(monkeypatch):
    # deep=-1 used to slice scored[:-1] — nearly every indicator, one live
    # API call each, straight through the account's rate limit.
    deep_calls = []

    def fake_post(self, path, body):
        if path == "/v1/enrich/ioc":
            deep_calls.append(body)
        return {"misp_attributes": [], "warninglist_hits": [], "errors": []}

    monkeypatch.setattr("phish_check.enrich.CrimsonCrawlerClient._post", fake_post)
    enrich(_indicators(), [], api_key="test-key", deep=-1)
    assert deep_calls == []


def test_retry_after_http_date_does_not_crash(monkeypatch):
    # RFC 7231 allows Retry-After to be an HTTP-date; float() on it must not
    # escape and kill the enrichment stage.
    responses = [
        httpx.Response(
            429,
            headers={"Retry-After": "Wed, 08 Jul 2026 01:00:00 GMT"},
            request=httpx.Request("POST", "https://cc.test/x"),
        ),
        httpx.Response(200, json={"ok": True}, request=httpx.Request("POST", "https://cc.test/x")),
    ]
    slept = []
    monkeypatch.setattr("phish_check.enrich.time.sleep", slept.append)
    client = CrimsonCrawlerClient("test-key")
    monkeypatch.setattr(client._client, "post", lambda path, json: responses.pop(0))
    assert client._post("/x", {}) == {"ok": True}
    assert slept == [2.0]  # fell back to exponential backoff


def test_deep_threat_assessment_with_null_score(monkeypatch):
    deep = copy.deepcopy(CANNED_DEEP)
    deep["threat_assessment"]["threat_score"] = None
    deep["threat_assessment"]["confidence"] = None

    def fake_post(self, path, body):
        return CANNED_PORTFOLIO if path == "/v1/assess/ioc-portfolio" else deep

    monkeypatch.setattr("phish_check.enrich.CrimsonCrawlerClient._post", fake_post)
    new_evidence, _ = enrich(_indicators(), [], api_key="test-key", deep=1)
    ta_ev = [e for e in new_evidence if "threat assessment" in e.description]
    assert ta_ev and "score n/a" in ta_ev[0].description


def test_deep_enrichment_error_is_defanged(monkeypatch):
    def fake_post(self, path, body):
        if path == "/v1/assess/ioc-portfolio":
            return CANNED_PORTFOLIO
        raise httpx.ConnectError("boom")

    monkeypatch.setattr("phish_check.enrich.CrimsonCrawlerClient._post", fake_post)
    _, meta = enrich(_indicators(), [], api_key="test-key", deep=1)
    assert meta.errors and "secure-account-check[.]top" in meta.errors[0]
    assert "secure-account-check.top" not in meta.errors[0]


def test_unattributed_feed_hits_do_not_verdict_malicious(monkeypatch):
    # Feed hits with NO matching misp_attribute (matched == []) used to fall
    # into the high branch -> rules_verdict MALICIOUS 0.9 on a benign email.
    canned = {
        "misp_attributes": [],
        "misp_feed_hits": [{"id": "9", "name": "IPsum", "provider": "", "url": ""}],
        "warninglist_hits": [],
        "errors": [],
    }
    monkeypatch.setattr(
        "phish_check.enrich.CrimsonCrawlerClient._post", lambda self, path, body: canned
    )
    new_evidence, _ = enrich(_indicators(), [], api_key="test-key")
    feed_ev = [e for e in new_evidence if "correlate with threat feed" in e.description]
    assert feed_ev and feed_ev[0].severity == "medium"
    assert "not attributable" in feed_ev[0].description
    assert rules_verdict(new_evidence).verdict != "malicious"


def test_garbage_response_shapes_degrade_without_losing_enrichment(monkeypatch):
    # Every field the server controls arrives malformed: none of it may raise
    # out of enrich() (that discards enrichment the quota already paid for).
    canned_portfolio = {
        "misp_attributes": [
            "not-a-dict",
            {
                "value": "https://secure-account-check.top/ms/portal",
                "type": "url",
                "tags": "osint",
                "sighting_count": "many",
                "feed_hits": [{"name": 123, "provider": None, "url": 456}, "junk"],
            },
        ],
        "misp_feed_hits": {"unexpected": "dict"},
        "warninglist_hits": [42],
        "errors": 5,
    }
    canned_deep = {
        "misp_attributes": canned_portfolio["misp_attributes"],
        "misp_feed_hits": [{"name": "URLhaus"}],
        "threat_assessment": {"verdict": "high_threat", "threat_score": "high", "confidence": None},
    }

    def fake_post(self, path, body):
        return canned_portfolio if path == "/v1/assess/ioc-portfolio" else canned_deep

    monkeypatch.setattr("phish_check.enrich.CrimsonCrawlerClient._post", fake_post)
    inds = _indicators()
    new_evidence, meta = enrich(inds, [], api_key="test-key", deep=1)

    url = inds[0]
    assert url.enrichment.misp_matched  # valid attribute still applied
    assert url.enrichment.tags == []  # string "tags" ignored, not char-split
    assert url.enrichment.sighting_count == 0  # non-numeric count coerced
    assert url.enrichment.feed_hits[0].name == "123"  # non-str fields coerced
    assert url.enrichment.threat_score is None  # string score coerced to None
    # Evidence still builds — the ":.2f" formats must not crash on bad types.
    assert any("threat assessment" in e.description for e in new_evidence)
    assert any("score n/a" in e.description for e in new_evidence)


def test_non_dict_json_response_degrades_gracefully(monkeypatch):
    # A 200 whose JSON body is a list must land in meta.errors, not raise.
    responses = [
        httpx.Response(
            200, json=["not", "a", "dict"], request=httpx.Request("POST", "https://cc.test/x")
        ),
    ]
    client = CrimsonCrawlerClient("test-key")
    monkeypatch.setattr(client._client, "post", lambda path, json: responses.pop(0))
    try:
        client._post("/x", {})
        raise AssertionError("expected ValueError")
    except ValueError as exc:
        assert "unexpected response shape" in str(exc)


def test_feed_names_are_defanged_in_evidence(monkeypatch):
    # Feed names/providers are API-echoed free text; a URL-shaped name must
    # not put a live IOC into an Evidence description (build-time defang).
    canned = {
        "misp_attributes": [],
        "misp_feed_hits": [
            {"id": "1", "name": "see https://evil.example/feed", "provider": "", "url": ""}
        ],
        "warninglist_hits": [],
        "errors": [],
    }
    monkeypatch.setattr(
        "phish_check.enrich.CrimsonCrawlerClient._post", lambda self, path, body: canned
    )
    new_evidence, _ = enrich(_indicators(), [], api_key="test-key")
    feed_ev = [e for e in new_evidence if "correlate with threat feed" in e.description]
    assert feed_ev and "hxxps://evil[.]example/feed" in feed_ev[0].description
    assert "https://evil.example" not in feed_ev[0].description


def test_plaintext_base_url_is_refused():
    # An unvalidated base URL is a credential-exfiltration path: the apikey
    # header would go wherever it points, in the clear.
    with pytest.raises(ValueError, match="must be https"):
        CrimsonCrawlerClient("test-key", base_url="http://attacker.invalid")
    with pytest.raises(ValueError, match="must be https"):
        CrimsonCrawlerClient("test-key", base_url="file:///etc/passwd")


def test_plaintext_base_url_from_environment_is_refused(monkeypatch):
    monkeypatch.setenv("CRIMSON_CRAWLER_BASE_URL", "http://attacker.invalid")
    with pytest.raises(ValueError, match="must be https"):
        CrimsonCrawlerClient("test-key")


def test_https_and_loopback_base_urls_are_allowed():
    # Loopback plaintext never leaves the host, so local mocks stay usable.
    for url in ("https://mock.example", "http://localhost:8080", "http://127.0.0.1:8080"):
        client = CrimsonCrawlerClient("test-key", base_url=url)
        client.close()


def test_oversized_indicator_is_not_submitted(monkeypatch):
    # The batch cap bounds the indicator count, not the payload: one crafted
    # link used to be uploaded whole, however many megabytes it was.
    from phish_check.enrich import MAX_IOC_CHARS

    calls = {}

    def fake_post(self, path, body):
        calls[path] = body
        return {"misp_attributes": [], "misp_feed_hits": [], "warninglist_hits": []}

    monkeypatch.setattr("phish_check.enrich.CrimsonCrawlerClient._post", fake_post)
    huge = "https://evil.example/" + "A" * (MAX_IOC_CHARS * 4)
    inds = [
        Indicator(value=huge, type="url", source="body-html"),
        Indicator(value="evil.example", type="domain", source="body-html"),
    ]
    _, meta = enrich(inds, [], api_key="test-key", deep=2)

    submitted = [i["value"] for i in calls["/v1/assess/ioc-portfolio"]["indicators"]]
    assert submitted == ["evil.example"]
    assert meta.indicators_submitted == 1
    assert any("longer than" in e for e in meta.errors)  # never a silent drop
    # And it is not picked up by --deep either.
    assert all(huge not in str(body) for body in calls.values())


def test_prompt_budget_is_never_exceeded_by_a_crafted_email():
    # Backstop for the per-field caps: a message that maximizes every
    # attacker-controlled field must still produce a bounded request.
    from phish_check.judge import MAX_PROMPT_CHARS, build_user_prompt
    from phish_check.models import ParsedEmail

    email = ParsedEmail()
    email.subject = "S" * 100_000
    email.from_display = "D" * 100_000
    email.from_addr = "a" * 100_000 + "@" + "d" * 100_000 + ".example"
    email.reply_to_addr = "b" * 100_000 + "@" + "e" * 100_000 + ".example"
    email.text_body = "lure text " * 100_000
    evidence = [
        Evidence(
            id=f"E{n}",
            category="link",
            severity="high",
            description="x" * 50_000,
            indicator="https://evil.example/" + "p" * 50_000,
        )
        for n in range(1, 500)
    ]
    indicators = [Indicator(value=e.indicator, type="url", source="body-html") for e in evidence]
    prompt = build_user_prompt(email, indicators, evidence)
    assert len(prompt) <= MAX_PROMPT_CHARS
    # The framing survives the caps — that is what must not be truncated away.
    assert prompt.rstrip().endswith("----- END UNTRUSTED-EMAIL-CONTENT -----")
