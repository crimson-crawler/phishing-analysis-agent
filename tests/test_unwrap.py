from phish_check.unwrap import (
    is_known_gateway,
    is_undecodable_rewrapper,
    unwrap,
    unwrap_gateways,
)


def test_safelinks():
    wrapped = (
        "https://nam12.safelinks.protection.outlook.com/"
        "?url=https%3A%2F%2Fevil.example%2Fpath%3Fa%3D1&data=05"
    )
    final, chain = unwrap(wrapped)
    assert final == "https://evil.example/path?a=1"
    assert chain == [wrapped]


def test_proofpoint_v2():
    wrapped = "https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.example_x&d=DwMF"
    final, _ = unwrap(wrapped)
    assert final == "https://evil.example/x"


def test_barracuda():
    wrapped = "https://linkprotect.cudasvc.com/url?a=https%3A%2F%2Fevil.example%2Fy&c=E,1,x"
    final, _ = unwrap(wrapped)
    assert final.startswith("https://evil.example/y")


def test_google_redirect():
    final, _ = unwrap("https://www.google.com/url?q=https%3A%2F%2Fevil.example%2Fz")
    assert final == "https://evil.example/z"


def test_generic_query_param_fallback():
    final, _ = unwrap("https://tracker.example/click?dest=https%3A%2F%2Fevil.example%2Fgo")
    assert final == "https://evil.example/go"


def test_nested_unwrapping():
    inner = "https://evil.example/final"
    google = "https://www.google.com/url?q=" + inner.replace(":", "%3A").replace("/", "%2F")
    safelinks = "https://nam12.safelinks.protection.outlook.com/?url=" + google.replace(
        ":", "%3A"
    ).replace("/", "%2F").replace("?", "%3F").replace("=", "%3D")
    final, chain = unwrap(safelinks)
    assert final == inner
    assert len(chain) == 2


def test_plain_url_untouched():
    final, chain = unwrap("https://example.com/normal?page=2")
    assert final == "https://example.com/normal?page=2"
    assert chain == []


def test_known_gateway_classification():
    assert is_known_gateway(
        "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fa.example%2F"
    )
    # A generic URL-valued query param is NOT a known gateway — the host may be
    # the phishing site itself.
    assert not is_known_gateway("https://tracker.example/click?dest=https%3A%2F%2Fa.example%2F")


def test_unwrap_gateways_does_not_follow_generic_redirects():
    url = "https://evil-phisher.example/steal?next=https%3A%2F%2Fwww.google.com%2F"
    assert unwrap_gateways(url) == url  # clicked host must not be masked
    final, chain = unwrap(url)  # full unwrap still surfaces the redirect target
    assert final == "https://www.google.com/"
    assert chain == [url]


def test_mimecast_flagged_undecodable():
    assert is_undecodable_rewrapper("https://protect-us.mimecast.com/s/AbCdEf")
    assert not is_undecodable_rewrapper("https://example.com/")


def test_no_double_decode_of_target_escapes():
    # parse_qs already percent-decodes once; a second unquote() used to turn
    # a target's own legitimate escapes (%2520 -> %20 -> ' ') into garbage —
    # and the corrupted URL is what gets enriched.
    wrapped = (
        "https://nam12.safelinks.protection.outlook.com/"
        "?url=https%3A%2F%2Fexample.com%2Ffiles%2FQ2%2520report.pdf%3Fid%3Da%252Bb&data=05"
    )
    final, _ = unwrap(wrapped)
    assert final == "https://example.com/files/Q2%20report.pdf?id=a%2Bb"


def test_generic_fallback_no_double_decode():
    wrapped = "https://tracker.example/r?dest=https%3A%2F%2Fevil.example%2Fx%2520y"
    final, _ = unwrap(wrapped)
    assert final == "https://evil.example/x%20y"


def test_generic_fallback_still_unwraps_double_encoded_target():
    # dest is double-percent-encoded: one decode (parse_qs) yields
    # https%3A%2F%2F... which is not URL-shaped; the extra decode applies
    # only in that case, so it can't corrupt ordinary targets.
    wrapped = "https://track.example/r?dest=https%253A%252F%252Fevil.example%252Fpay"
    final, _ = unwrap(wrapped)
    assert final == "https://evil.example/pay"


def test_proofpoint_v3_lowercase_run_char():
    # PPv3 run-length chars map A-Z -> 2-27 and a-z -> 28-53; 'c' means 30
    # substituted chars. The old decoder only knew uppercase and emitted 1.
    import base64

    hidden = "A" * 30
    enc = base64.urlsafe_b64encode(hidden.encode()).decode().rstrip("=")
    wrapped = f"https://urldefense.com/v3/__https://example.com/**c__;{enc}!!tag!xyz$"
    final, _ = unwrap(wrapped)
    assert final == "https://example.com/" + hidden
