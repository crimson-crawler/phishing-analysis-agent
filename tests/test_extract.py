from phish_check.defang import defang, refang
from phish_check.extract import extract_indicators
from phish_check.parser import parse_email


def _values(indicators, ioc_type):
    return {i.value for i in indicators if i.type == ioc_type}


def test_phishing_urls(phishing_indicators):
    urls = _values(phishing_indicators, "url")
    assert "https://micros0ft-support.xyz/login/verify?session=8842" in urls
    # SafeLinks-wrapped URL is unwrapped to the real target.
    assert "https://secure-account-check.top/ms/portal" in urls
    unwrapped = next(
        i for i in phishing_indicators if i.value == "https://secure-account-check.top/ms/portal"
    )
    assert "safelinks" in (unwrapped.unwrapped_from or "")


def test_defanged_text_url_refanged(phishing_indicators):
    # The plain-text part carried hxxps://micros0ft-support[.]xyz/... — refang() restores it.
    urls = _values(phishing_indicators, "url")
    assert any("micros0ft-support.xyz/login/verify" in u for u in urls)


def test_domains_and_ips(phishing_indicators):
    domains = _values(phishing_indicators, "domain")
    assert "micros0ft-support.xyz" in domains
    assert "secure-account-check.top" in domains
    assert "gmail.com" in domains  # reply-to domain
    assert "192.88.99.66" in _values(phishing_indicators, "ip")


def test_attachment_hashes(phishing_email, phishing_indicators):
    att = phishing_email.attachments[0]
    assert att.sha256 in _values(phishing_indicators, "sha256")
    assert att.md5 in _values(phishing_indicators, "md5")


def test_anchor_text_preserved(phishing_indicators):
    ind = next(
        i
        for i in phishing_indicators
        if i.value == "https://micros0ft-support.xyz/login/verify?session=8842"
    )
    assert ind.display_text == "https://login.microsoft.com/verify"


def test_benign_noise_tagging(benign_indicators):
    tracker = [i for i in benign_indicators if "gstatic.com" in i.value]
    assert tracker and all(i.noise for i in tracker)
    real = [i for i in benign_indicators if "pythonweekly.com" in i.value and i.type == "domain"]
    assert real and not real[0].noise


def test_dedupe():
    raw = b"""From: a@b.example
Subject: x

https://dup.example/page https://dup.example/page https://dup.example/page
"""
    indicators = extract_indicators(parse_email(raw))
    assert len([i for i in indicators if i.type == "url"]) == 1


def test_generic_redirect_keeps_wrapper_host():
    # The linking host must never vanish just because a query param holds a
    # benign URL — that would let phishers hide behind ?next=https://google.com.
    raw = b"""From: a@b.example
Subject: x

https://evil-phisher.example/steal?next=https%3A%2F%2Fwww.google.com%2F
"""
    indicators = extract_indicators(parse_email(raw))
    domains = _values(indicators, "domain")
    assert "evil-phisher.example" in domains
    assert "google.com" in domains  # redirect target still surfaced
    assert any("evil-phisher.example" in u for u in _values(indicators, "url"))


def test_html_only_bare_text_url_extracted():
    raw = b"""From: a@b.example
Subject: x
MIME-Version: 1.0
Content-Type: text/html

<html><body><p>Copy this link: https://evil-phish.example/verify</p></body></html>
"""
    indicators = extract_indicators(parse_email(raw))
    assert "evil-phish.example" in _values(indicators, "domain")


def test_ranking_puts_noise_last(benign_indicators):
    noise_positions = [n for n, i in enumerate(benign_indicators) if i.noise]
    real_positions = [n for n, i in enumerate(benign_indicators) if not i.noise]
    assert not noise_positions or not real_positions or min(noise_positions) > max(real_positions)


def test_private_ip_host_not_typed_as_domain():
    raw = b"""From: a@b.example
Subject: x

click http://10.0.0.5/login now
"""
    indicators = extract_indicators(parse_email(raw))
    # The URL survives as an indicator, but a non-global IP is neither an "ip"
    # indicator (not routable) nor a "domain" (malformed CC query).
    assert any("10.0.0.5" in u for u in _values(indicators, "url"))
    assert "10.0.0.5" not in _values(indicators, "domain")
    assert "10.0.0.5" not in _values(indicators, "ip")


def test_iframe_src_is_not_noise():
    raw = b"""From: a@b.example
Subject: x
MIME-Version: 1.0
Content-Type: text/html

<html><body>
<iframe src="https://evil-kit.example/frame"></iframe>
<img src="https://cdn.example/logo.png">
</body></html>
"""
    indicators = extract_indicators(parse_email(raw))
    iframe = [i for i in indicators if "evil-kit.example" in i.value]
    assert iframe and all(not i.noise for i in iframe)  # payload vector, never deranked
    img = [i for i in indicators if "cdn.example" in i.value]
    assert img and all(i.noise for i in img)  # decoration stays noise


def test_defang():
    assert defang("https://evil.example/x", "url") == "hxxps://evil[.]example/x"
    assert defang("evil.example", "domain") == "evil[.]example"
    assert defang("192.88.99.66", "ip") == "192[.]88[.]99[.]66"
    assert defang("a@b.example", "email") == "a[@]b[.]example"
    assert defang("d41d8cd98f00b204e9800998ecf8427e", "md5") == "d41d8cd98f00b204e9800998ecf8427e"


def test_refang_round_trips_this_tools_own_conventions():
    for value, ioc_type in (
        ("https://evil.example/x", "url"),
        ("http://evil.example/x", "url"),
        ("evil.example", "domain"),
        ("a@b.example", "email"),
    ):
        assert refang(defang(value, ioc_type)) == value


def test_refang_third_party_conventions():
    # Variants other tools emit — a report pasted in from elsewhere must still
    # yield analyzable IOCs.
    assert refang("hxxps://evil(.)example/x") == "https://evil.example/x"
    assert refang("hXXp://evil{.}example") == "http://evil.example"
    assert refang("https[:]//evil[dot]example/a") == "https://evil.example/a"
    assert refang("https[:]//evil.example[/]a") == "https://evil.example/a"
    assert refang("bob(at)corp(dot)example") == "bob@corp.example"
    # Ordinary prose is left alone.
    assert refang("Ship it by 5pm. See attached.") == "Ship it by 5pm. See attached."


def test_defanged_urls_in_plain_text_are_extracted():
    raw = b"""From: a@b.example
Subject: pay

Two links: hxxps://first-lure[.]example/a and hxxps://second-lure[.]example/b.
"""
    urls = _values(extract_indicators(parse_email(raw)), "url")
    # Trailing sentence punctuation must not end up inside the indicator.
    assert "https://first-lure.example/a" in urls
    assert "https://second-lure.example/b" in urls


def test_numeric_ip_url_hosts_are_analyzed():
    # 134744072 == 8.8.8.8 — browsers resolve single-number hosts; these used
    # to be dropped entirely as "dotless junk" (no url, no ip indicator).
    raw = b"""From: a@b.example
Subject: pay
MIME-Version: 1.0
Content-Type: text/html

<html><body><a href="http://134744072/login">invoice</a></body></html>
"""
    indicators = extract_indicators(parse_email(raw))
    assert "http://134744072/login" in _values(indicators, "url")
    assert "8.8.8.8" in _values(indicators, "ip")


def test_numeric_private_ip_host_keeps_url_only():
    # 0x7f000001 == 127.0.0.1: not a routable IOC, but the URL must survive.
    raw = b"""From: a@b.example
Subject: pay
MIME-Version: 1.0
Content-Type: text/html

<html><body><a href="http://0x7f000001/x">click</a></body></html>
"""
    indicators = extract_indicators(parse_email(raw))
    assert "http://0x7f000001/x" in _values(indicators, "url")
    assert _values(indicators, "ip") == set()


def test_scheme_relative_href_is_extracted():
    # Webmail renders over https, so //host resolves to https://host; WHATWG
    # treats backslashes as slashes for special schemes.
    raw = b"""From: a@b.example
Subject: reset
MIME-Version: 1.0
Content-Type: text/html

<html><body><a href="//evil-relative.example/login">account</a>
<a href="/\\evil-backslash.example/login">billing</a></body></html>
"""
    indicators = extract_indicators(parse_email(raw))
    urls = _values(indicators, "url")
    assert "https://evil-relative.example/login" in urls
    assert "https://evil-backslash.example/login" in urls
    assert "evil-relative.example" in _values(indicators, "domain")
    anchored = next(i for i in indicators if i.value == "https://evil-relative.example/login")
    assert anchored.display_text == "account"


def test_dotted_octal_and_hex_ip_hosts_are_analyzed():
    # inet_aton-style obfuscation: 010.010.010.010 == 8.8.8.8; 0177.0.0.1 ==
    # 127.0.0.1. These used to be typed as bogus *domain* indicators.
    raw = b"""From: a@b.example
Subject: pay
MIME-Version: 1.0
Content-Type: text/html

<html><body><a href="http://010.010.010.010/x">a</a>
<a href="http://0177.0.0.1/y">b</a></body></html>
"""
    indicators = extract_indicators(parse_email(raw))
    assert "8.8.8.8" in _values(indicators, "ip")
    assert "http://0177.0.0.1/y" in _values(indicators, "url")  # kept as URL...
    assert _values(indicators, "domain") == {"b.example"}  # ...never a domain


def test_malformed_bracketed_host_does_not_crash():
    # A crafted invalid IPv6-literal href must not abort the whole analysis
    # (urlparse raises ValueError on it); the co-located real link must still
    # be extracted. Regression for the deny-analysis evasion.
    raw = (
        b"From: a@evil.example\nMIME-Version: 1.0\nContent-Type: text/html\n\n"
        b'<html><body><a href="http://[test]/">x</a>'
        b'<a href="https://real-phish.example/login">y</a></body></html>'
    )
    inds = extract_indicators(parse_email(raw))
    assert "real-phish.example" in _values(inds, "domain")
