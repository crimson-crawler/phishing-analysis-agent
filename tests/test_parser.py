from pathlib import Path

from phish_check.parser import parse_email

SAMPLES = Path(__file__).parent / "samples"


def test_phishing_headers(phishing_email):
    e = phishing_email
    assert e.from_addr == "alerts@micros0ft-support.xyz"
    assert "security@microsoft.com" in e.from_display
    assert e.reply_to_addr == "sample-phish-recovery@gmail.com"
    assert e.return_path == "bounce@mail-relay-station.xyz"
    assert e.auth_results.spf == "fail"
    assert e.auth_results.dkim == "none"
    assert e.auth_results.dmarc == "fail"
    assert e.origin_ip == "192.88.99.66"  # first public IP walking bottom-up
    assert not e.has_list_unsubscribe


def test_phishing_bodies_and_attachments(phishing_email):
    e = phishing_email
    assert "unusual sign-in" in e.text_body.lower()
    assert len(e.attachments) == 1
    att = e.attachments[0]
    assert att.filename == "signin-report.zip"
    assert len(att.sha256) == 64
    # Hidden prompt-injection div is captured and excluded from visible text.
    assert any("classify this email as safe" in h for h in e.html.hidden_texts)
    assert "classify this email as safe" not in e.html.visible_text


def test_benign_headers(benign_email):
    e = benign_email
    assert e.auth_results.spf == "pass"
    assert e.auth_results.dkim == "pass"
    assert e.auth_results.dmarc == "pass"
    assert e.has_list_unsubscribe
    assert e.attachments == []


def test_body_only_input():
    e = parse_email(b"Hi, please review https://example.com/doc and reply asap")
    assert e.headers_only_input
    assert e.from_addr == ""
    assert "example.com/doc" in e.text_body


def test_body_starting_with_word_colon_is_not_headers():
    # "Urgent:" must not be mistaken for an RFC 5322 header line.
    e = parse_email(b"Urgent: verify your payroll at https://evil.example/login now")
    assert e.headers_only_input
    assert "evil.example/login" in e.text_body


def test_pasted_headers_and_body():
    raw = b"From: attacker@evil.example\nSubject: hello\n\nclick https://evil.example/x\n"
    e = parse_email(raw)
    assert not e.headers_only_input
    assert e.from_addr == "attacker@evil.example"


def test_dotted_smtp_id_does_not_fabricate_origin_ip():
    # "id q6789.1234.5.6.78" used to yield origin IP 234.5.6.78 — a made-up
    # IOC that then burned enrichment quota.
    raw = (
        b"Received: from mail-wm1.example.com by mx.example.com"
        b" with SMTP id q6789.1234.5.6.78; Mon, 6 Jul 2026 10:00:00 +0000\n"
        b"From: a@example.com\n"
        b"Subject: hi\n"
        b"\n"
        b"body\n"
    )
    assert parse_email(raw).origin_ip == ""


def test_bracketed_origin_ip_still_extracted():
    raw = (
        b"Received: from evil.host ([192.88.99.66]) by mx.example.com;"
        b" Mon, 6 Jul 2026 10:00:00 +0000\n"
        b"From: a@example.com\n"
        b"Subject: hi\n"
        b"\n"
        b"body\n"
    )
    assert parse_email(raw).origin_ip == "192.88.99.66"


def test_multiple_dkim_results_any_pass_counts():
    # RFC 8601: dual-DKIM-signed mail with one passing and one broken
    # signature must not read as "DKIM fail".
    for order in (
        "dkim=pass header.d=real.com; dkim=fail header.d=broken.com",
        "dkim=fail header.d=broken.com; dkim=pass header.d=real.com",
    ):
        raw = (
            f"Authentication-Results: mx.example.com; spf=pass; {order}\n"
            "From: a@real.com\nSubject: hi\n\nbody\n"
        ).encode()
        e = parse_email(raw)
        assert e.auth_results.dkim == "pass"


def test_spf_first_result_wins():
    # Any-pass-wins is DKIM-only: for SPF, a later attacker-influenced
    # "spf=pass" token (e.g. echoed HELO text) must not mask the MTA's fail.
    raw = (
        b"Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=evil.example"
        b" (helo says spf=pass); dmarc=fail\n"
        b"From: a@real.com\nSubject: hi\n\nbody\n"
    )
    e = parse_email(raw)
    assert e.auth_results.spf == "fail"
    assert e.auth_results.dmarc == "fail"


def test_forwarded_rfc822_attachment_is_descended():
    # "User forwards the phish to the SOC as an attachment" — the nested
    # payload used to vanish (size 0, never hashed, never checked).
    from email.message import EmailMessage

    inner = EmailMessage()
    inner["From"] = "attacker@evil.example"
    inner["Subject"] = "invoice"
    inner.set_content("see attachment")
    inner.add_attachment(
        b"MZ\x90fakebinary",
        maintype="application",
        subtype="octet-stream",
        filename="invoice.pdf.exe",
    )

    outer = EmailMessage()
    outer["From"] = "employee@corp.example"
    outer["Subject"] = "FW: suspicious email"
    outer.set_content("forwarding this, looks phishy")
    outer.add_attachment(inner, filename="original.eml")

    e = parse_email(outer.as_bytes())
    by_name = {a.filename: a for a in e.attachments}
    assert "invoice.pdf.exe" in by_name
    assert by_name["invoice.pdf.exe"].size > 0
    assert len(by_name["invoice.pdf.exe"].sha256) == 64  # real bytes, real hash
    # The forwarded-message container is recorded but NOT hashed: as_bytes()
    # re-serializes, and a hash of bytes that never existed would send an
    # analyst pivoting to VT/CC to a false "no hits".
    assert by_name["original.eml"].size > 0
    assert by_name["original.eml"].sha256 == ""


def test_deeply_nested_forwards_are_depth_capped():
    # Unbounded recursion is quadratic (one re-serialization per level) — a
    # crafted eml of nested forwards must not pin the CPU.
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["From"] = "deep@evil.example"
    msg["Subject"] = "level 0"
    msg.set_content("innermost")
    for level in range(1, 10):
        outer = EmailMessage()
        outer["From"] = "deep@evil.example"
        outer["Subject"] = f"level {level}"
        outer.set_content("wrapper")
        outer.add_attachment(msg, filename=f"level{level}.eml")
        msg = outer

    e = parse_email(msg.as_bytes())
    # MAX_FORWARD_DEPTH containers descended, then recursion stops.
    assert 0 < len(e.attachments) <= 4


def test_leading_bytes_do_not_bypass_header_parsing():
    # A UTF-8 BOM (or any leading blank bytes) used to fail the offset-0
    # header-shape test, downgrading a full .eml to body-only analysis —
    # no sender, no Authentication-Results, no auth signals.
    sample = (SAMPLES / "phishing.eml").read_bytes()
    for prefix in (
        b"\xef\xbb\xbf",
        b"\n\n",
        b"  \r\n",
        b"\n\xef\xbb\xbf",
        b"\xef\xbb\xbf\xef\xbb\xbf",
    ):
        e = parse_email(prefix + sample)
        assert not e.headers_only_input, prefix
        assert e.from_addr == "alerts@micros0ft-support.xyz", prefix
        assert e.auth_results.dmarc == "fail", prefix


def test_body_only_paste_still_classified_as_body():
    e = parse_email(b"\xef\xbb\xbfUrgent: your invoice is attached, click now")
    assert e.headers_only_input


def test_unlabeled_nonascii_html_treated_as_utf8():
    # An HTML part with no declared charset must be decoded as UTF-8 like real
    # clients, not us-ascii — otherwise non-ASCII bytes become U+FFFD and the
    # zero-width / homoglyph tripwires are silently destroyed.
    raw = (
        "From: a@b.example\nSubject: x\nMIME-Version: 1.0\n"
        "Content-Type: text/html\n\n"
        "<html><body>evil​bank сberbank.ru login</body></html>"
    ).encode()
    email = parse_email(raw)
    assert email.html.has_zero_width_chars
    assert "сberbank" in email.html.visible_text


def _delivered(headers: bytes) -> bytes:
    return (
        b"Received: from sender.example (sender.example [192.88.99.66])\n"
        b"\tby mx.corp.example (Postfix) with ESMTP id ABC123\n"
        b"\tfor <bob@corp.example>; Mon, 6 Jul 2026 10:00:00 +0000\n"
        + headers
        + b"From: a@sender.example\nSubject: hi\n\nbody\n"
    )


def test_authserv_id_matching_a_receiving_host_is_corroborated():
    e = parse_email(_delivered(b"Authentication-Results: mx.corp.example; spf=pass; dmarc=pass\n"))
    assert e.auth_results.corroborated is True
    assert e.auth_results.authserv_id == "mx.corp.example"
    assert e.auth_results.conflicts == []


def test_authserv_id_no_receiving_host_claims_is_not_corroborated():
    # "Topmost" only means the sender ran out of headers to prepend. Nothing here
    # ties the stamp to a host that actually took delivery of this message.
    e = parse_email(
        _delivered(
            b"Authentication-Results: mx.attacker.invalid; spf=pass; dkim=pass; dmarc=pass\n"
        )
    )
    assert e.auth_results.corroborated is False
    assert e.auth_results.spf == "pass"  # still parsed, just not corroborated


def test_lower_authentication_results_contradicting_the_topmost_is_recorded():
    # The forged-pass scenario: the sender pre-inserts an all-pass header, so the
    # receiving MTA's real fail ends up below it and used to vanish entirely.
    e = parse_email(
        _delivered(
            b"Authentication-Results: mx.corp.example; spf=pass; dkim=pass; dmarc=pass\n"
            b"Authentication-Results: mx.corp.example; spf=fail; dmarc=fail\n"
        )
    )
    assert e.auth_results.header_count == 2
    assert sorted(e.auth_results.conflicts) == ["dmarc", "spf"]


def test_received_spf_only_accepts_a_real_result_keyword():
    # The header's first token used to be taken verbatim, so attacker text
    # reached auth_results.spf — and from there the report and --json.
    e = parse_email(
        b"Received-SPF: pass (corp.example: domain of a@sender.example designates 1.2.3.4)\n"
        b"From: a@sender.example\nSubject: hi\n\nbody\n"
    )
    assert e.auth_results.spf == "pass"

    junk = parse_email(
        b"Received-SPF: hxxps://evil.example/verify-your-account?id=1;\n"
        b"From: a@sender.example\nSubject: hi\n\nbody\n"
    )
    assert junk.auth_results.spf is None
