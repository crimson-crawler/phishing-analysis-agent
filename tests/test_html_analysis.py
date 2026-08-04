from phish_check.html_analysis import analyze_html


def test_fractional_font_size_is_not_hidden():
    # Newsletter fine print (font-size:0.9em) used to be decomposed as hidden
    # text — removed from what the judge sees and flagged as evasion.
    r = analyze_html('<p style="font-size:0.9em">Unsubscribe or manage preferences</p>')
    assert r.hidden_texts == []
    assert "Unsubscribe" in r.visible_text


def test_zero_and_near_zero_font_sizes_are_hidden():
    # Near-zero (0.5px, 0.1em) is unreadable — hiding, not fine print; exact
    # matching only on 0 would reopen the prompt-injection channel.
    for style in (
        "font-size:0",
        "font-size: 0;",
        "font-size:0px",
        "font-size: 0.0em;",
        "font-size:0.5px",
        "font-size: 1px",
        "font-size:0.1em",
        "font-size:10%",
    ):
        r = analyze_html(f'<div style="{style}">secret instructions</div>')
        assert r.hidden_texts == ["secret instructions"], style
        assert "secret" not in r.visible_text


def test_readable_font_sizes_stay_visible():
    for style in (
        "font-size:0.9em",
        "font-size:12px",
        "font-size:80%",
        "font-size:0.875rem",
        "font-size:10pt",
    ):
        r = analyze_html(f'<div style="{style}">fine print</div>')
        assert r.hidden_texts == [], style
        assert "fine print" in r.visible_text


def test_emoji_zwj_sequence_is_not_flagged():
    # Compound emoji (👩‍💻) are ubiquitous in marketing mail; a bare
    # presence check false-positived on every one of them.
    r = analyze_html("<p>Meet the team \U0001f469‍\U0001f4bb this week!</p>")
    assert not r.has_zero_width_chars


def test_zero_width_inside_word_is_flagged():
    r = analyze_html("<p>please ver​ify your account</p>")
    assert r.has_zero_width_chars
    assert "verify" in r.visible_text  # still stripped for the judge's view


def test_zero_width_next_to_punctuation_is_flagged():
    # ZWSP before the dot of a domain — classic placement to break IOC
    # extraction; adjacency to a word char on either side must count.
    r = analyze_html("<p>Pay at evil​.com now</p>")
    assert r.has_zero_width_chars
