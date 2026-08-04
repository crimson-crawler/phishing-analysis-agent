# Sample emails

Fabricated demo inputs. Every domain, sender, recipient, subject and "payload"
is invented, and no sample derives from a real received email — there are no
real DKIM/ARC signatures or gateway headers anywhere in this directory.

**About the IP addresses:** every fabricated address here — every one presented
as a phishing origin, and the invented `corp.example` relays — is in
`192.88.99.0/24` or `233.252.0.0/24`. Both are IANA special-purpose ranges that
no operator can be allocated: `192.88.99.0/24` is the deprecated 6to4 relay
anycast prefix (RFC 7526) and `233.252.0.0/24` is MCAST-TEST-NET (RFC 5771).
Both are still `ipaddress.is_global`, which is what decides whether origin-IP
extraction keeps an address — the RFC 5737 documentation ranges (`192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24`) are classified *private* by that check and
get filtered out, so they cannot exercise this path at all. So no address here
attributes phishing to anybody's real infrastructure.

The only real addresses are accurate ones: the GitHub, Google and Mailchimp
relays in the benign samples, so those look like the genuine notifications they
imitate.

**About the domains:** these are invented, but they sit in live, registrable
TLDs (`.top`, `.icu`, `.xyz`, `.com`) rather than in `.invalid` or `.example`,
and one sample uses a real shortener host with an invented path. That is
deliberate and unavoidable: the checks these samples demonstrate — eTLD+1
comparison, anchor-text mismatch, punycode lookalikes — go through the Public
Suffix List, and the reserved TLDs are not in it, so `.invalid` and `.example`
have no registrable domain and the signals simply stop firing. The tool never
resolves or fetches a URL from an email, so nothing here is reachable by running
phish-check; the residual caveat is that a fabricated domain could be registered
by someone later, so treat these as strings to read, not destinations to visit.

The freemail senders end in `@gmail.com` because that is what the BEC and
freemail-Reply-To signals key on, but their local parts contain a hyphen —
which Gmail does not permit in a username — so they cannot belong to anyone.

Each sample exercises a different part of the pipeline. Expected verdicts
below are for offline runs (`--no-llm --no-enrich`, rule-based); with an
OpenAI key the judge weighs the content too.

```bash
uv run phish-check sample-emails/01-credential-phish.eml --no-llm --no-enrich
```

| Sample | Demonstrates | Offline verdict (exit) |
|---|---|---|
| `01-credential-phish.eml` | Lookalike domain, DMARC fail, freemail Reply-To, display-name spoof, anchor-text mismatch | malicious (2) |
| `02-benign-notification.eml` | Passing SPF/DKIM/DMARC, matching links, List-Unsubscribe | benign (0) |
| `03-safelinks-hidden-target.eml` | SafeLinks-rewrapped URL unwrapped to reveal the real target | suspicious (1) |
| `04-prompt-injection.eml` | Hidden AI-classifier instructions (inverted to evidence), tiny-font text, zero-width chars | suspicious (1) |
| `05-invoice-malware.eml` | Double-extension executable attachment, IP-literal link | malicious (2) |
| `06-bec-gift-cards.eml` | Pure social engineering, zero technical IOCs — rules can't see it; the LLM judge flags it | benign (0) offline |
| `07-forwarded-phish.eml` | Phish forwarded as a message/rfc822 attachment; nested payload extracted and hashed | suspicious (1) |
| `08-body-only-paste.txt` | Headerless pasted text via stdin (`phish-check < file`), defanged URL refanged on extraction, URL-shortener lure | inconclusive (0) |
| `09-punycode-lookalike.eml` | Punycode/IDN homoglyph domain | suspicious (1) |
