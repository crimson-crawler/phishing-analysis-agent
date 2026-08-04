# Security policy

`phish-check` is published as a demonstration of the
[Crimson Crawler](https://crimsoncrawler.com) API. It is not an accept-contributions
project and has no pull-request workflow — but it is a security tool that parses hostile
input, so we do want to hear about vulnerabilities in it.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/crimson-crawler/phishing-analysis-agent/security/advisories/new)
on this repository. That keeps the report confidential until a fix is published.

Please include, as far as you can:

- what the issue is and why it matters
- a minimal input or command that reproduces it (a crafted `.eml` is ideal)
- the version or commit you tested
- what you think an attacker gains

We aim to acknowledge a report within 5 working days and to agree a disclosure timeline
with you from there. We'll credit you when the fix ships unless you'd rather we didn't.

## What we consider a vulnerability here

This tool reads **attacker-authored input by design**. Reports in these areas are the ones
we care most about:

- **Prompt injection reaching the judge.** The model must never receive raw HTML or raw
  headers, email content must never escape the untrusted-data delimiters in `judge.py`,
  attacker-authored free text must never be quoted into an `Evidence` description (that
  list is the prompt's trusted zone), and the model must never be able to forge an
  evidence ID.
- **Output escape.** Reports are defanged and control-stripped so they're safe to paste
  into a ticket or a terminal. A live URL, an ANSI escape, or a bidi override reaching
  output is a bug.
- **Parser crashes or resource exhaustion** from a crafted message.
- **Credential handling** — anything causing an API key to be logged, printed, or sent to
  an endpoint other than the configured one.

### Not vulnerabilities

- **Verdict accuracy.** Missing a phish or flagging a legitimate email is detection quality,
  not a security issue. The checks are deliberately a sample rather than a complete set —
  see "Scope" in the README.
- **Dependency CVEs with no reachable path in this code.** Report those upstream; do tell us
  if the path *is* reachable here.
- **The bundled `sample-emails/`.** Those are fabricated demonstration inputs containing no
  real data and no live payloads: the attachment "payloads" are inert stubs with no
  executable code, and every fabricated IP is in an IANA special-purpose range no operator
  can be allocated. The invented domains do sit in registrable TLDs, for a reason
  `sample-emails/README.md` explains — the tool never resolves or fetches them, but read
  that note before treating one as a destination.

## Supported versions

Pre-1.0. Only the latest commit on `main` is supported; there are no backported fixes.

## Analyzing real suspicious email safely

`phish-check` never fetches a URL out of an email and never executes an attachment. With
`--no-llm --no-enrich` it touches no network at all. Without those flags, indicators go to
the Crimson Crawler API and sanitized visible text goes to OpenAI — see "What leaves your
machine" in the README before pointing it at confidential mail.
