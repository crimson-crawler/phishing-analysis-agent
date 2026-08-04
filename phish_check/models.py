"""Plain-data types passed between pipeline stages."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# Severity levels, in ascending order.
SEVERITIES = ("info", "low", "medium", "high")

VERDICTS = ("benign", "inconclusive", "suspicious", "malicious")


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    md5: str
    sha1: str
    sha256: str


@dataclass
class Link:
    """A hyperlink from an HTML body part."""

    href: str
    text: str  # visible anchor text ("" if none)
    source: str = "href"  # href | src | iframe-src | form-action | meta-refresh


@dataclass
class HtmlAnalysis:
    links: list[Link] = field(default_factory=list)
    visible_text: str = ""
    hidden_texts: list[str] = field(default_factory=list)
    has_zero_width_chars: bool = False
    form_actions: list[str] = field(default_factory=list)


@dataclass
class AuthResults:
    """Parsed from the topmost Authentication-Results header.

    "Topmost" is a heuristic, not proof of origin: in an arbitrary .eml nothing
    says the receiving MTA added that header. The trust fields below record how
    much corroboration there is — see parser._parse_auth_results.
    """

    spf: str | None = None
    dkim: str | None = None
    dmarc: str | None = None
    raw: str | None = None
    header_count: int = 0  # how many Authentication-Results headers were present
    authserv_id: str = ""  # who the topmost header claims to be
    # True when `authserv_id` matches a host that actually appears as a
    # receiving ("by") host in the Received chain. False means the results are
    # self-asserted: nothing in the message ties them to a delivering MTA.
    corroborated: bool = False
    # Methods where a *lower* Authentication-Results header contradicts the
    # topmost one — the signature of forged copies pre-inserted by the sender.
    conflicts: list[str] = field(default_factory=list)


@dataclass
class ParsedEmail:
    subject: str = ""
    from_display: str = ""
    from_addr: str = ""
    reply_to_addr: str = ""
    return_path: str = ""
    to_addrs: list[str] = field(default_factory=list)
    message_id: str = ""
    date: str = ""
    received: list[str] = field(default_factory=list)
    origin_ip: str = ""
    auth_results: AuthResults = field(default_factory=AuthResults)
    has_list_unsubscribe: bool = False
    text_body: str = ""
    html: HtmlAnalysis = field(default_factory=HtmlAnalysis)
    attachments: list[Attachment] = field(default_factory=list)
    headers_only_input: bool = False  # input wasn't a parseable RFC 5322 message

    @property
    def from_domain(self) -> str:
        return self.from_addr.rsplit("@", 1)[-1].lower() if "@" in self.from_addr else ""

    @property
    def reply_to_domain(self) -> str:
        return self.reply_to_addr.rsplit("@", 1)[-1].lower() if "@" in self.reply_to_addr else ""

    @property
    def return_path_domain(self) -> str:
        return self.return_path.rsplit("@", 1)[-1].lower() if "@" in self.return_path else ""

    @property
    def visible_text(self) -> str:
        return self.html.visible_text or self.text_body


@dataclass
class FeedHit:
    name: str
    provider: str = ""
    url: str = ""


@dataclass
class IndicatorEnrichment:
    misp_matched: bool = False  # value matched a MISP attribute in CC
    feed_hits: list[FeedHit] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    actors: list[str] = field(default_factory=list)
    malware: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    to_ids: bool = False
    sighting_count: int = 0
    on_warninglist: bool = False
    warninglists: list[str] = field(default_factory=list)
    # From /v1/enrich/ioc --deep only:
    threat_verdict: str = ""
    threat_score: float | None = None
    threat_confidence: float | None = None


@dataclass
class Indicator:
    value: str  # normalized, fanged (real) form — defang only at render time
    type: str  # url | domain | hostname | ip | md5 | sha1 | sha256 | email
    source: str  # body-html | body-text | header-received | header-sender | attachment
    display_text: str | None = None  # anchor text, for text-vs-href mismatch
    unwrapped_from: str | None = None  # original rewrapped URL, if any
    noise: bool = False  # display-suppressed but still enriched when budget allows
    enrichment: IndicatorEnrichment | None = None


@dataclass
class Evidence:
    id: str  # "E7" — the LLM cites these
    category: str  # auth | header | link | content | attachment | enrichment
    severity: str  # info | low | medium | high
    description: str  # human-readable, self-contained; reaches the judge as trusted fact
    indicator: str | None = None  # Indicator.value this evidence is about, if any
    # Attacker-controlled free text (currently only attachment filenames), already
    # defanged and bounded, carried for the *report* alone. Descriptions land in the
    # judge's trusted EVIDENCE zone, so unbounded prose must never go there — this
    # field is deliberately omitted from the prompt. See signals._attachment_checks.
    untrusted_detail: str | None = None


@dataclass
class Reason:
    evidence_id: str
    weight: str  # low | medium | high
    explanation: str


@dataclass
class Verdict:
    verdict: str  # malicious | suspicious | benign | inconclusive
    confidence: float
    summary: str
    reasons: list[Reason] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    source: str = "rules"  # rules | llm


@dataclass
class EnrichmentMeta:
    enabled: bool = False
    disabled_by_flag: bool = False  # skipped via --no-enrich, not a missing key
    api_calls: int = 0
    indicators_submitted: int = 0
    indicators_truncated: int = 0
    portfolio_summary: str = ""
    # Deduped feed correlations for the whole email; CC only attributes feeds
    # per-indicator on the single-IOC deep endpoint.
    portfolio_feed_hits: list[FeedHit] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class Report:
    email: ParsedEmail
    indicators: list[Indicator]
    evidence: list[Evidence]
    verdict: Verdict
    enrichment: EnrichmentMeta

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # The raw bodies/headers are large and attacker-controlled; keep JSON
        # output lean (and free of live IOCs the defang pass can't reach —
        # the raw Authentication-Results header carries live domains/IPs).
        d["email"].pop("received", None)
        d["email"]["html"].pop("visible_text", None)
        d["email"].pop("text_body", None)
        d["email"]["auth_results"].pop("raw", None)
        return d


def severity_rank(sev: str) -> int:
    return SEVERITIES.index(sev) if sev in SEVERITIES else 0
