"""Stage 4: enrich indicators via the Crimson Crawler API.

One POST /v1/assess/ioc-portfolio call covers the whole email (max 50
indicators, counting as a single request against your API plan's rate limit).
--deep N adds per-IOC /v1/enrich/ioc calls, which are the only way to get CC's
per-indicator threat_assessment verdict.
"""

from __future__ import annotations

import os
import time

import httpx

from .defang import defang, defang_text, strip_controls
from .endpoints import checked_base_url
from .models import (
    EnrichmentMeta,
    Evidence,
    FeedHit,
    Indicator,
    IndicatorEnrichment,
    severity_rank,
)

DEFAULT_BASE_URL = "https://crimsoncrawler.com"
PORTFOLIO_MAX = 50
# The batch cap bounds the indicator *count*, not the payload: one crafted link
# can be megabytes of URL. Cap each value too, so a request is at most
# PORTFOLIO_MAX * MAX_IOC_CHARS of indicator data. Over-long values are dropped
# rather than truncated — a truncated IOC is a different IOC, and asking CC
# about it would produce a confidently wrong answer.
MAX_IOC_CHARS = 2048

# phish-check type -> MISP attribute type used by CC.
CC_TYPE_MAP = {
    "url": "url",
    "domain": "domain",
    "hostname": "hostname",
    "ip": "ip-dst",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "email": "email",
}

# The portfolio endpoint does not accept "warninglist" as an include value;
# warninglist_hits are returned regardless, so it is omitted here.
PORTFOLIO_INCLUDE = ["misp_attributes", "techniques", "tie", "summary"]
DEEP_INCLUDE = ["misp_attributes", "warninglist", "tie"]


class CrimsonCrawlerClient:
    def __init__(self, api_key: str, base_url: str | None = None, timeout: float = 60.0):
        resolved = base_url or os.environ.get("CRIMSON_CRAWLER_BASE_URL") or DEFAULT_BASE_URL
        # Gate the endpoint before the `apikey` header below can travel to it.
        self._client = httpx.Client(
            base_url=checked_base_url(resolved, "CRIMSON_CRAWLER_BASE_URL"),
            headers={"apikey": api_key, "content-type": "application/json"},
            timeout=timeout,
        )

    def close(self) -> None:
        self._client.close()

    def _post(self, path: str, body: dict) -> dict:
        for attempt in range(3):
            resp = self._client.post(path, json=body)
            if resp.status_code == 429 and attempt < 2:
                try:
                    delay = float(resp.headers.get("Retry-After", ""))
                except ValueError:  # absent, or the HTTP-date form
                    delay = float(2 ** (attempt + 1))
                time.sleep(min(max(delay, 0.0), 60.0))
                continue
            resp.raise_for_status()
            data = resp.json()
            if not isinstance(data, dict):
                # ValueError so it lands in the same handler as non-JSON 200s.
                raise ValueError(f"unexpected response shape: {type(data).__name__}")
            return data
        raise RuntimeError("unreachable")

    def assess_portfolio(self, indicators: list[dict]) -> dict:
        return self._post(
            "/v1/assess/ioc-portfolio",
            {"indicators": indicators, "include": PORTFOLIO_INCLUDE},
        )

    def enrich_ioc(self, value: str, ioc_type: str) -> dict:
        return self._post(
            "/v1/enrich/ioc",
            {"value": value, "type": ioc_type, "include": DEEP_INCLUDE},
        )


# The response may come from an arbitrary --base-url server; a shape surprise
# must degrade, never raise — an escape after a successful call would discard
# enrichment the request has already spent against the plan's rate limit.
def _dict_list(value) -> list[dict]:
    if not isinstance(value, list):
        return []
    return [v for v in value if isinstance(v, dict)]


def _str_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(v) for v in value]


def _as_float(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


# Feed names, tags, malware names and warninglist names are API-echoed strings.
# The API is first-party, but the *content* of a MISP tag or feed name is not:
# it travels from whatever feed produced it, and an Evidence description is the
# judge's trusted zone. Bound each label and the joined list so no amount of
# upstream text can turn a verified fact into a paragraph of instructions.
MAX_LABEL_CHARS = 60
MAX_LABELS_CHARS = 240


def _safe(text: str) -> str:
    """Defang + control-strip API-echoed free text before it enters an
    Evidence description (done at build time so rendered reports stay safe)."""
    return defang_text(strip_controls(text))


def _safe_labels(labels: list[str]) -> str:
    """`_safe`, plus the per-label and total caps that keep API-echoed text from
    dominating a trusted evidence line."""
    joined = ", ".join(_safe(label)[:MAX_LABEL_CHARS] for label in labels)
    return joined[:MAX_LABELS_CHARS] + "..." if len(joined) > MAX_LABELS_CHARS else joined


def _feed_hits(raw) -> list[FeedHit]:
    return [
        FeedHit(
            name=str(f.get("name") or ""),
            provider=str(f.get("provider") or ""),
            url=str(f.get("url") or ""),
        )
        for f in _dict_list(raw)
        if f.get("name")
    ]


def _match(indicator: Indicator, value: str) -> bool:
    return value.strip().lower() == indicator.value.lower()


def _apply_attributes(indicators: list[Indicator], attributes) -> None:
    for attr in _dict_list(attributes):
        value = str(attr.get("value", ""))
        for ind in indicators:
            if not _match(ind, value):
                continue
            e = ind.enrichment or IndicatorEnrichment()
            e.misp_matched = True
            for hit in _feed_hits(attr.get("feed_hits")):
                if hit.name not in [h.name for h in e.feed_hits]:
                    e.feed_hits.append(hit)
            e.tags = sorted(set(e.tags) | set(_str_list(attr.get("tags"))))
            e.actors = sorted(set(e.actors) | set(_str_list(attr.get("actors"))))
            e.malware = sorted(set(e.malware) | set(_str_list(attr.get("malware"))))
            e.first_seen = e.first_seen or str(attr.get("first_seen") or "")
            e.last_seen = e.last_seen or str(attr.get("last_seen") or "")
            e.to_ids = e.to_ids or bool(attr.get("to_ids"))
            e.sighting_count += _as_int(attr.get("sighting_count"))
            ind.enrichment = e


def _apply_warninglists(indicators: list[Indicator], hits) -> None:
    for wl in _dict_list(hits):
        if not wl.get("is_on_warninglist"):
            continue
        value = str(wl.get("value", ""))
        names = _str_list(wl.get("warninglists"))
        for ind in indicators:
            if _match(ind, value):
                e = ind.enrichment or IndicatorEnrichment()
                e.on_warninglist = True
                e.warninglists = names
                ind.enrichment = e


def _enrichment_evidence(
    indicators: list[Indicator], meta: EnrichmentMeta, start_id: int
) -> list[Evidence]:
    out: list[Evidence] = []

    def add(severity: str, description: str, indicator: str | None = None):
        out.append(
            Evidence(
                id=f"E{start_id + len(out)}",
                category="enrichment",
                severity=severity,
                description=description,
                indicator=indicator,
            )
        )

    if meta.portfolio_feed_hits:
        # Feed names/providers are API-echoed free text — defanged and bounded
        # at build time, because this description reaches the judge as fact.
        feeds = _safe_labels(
            [h.name + (f" ({h.provider})" if h.provider else "") for h in meta.portfolio_feed_hits]
        )
        # Portfolio feed hits are deduped across the batch and unattributable
        # per-indicator — when no indicator matched at all, or when every
        # MISP-matched indicator sits on a false-positive warninglist (8.8.8.8
        # in an OSINT feed), a high here would tip rules_verdict() into
        # MALICIOUS on a benign newsletter.
        # Medium, not info: feed hits aren't guaranteed to originate from a
        # misp_attributes-matched indicator, so a weak attribution must not
        # fully suppress a possibly-genuine correlation — it just must not be
        # the sole signal that tips rules_verdict() to malicious.
        matched = [i.enrichment for i in indicators if i.enrichment and i.enrichment.misp_matched]
        if matched and all(e.on_warninglist for e in matched):
            add(
                "medium",
                "Indicators in this email correlate with threat feed(s): "
                f"{feeds} — but every matched indicator is on a false-positive "
                "warninglist (shared infrastructure); verify before acting.",
            )
        elif not matched:
            add(
                "medium",
                "Indicators in this email correlate with threat feed(s): "
                f"{feeds} — but the correlation is not attributable to any "
                "specific indicator in this email; verify before acting.",
            )
        else:
            add(
                "high",
                "Indicators in this email correlate with threat feed(s): "
                f"{feeds} (Crimson Crawler cross-feed correlation).",
            )

    for ind in indicators:
        e = ind.enrichment
        if e is None:
            continue
        if e.feed_hits:
            feeds = _safe_labels(
                [f"{h.name}" + (f" ({h.provider})" if h.provider else "") for h in e.feed_hits]
            )
            desc = f"{ind.type} is listed on threat feed(s): {feeds}."
            if e.last_seen:
                desc += f" Last seen {_safe(e.last_seen)[:MAX_LABEL_CHARS]}."
            if e.malware:
                desc += f" Associated malware: {_safe_labels(e.malware[:5])}."
            add("high", desc, ind.value)
        elif e.misp_matched and not e.on_warninglist:
            desc = f"{ind.type} matches a known indicator in MISP threat events."
            if e.tags:
                desc += f" Tags: {_safe_labels(e.tags[:6])}."
            if e.malware:
                desc += f" Associated malware: {_safe_labels(e.malware[:5])}."
            add("high", desc, ind.value)
        if e.threat_verdict in ("high_threat", "medium_threat"):
            score = "n/a" if e.threat_score is None else f"{e.threat_score:.2f}"
            conf = "n/a" if e.threat_confidence is None else f"{e.threat_confidence:.2f}"
            add(
                "high" if e.threat_verdict == "high_threat" else "medium",
                f"Crimson Crawler threat assessment for this {ind.type}: "
                f"{e.threat_verdict.replace('_', ' ')} "
                f"(score {score}, confidence {conf}).",
                ind.value,
            )
        if e.on_warninglist:
            add(
                "info",
                f"{ind.type} appears on false-positive warninglist(s): "
                f"{_safe_labels(e.warninglists[:3])} — hits on it are likely "
                "benign infrastructure.",
                ind.value,
            )
    return out


def _deep_candidates(indicators: list[Indicator], evidence: list[Evidence], n: int):
    """Pick the N most suspicious indicators: feed hits first, then ones with
    the highest-severity deterministic evidence."""
    if n <= 0:  # negative n must not slice into "nearly all" (quota burn)
        return []
    by_value: dict[str, int] = {}
    for ev in evidence:
        if ev.indicator:
            by_value[ev.indicator] = max(by_value.get(ev.indicator, 0), severity_rank(ev.severity))
    scored = sorted(
        (
            i
            for i in indicators
            if not i.noise and i.type in CC_TYPE_MAP and len(i.value) <= MAX_IOC_CHARS
        ),
        key=lambda i: (
            not (i.enrichment and i.enrichment.misp_matched),  # confirmed hits first
            -(len(i.enrichment.feed_hits) if i.enrichment else 0),
            -by_value.get(i.value, 0),
        ),
    )
    return scored[:n]


def enrich(
    indicators: list[Indicator],
    evidence: list[Evidence],
    api_key: str,
    base_url: str | None = None,
    deep: int = 0,
) -> tuple[list[Evidence], EnrichmentMeta]:
    """Enrich in place; returns (new enrichment evidence, meta). `evidence` is
    the deterministic evidence list — used only to rank --deep candidates and
    to continue the E<n> id sequence."""
    meta = EnrichmentMeta(enabled=True)
    client = CrimsonCrawlerClient(api_key, base_url)
    try:
        eligible = [
            i for i in indicators if i.type in CC_TYPE_MAP and len(i.value) <= MAX_IOC_CHARS
        ]
        oversized = sum(
            1 for i in indicators if i.type in CC_TYPE_MAP and len(i.value) > MAX_IOC_CHARS
        )
        if oversized:  # named, not silently dropped
            meta.errors.append(
                f"{oversized} indicator(s) not submitted: longer than {MAX_IOC_CHARS} characters"
            )
        ranked = sorted(eligible, key=lambda i: i.noise)  # non-noise first, order kept
        batch = ranked[:PORTFOLIO_MAX]
        meta.indicators_submitted = len(batch)
        meta.indicators_truncated = len(eligible) - len(batch)

        if batch:
            payload = [{"value": i.value, "type": CC_TYPE_MAP[i.type]} for i in batch]
            try:
                resp = client.assess_portfolio(payload)
                meta.api_calls += 1
                _apply_attributes(indicators, resp.get("misp_attributes") or [])
                _apply_warninglists(indicators, resp.get("warninglist_hits") or [])
                meta.portfolio_feed_hits = _feed_hits(resp.get("misp_feed_hits"))
                # API-echoed free text names live IOCs — defang at build time.
                meta.portfolio_summary = defang_text(strip_controls(str(resp.get("summary") or "")))
                errs = resp.get("errors")
                for err in errs if isinstance(errs, list) else []:
                    if isinstance(err, dict):
                        err = err.get("message") or err
                    meta.errors.append(defang_text(strip_controls(str(err))))
            # ValueError covers JSONDecodeError on a non-JSON 200 body — an
            # escape here after a successful call would discard enrichment
            # the quota already paid for.
            except (httpx.HTTPError, ValueError) as exc:
                meta.errors.append(f"portfolio assessment failed: {exc}")

        for ind in _deep_candidates(indicators, evidence, deep):
            try:
                resp = client.enrich_ioc(ind.value, CC_TYPE_MAP[ind.type])
                meta.api_calls += 1
            except (httpx.HTTPError, ValueError) as exc:
                meta.errors.append(
                    f"deep enrichment of {defang(ind.value, ind.type)} failed: {exc}"
                )
                continue
            _apply_attributes([ind], resp.get("misp_attributes") or [])
            # On the single-IOC endpoint the top-level feed hits belong to this
            # indicator — the only place CC attributes feeds per-indicator.
            deep_hits = _feed_hits(resp.get("misp_feed_hits"))
            if deep_hits:
                e = ind.enrichment or IndicatorEnrichment()
                for hit in deep_hits:
                    if hit.name not in [h.name for h in e.feed_hits]:
                        e.feed_hits.append(hit)
                ind.enrichment = e
            ta = resp.get("threat_assessment")
            if isinstance(ta, dict):
                e = ind.enrichment or IndicatorEnrichment()
                e.threat_verdict = str(ta.get("verdict") or "")
                e.threat_score = _as_float(ta.get("threat_score"))
                e.threat_confidence = _as_float(ta.get("confidence"))
                ind.enrichment = e
    finally:
        client.close()

    new_evidence = _enrichment_evidence(indicators, meta, start_id=len(evidence) + 1)
    return new_evidence, meta
