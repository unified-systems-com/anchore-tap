"""The probe: ask the instance what it is before any data is read (req-anchore-probe).

``GET /account`` comes first and the run stops, writing nothing, unless it answers with exactly the
configured account (``req-anchore-probe-4``). ``/status``, ``/system`` and ``/system/feeds`` follow;
each is optional, because the hosted service may restrict the admin surface, and a read the instance
refuses, does not offer or cannot complete leaves its fields null and is listed as *not read* with
the reason, never as empty or healthy (``req-anchore-probe-2``, ``req-anchore-states``).

Reads only, through the read-only client; no grid, no Django. Messages name the credential's
qualified key and a class of failure, never an account or a response body.
"""

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from tap_plugin.anchore.client import ClientError, ReadOnlyClient, RequestFailed
from tap_plugin.anchore.collectors.anchore_collector.manifest import Source, shipped_manifest

READ = "read"
NOT_READ = "not_read"
_REFUSED = frozenset({401, 403})


class ProbeError(Exception):
    """The run cannot start: the account could not be verified."""


@dataclass(frozen=True)
class Outcome:
    """What one probe read produced. ``body`` is the parsed JSON when ``state`` is read, else None."""

    source_id: str
    state: str
    reason: str | None
    body: Any = None


@dataclass(frozen=True)
class ProbeResult:
    outcomes: dict[str, Outcome]
    reported_version: str | None
    feed_syncs: tuple[tuple[str, str | None, datetime | None], ...] = field(default=())

    def body(self, source_id: str) -> Any:
        outcome = self.outcomes.get(source_id)
        return outcome.body if outcome is not None and outcome.state == READ else None

    def not_read(self) -> list[dict[str, str]]:
        """The scan run's ``scopes_not_read`` entries for the probe sources that were not read."""
        return [
            {"scope": f"probe:{o.source_id}", "reason": o.reason or "not read"}
            for o in self.outcomes.values()
            if o.state == NOT_READ
        ]

    def stale_feeds(self, now: datetime, max_age: timedelta) -> list[dict[str, Any]]:
        """Feed groups whose last sync is older than ``max_age``, with the age (``req-anchore-probe-3``).

        A group whose last sync is unobserved is not called stale and not called fresh: it is
        absent from the answer and from ``feed_syncs`` as a datetime, so a caller can tell it apart.
        """
        out: list[dict[str, Any]] = []
        for feed, group, synced in self.feed_syncs:
            if synced is not None and now - synced > max_age:
                out.append({"feed": feed, "group": group, "last_sync": synced.isoformat(), "age_seconds": int((now - synced).total_seconds())})
        return out


def _parse_time(value: Any) -> datetime | None:
    """An ISO-8601 timestamp as Anchore writes it, or None when absent or not parseable."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _read(client: ReadOnlyClient, source: Source) -> Outcome:
    try:
        reply = client.get(source.path)
    except RequestFailed as exc:
        last = exc.reply.status if exc.reply is not None else None
        return Outcome(source.id, NOT_READ, f"failed after retries ({'HTTP ' + str(last) if last else 'no response'})")
    except ClientError as exc:
        return Outcome(source.id, NOT_READ, f"refused before sending ({type(exc).__name__})")
    if reply.status in _REFUSED:
        return Outcome(source.id, NOT_READ, f"refused (HTTP {reply.status})")
    if reply.status == 404:
        return Outcome(source.id, NOT_READ, "not offered (HTTP 404)")
    if reply.status != 200:
        return Outcome(source.id, NOT_READ, f"unexpected HTTP {reply.status}")
    try:
        return Outcome(source.id, READ, None, json.loads(reply.body))
    except ValueError:
        return Outcome(source.id, NOT_READ, "the body was not JSON")


def _feed_syncs(feeds: Any) -> tuple[tuple[str, str | None, datetime | None], ...]:
    if not isinstance(feeds, list):
        return ()
    out: list[tuple[str, str | None, datetime | None]] = []
    for feed in feeds:
        if not isinstance(feed, dict):
            continue
        name = str(feed.get("name") or feed.get("dataset_name") or "")
        groups = feed.get("groups")
        if isinstance(groups, list) and groups:
            out.extend((name, str(g.get("name")) if g.get("name") is not None else None, _parse_time(g.get("last_sync"))) for g in groups if isinstance(g, dict))
        else:
            out.append((name, None, _parse_time(feed.get("last_full_sync"))))
    return tuple(out)


def run_probe(client: ReadOnlyClient, account: str, sources: tuple[Source, ...] | None = None, *, qualified: str = "anchore") -> ProbeResult:
    """Read the account source first, then the other probe sources in manifest order.

    Raises ProbeError, with no other request made, unless the sources hold exactly one ``account``
    source; and raises it before reading anything else unless ``/account`` names ``account``.
    """
    probe_sources = [s for s in (sources if sources is not None else shipped_manifest()) if s.scope == "probe"]
    # The gate is enforced here and not left to the order or content of the list it is handed: exactly
    # one account source must exist, and it is read before any other request is made.
    accounts = [s for s in probe_sources if s.id == "account"]
    if len(accounts) != 1:
        raise ProbeError(f"{qualified}: the probe needs exactly one account source, found {len(accounts)}; nothing was read or written")
    outcomes: dict[str, Outcome] = {}
    for source in [accounts[0], *(s for s in probe_sources if s.id != "account")]:
        outcome = _read(client, source)
        outcomes[source.id] = outcome
        if source.id == "account":
            if outcome.state != READ:
                raise ProbeError(f"{qualified}: the account could not be read ({outcome.reason}); nothing was read or written")
            name = outcome.body.get("name") if isinstance(outcome.body, dict) else None
            if name != account:
                raise ProbeError(f"{qualified}: the instance's effective account is not the configured account; nothing was read or written")
    status = outcomes["status"].body if "status" in outcomes and outcomes["status"].state == READ else None
    version = status.get("version") if isinstance(status, dict) and isinstance(status.get("version"), str) else None
    feeds = outcomes["feeds"].body if "feeds" in outcomes and outcomes["feeds"].state == READ else None
    return ProbeResult(outcomes=outcomes, reported_version=version, feed_syncs=_feed_syncs(feeds))
