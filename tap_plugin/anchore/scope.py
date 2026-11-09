"""Collection scope: which images a run reads and which inventory records count as running (req-anchore-scope).

Pure functions over what Anchore returned and what the operator configured. This module imports
no Django and no ``tap_*`` app, makes no request and reads no grid: the collector fetches, this
decides. Everything Anchore-shaped here is taken from the vendor's OpenAPI file (2.20.0) and not
from a recorded response.
"""

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

#: A digest that can name an image host: ``sha256:`` and 64 lower-case hex characters.
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")

DEFAULT_MAX_AGE_HOURS = 24


@dataclass(frozen=True)
class Settings:
    """The operator's scope and creation settings, with the defaults of ``req-anchore-scope``.

    ``running_only`` has no default: the envelope must state it (req-anchore-scope-1). A list
    setting that is empty here was absent from the envelope: the schema refuses an empty list, so
    "configured to select nothing" cannot reach this class.
    """

    running_only: bool
    aws_account_ids: tuple[str, ...] = ()
    context_prefixes: tuple[str, ...] = ()
    repository_prefixes: tuple[str, ...] = ()
    inventory_max_age_hours: int = DEFAULT_MAX_AGE_HOURS
    create_kubernetes: bool = True
    create_ecs: bool = False

    @classmethod
    def from_data(cls, data: Mapping[str, Any]) -> Settings:
        """Build from an envelope's validated ``data``. Absent optional keys take the defaults.

        Raises KeyError when ``scope.running_only`` is missing; the schema refuses that envelope first.
        """
        # WORKAROUND(unified-systems-com/tap#907): these settings live in the credential envelope
        # because tap has no per-run collector configuration yet.
        scope = data["scope"]
        create = data.get("create") or {}
        return cls(
            running_only=scope["running_only"],
            aws_account_ids=tuple(scope.get("aws_account_ids", ())),
            context_prefixes=tuple(scope.get("context_prefixes", ())),
            repository_prefixes=tuple(scope.get("repository_prefixes", ())),
            inventory_max_age_hours=data.get("inventory_max_age_hours", DEFAULT_MAX_AGE_HOURS),
            create_kubernetes=create.get("kubernetes", True),
            create_ecs=create.get("ecs", False),
        )

    @property
    def has_running_selector(self) -> bool:
        return bool(self.aws_account_ids or self.context_prefixes)

    def as_recorded(self) -> dict[str, Any]:
        """The settings as the scan run records them (req-anchore-scope-14). No secret is among them."""
        return {
            "scope": {
                "running_only": self.running_only,
                "aws_account_ids": list(self.aws_account_ids),
                "context_prefixes": list(self.context_prefixes),
                "repository_prefixes": list(self.repository_prefixes),
            },
            "inventory_max_age_hours": self.inventory_max_age_hours,
            "create": {"kubernetes": self.create_kubernetes, "ecs": self.create_ecs},
        }


def account_of_arn(arn: Any) -> str | None:
    """The account id in an AWS ARN (its fifth colon-separated field), or None when there is none.

    ``arn:partition:service:region:account-id:resource``. Only a 12-digit account is returned;
    anything else (not a string, too few fields, an empty or malformed account) is None.
    """
    if not isinstance(arn, str):
        return None
    parts = arn.split(":", 5)
    if len(parts) < 6 or parts[0] != "arn":
        return None
    return parts[4] if re.fullmatch(r"[0-9]{12}", parts[4]) else None


def parse_time(value: Any) -> datetime | None:
    """An RFC 3339 timestamp as an aware datetime, or None when it is absent or not one."""
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00") if value.endswith("Z") else value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def is_fresh(last_seen: Any, now: datetime, max_age_hours: int) -> bool:
    """Whether a record was seen recently enough to count as running (req-anchore-scope-4).

    Anchore keeps a record for up to 120 days after its agent last reported it, so presence is
    not evidence of running. No ``last_seen``, or one that cannot be read, is not fresh. A
    ``last_seen`` in the future (a clock ahead of ours) is fresh.
    """
    seen = parse_time(last_seen)
    return seen is not None and now - seen <= timedelta(hours=max_age_hours)


def _starts_with_any(value: Any, prefixes: Iterable[str]) -> bool:
    return isinstance(value, str) and any(value.startswith(prefix) for prefix in prefixes)


def _digest(value: Any) -> str | None:
    return value if isinstance(value, str) and DIGEST.fullmatch(value) else None


@dataclass
class Running:
    """What a run's running selection came to."""

    #: The selected inventory items, each ``{inventory_type, context, image_digest, ...}`` as returned.
    items: list[Mapping[str, Any]] = field(default_factory=list)
    #: The in-scope ECS container records, as returned, for linking and creation.
    ecs_containers: list[Mapping[str, Any]] = field(default_factory=list)
    #: Inventory items older than the window, or with no readable ``last_seen``.
    stale: int = 0
    #: Records with no digest that can name an image host.
    no_digest: int = 0
    #: ECS containers with no inventory item for their context and digest, so no ``last_seen``.
    ecs_without_inventory: int = 0

    @property
    def digests(self) -> set[str]:
        return {item["image_digest"] for item in self.items}


def select_running(
    inventory: Iterable[Mapping[str, Any]],
    ecs_containers: Iterable[Mapping[str, Any]],
    settings: Settings,
    now: datetime,
) -> Running:
    """The inventory records that count as running and are in scope (req-anchore-scope-4 to -7).

    ``context_prefixes`` and ``aws_account_ids`` are a union; with neither set every running
    record is selected. An ECS container has no ``last_seen`` of its own and takes the one of the
    inventory item with its context and digest.
    """
    out = Running()
    fresh: dict[tuple[Any, str], Mapping[str, Any]] = {}
    selected: dict[tuple[Any, Any, str], Mapping[str, Any]] = {}
    for item in inventory:
        digest = _digest(item.get("image_digest"))
        if digest is None:
            out.no_digest += 1
            continue
        if not is_fresh(item.get("last_seen"), now, settings.inventory_max_age_hours):
            out.stale += 1
            continue
        fresh[(item.get("context"), digest)] = item
        if not settings.has_running_selector or _starts_with_any(item.get("context"), settings.context_prefixes):
            selected[(item.get("inventory_type"), item.get("context"), digest)] = item
    for container in ecs_containers:
        digest = _digest(container.get("image_digest"))
        if digest is None:
            out.no_digest += 1
            continue
        item = fresh.get((container.get("context"), digest))
        if item is None:
            out.ecs_without_inventory += 1
            continue
        in_scope = (
            not settings.has_running_selector
            or _starts_with_any(container.get("context"), settings.context_prefixes)
            or account_of_arn(container.get("arn")) in settings.aws_account_ids
        )
        if in_scope:
            out.ecs_containers.append(container)
            selected[(item.get("inventory_type"), item.get("context"), digest)] = item
    out.items = list(selected.values())
    return out


def passes_repository(image: Mapping[str, Any], prefixes: Iterable[str]) -> bool:
    """Whether an image record passes the repository filter (req-anchore-scope-8).

    True when no prefix is set, or when the registry, a slash, and the repo of at least one of the
    image's tags begin with a listed prefix, compared as written.
    """
    prefixes = tuple(prefixes)
    if not prefixes:
        return True
    details = image.get("image_detail")
    if not isinstance(details, list):
        return False
    for detail in details:
        if not isinstance(detail, Mapping):
            continue
        registry, repo = detail.get("registry"), detail.get("repo")
        if isinstance(registry, str) and isinstance(repo, str) and _starts_with_any(f"{registry}/{repo}", prefixes):
            return True
    return False


@dataclass
class ImagesToRead:
    """Which listed images a run reads, and the counts the scan run records (req-anchore-scope-14)."""

    digests: list[str] = field(default_factory=list)
    images_listed: int = 0
    images_selected: int = 0
    images_out_of_scope: int = 0
    #: Selected running digests Anchore's image list does not hold (req-anchore-scope-11).
    not_in_anchore: list[str] = field(default_factory=list)


def images_to_read(
    listed: Mapping[str, Mapping[str, Any]],
    running_digests: Iterable[str] | None,
    settings: Settings,
) -> ImagesToRead:
    """Combine the running selection with the repository filter (req-anchore-scope-3).

    ``listed`` is Anchore's image list by digest, one record per digest, in list order; the
    digests are returned in that order. ``running_digests`` is None when the running selection
    could not be read: with ``running_only`` that selects nothing (req-anchore-scope-9), never
    everything.
    """
    out = ImagesToRead()
    by_digest = listed
    out.images_listed = len(by_digest)
    if settings.running_only:
        wanted = set(running_digests or ())
        out.not_in_anchore = sorted(digest for digest in wanted if digest not in by_digest)
        candidates = [digest for digest in by_digest if digest in wanted]
    else:
        candidates = list(by_digest)
    out.digests = [digest for digest in candidates if passes_repository(by_digest[digest], settings.repository_prefixes)]
    out.images_selected = len(out.digests)
    out.images_out_of_scope = out.images_listed - out.images_selected
    return out
