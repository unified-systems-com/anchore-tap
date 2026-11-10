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
    not evidence of running. No ``last_seen``, or one that cannot be read, is not fresh. The
    window is applied on both sides of ``now``: a ``last_seen`` a little ahead of ours is a clock
    that runs fast and is fresh, but one further ahead than the window is not evidence of
    anything, and would otherwise count as running for as long as its date stays in the future.
    """
    seen = parse_time(last_seen)
    return seen is not None and abs(now - seen) <= timedelta(hours=max_age_hours)


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


_ECS_ARN = re.compile(r"^arn:(aws[a-z-]*):ecs:([a-z0-9-]+):([0-9]{12}):(container|task|service|cluster)/(.+)$")


@dataclass(frozen=True)
class EcsArn:
    """An ECS ARN taken apart: ``arn:<partition>:ecs:<region>:<account>:<kind>/<path>``."""

    partition: str
    region: str
    account: str
    kind: str
    path: str

    @property
    def last(self) -> str:
        """The last path segment: a cluster's or service's name, a task's or container's id."""
        return self.path.rsplit("/", 1)[-1]

    def same_place(self, other: EcsArn) -> bool:
        return (self.partition, self.region, self.account) == (other.partition, other.region, other.account)


def parse_ecs_arn(arn: Any, kind: str) -> EcsArn | None:
    """The parts of a well-formed ECS ARN of this resource kind, else None (req-anchore-shared-12)."""
    match = _ECS_ARN.fullmatch(arn) if isinstance(arn, str) else None
    if match is None or match.group(4) != kind:
        return None
    return EcsArn(match.group(1), match.group(2), match.group(3), kind, match.group(5))


def _flat_tags(value: Any) -> dict[str, str] | None:
    """A tag map as aws_core holds one, string keys to string values, or None when it is not one."""
    if isinstance(value, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        return dict(value)
    return None


@dataclass
class EcsPlan:
    """The ECS nodes a run may create and the edges between them, by ARN (req-anchore-shared, rules 6 to 9).

    Nothing here says a node is absent from the grid: the collector asks that and creates only
    what is. Each node maps its ARN to the fields Anchore reported for it.
    """

    containers: dict[str, dict[str, Any]] = field(default_factory=dict)
    tasks: dict[str, dict[str, Any]] = field(default_factory=dict)
    services: dict[str, dict[str, Any]] = field(default_factory=dict)
    clusters: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: (edge kind, from ARN, to ARN): ``RUNS_CONTAINER``, ``RUNS_TASK`` or ``RUNS_SERVICE``.
    edges: list[tuple[str, str, str]] = field(default_factory=list)
    #: Selected containers whose own ARN, or an ancestor's, failed a check; nothing is created for them.
    rejected: int = 0


def plan_ecs_creation(
    containers: Iterable[Mapping[str, Any]],
    tasks: Iterable[Mapping[str, Any]],
    services: Iterable[Mapping[str, Any]],
    settings: Settings,
) -> EcsPlan:
    """What ``create.ecs`` may create: the selected containers and the ancestors each leads to by ARN.

    A container is taken only when its ARN is a well-formed ECS container ARN, its account is a
    listed one where ``aws_account_ids`` is set, and its task, and that task's service and
    cluster, are well-formed ECS ARNs in the same partition, region and account. One that fails
    creates nothing, neither it nor its ancestors. A task or service no selected container leads
    to is never in the plan, whatever the lists hold.
    """
    plan = EcsPlan()
    task_records = {t.get("arn"): t for t in tasks if isinstance(t.get("arn"), str)}
    service_records = {s.get("arn"): s for s in services if isinstance(s.get("arn"), str)}
    edges: set[tuple[str, str, str]] = set()
    for container in containers:
        arn = parse_ecs_arn(container.get("arn"), "container")
        task = parse_ecs_arn(container.get("task_arn"), "task")
        if arn is None or task is None or not arn.same_place(task):
            plan.rejected += 1
            continue
        if settings.aws_account_ids and arn.account not in settings.aws_account_ids:
            plan.rejected += 1
            continue
        task_arn = container["task_arn"]
        record = task_records.get(task_arn, {})
        # An empty service or cluster ARN is "none reported"; a present one must be well formed and consistent.
        service_arn, cluster_arn = record.get("service_arn") or None, record.get("cluster_arn") or None
        service = parse_ecs_arn(service_arn, "service") if service_arn else None
        service_record = service_records.get(service_arn, {}) if service_arn else {}
        cluster_arn = cluster_arn or service_record.get("cluster_arn") or None
        cluster = parse_ecs_arn(cluster_arn, "cluster") if cluster_arn else None
        if (service_arn and (service is None or not arn.same_place(service))) or (cluster_arn and (cluster is None or not arn.same_place(cluster))):
            plan.rejected += 1
            continue
        plan.containers[container["arn"]] = {"image": container.get("image_tag"), "image_digest": container.get("image_digest")}
        plan.tasks[task_arn] = {
            "cluster_arn": cluster_arn,
            "task_definition_arn": record.get("task_definition_arn") or None,
            "tags": _flat_tags(record.get("tags")),
        }
        edges.add(("RUNS_CONTAINER", task_arn, container["arn"]))
        if service_arn:
            plan.services[service_arn] = {"tags": _flat_tags(service_record.get("tags"))}
            edges.add(("RUNS_TASK", service_arn, task_arn))
        if cluster_arn:
            plan.clusters[cluster_arn] = {}
            edges.add(("RUNS_TASK", cluster_arn, task_arn))
            if service_arn:
                edges.add(("RUNS_SERVICE", cluster_arn, service_arn))
    plan.edges = sorted(edges)
    return plan
