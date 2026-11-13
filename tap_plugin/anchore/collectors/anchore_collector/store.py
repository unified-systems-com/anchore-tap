"""What the grid already holds: the reads a run needs before it writes.

The scanner reads are of this plugin's own nodes; the host and vulnerability reads are existence
checks on two shared types (computing_core's image host, compliance_core's vulnerability), which
this plugin links to and never rewrites. All go through the models' default manager, which excludes
tombstoned rows and is guarded to a bound actor (the collector task binds one).

The ECS container read is of a type this plugin does not import: aws_core is an optional
dependency (req-anchore-shared-4), so its model is taken from the registry by name, and its
absence is an answer, not an error.
"""

from typing import Any

from tap_plugin.compliance_core.models.compliance_vulnerability import ComplianceVulnerability
from tap_plugin.computing_core.models.host import Host
from tap_plugin.computing_core.models.package import Package
from tap_plugin.computing_core.models.sbom_document import SbomDocument

from tap_grid.models import Edge
from tap_grid.registry import get_model_class
from tap_plugin.anchore import keys
from tap_plugin.anchore.models.finding import AnchoreFinding
from tap_plugin.anchore.models.policy_evaluation import AnchorePolicyEvaluation
from tap_plugin.anchore.models.scan_run import AnchoreScanRun
from tap_plugin.anchore.models.vex_annotation import AnchoreVexAnnotation


def previous_run(scanner_key: str) -> AnchoreScanRun | None:
    """The scanner's latest finished run, or None when it has none.

    A run with no finish time is a run that did not end; it says nothing about what the instance served.
    """
    return AnchoreScanRun.objects.filter(scanner_key=scanner_key, finished_at__isnull=False).order_by("-finished_at").first()


def current_findings(scanner_key: str, target_key: str) -> list[AnchoreFinding]:
    """The findings a read of one image last reported and no read has since withdrawn."""
    return list(AnchoreFinding.objects.filter(scanner_key=scanner_key, target_kind="image", target_key=target_key, state="current"))


def current_target_keys(scanner_key: str) -> set[str]:
    """The images that have findings no read has withdrawn."""
    return set(AnchoreFinding.objects.filter(scanner_key=scanner_key, target_kind="image", state="current").values_list("target_key", flat=True).distinct())


def image_host_exists(digest: str) -> bool:
    """Whether the grid already holds the image host for a digest (computing_core: realm oci-digest).

    The collector writes a host only where none exists, so it never rewrites a record another
    collector filled in.
    """
    return _hosts("oci-digest", digest).exists()


def known_vulnerabilities(ids: set[str]) -> set[str]:
    """Which of these identifiers the shared compliance_core vulnerability already holds, by exact match.

    No alias is resolved and no case is folded (req-anchore-findings-5).
    """
    if not ids:
        return set()
    return set(ComplianceVulnerability.objects.filter(vuln_id__in=ids).values_list("vuln_id", flat=True))


def natural_key_of(node: dict[str, Any]) -> dict[str, Any] | None:
    """A staged node's ``{"entity_type", "key"}`` by its type's natural key, or None when it cannot be stated.

    None for a type that is not registered, one with no natural key, and a node missing a key
    field: an edge to such a node cannot be moved to another batch (req-anchore-limits-7).
    """
    entity_type = node.get("entity", {}).get("entity_type")
    try:
        fields = get_model_class(entity_type).NATURAL_KEY
    except Exception:  # noqa: BLE001 - an unregistered type has no key to state
        return None
    if not isinstance(fields, tuple) or not fields:
        return None
    values = node.get("node", {})
    if any("." in name or values.get(name) is None for name in fields):
        return None
    return {"entity_type": entity_type, "key": {name: values[name] for name in fields}}


def current_vex_annotations(scanner_key: str, scope_kind: str, scope_id: str) -> list[AnchoreVexAnnotation]:
    """The VEX annotations the grid holds as current for one scope of one scanner."""
    return list(AnchoreVexAnnotation.objects.filter(scanner_key=scanner_key, scope_kind=scope_kind, scope_id=scope_id, state="current"))


def current_policy_evaluations(scanner_key: str, image_digest: str) -> list[AnchorePolicyEvaluation]:
    """The policy verdicts the grid holds as current for one image of one scanner."""
    return list(AnchorePolicyEvaluation.objects.filter(scanner_key=scanner_key, image_digest=image_digest, state="current"))


def host_holds_image_facts() -> bool:
    """Whether the installed computing_core's host has the image fact fields (v0.10.6 on)."""
    return all(any(f.name == name for f in Host._meta.get_fields()) for name in ("architecture", "image_size_bytes", "image_layer_count"))


def image_host_fields(digest: str) -> dict[str, Any] | None:
    """What the grid's image host for a digest holds of its name, operating system and image facts, or None when it holds no such host."""
    row = _hosts("oci-digest", digest).first()
    if row is None:
        return None
    # The image facts are fields of computing_core v0.10.6; an older one has none, and they read as held so nothing is sent.
    return {"name": row.name, "os": row.os, **{name: getattr(row, name, "not a field of this computing_core") for name in ("architecture", "image_size_bytes", "image_layer_count")}}


def sbom_document_state(content_digest: str) -> dict[str, Any] | None:
    """What the grid's document with these exact bytes says of itself, or None when it holds none.

    ``verified``, ``signer``, ``verification_note`` and ``authenticated_source``: enough to tell a
    record this plugin wrote from one another collector did, and a parsed one from a recorded one.
    """
    row = SbomDocument.objects.filter(content_digest=content_digest).first()
    if row is None:
        return None
    return {"verified": row.verified, "signer": row.signer, "verification_note": row.verification_note, "authenticated_source": getattr(row, "authenticated_source", "")}


def sbom_describes_host(content_digest: str, image_digest: str) -> bool:
    """Whether the grid's document with these bytes already has its edge to this image's host."""
    document = SbomDocument.objects.filter(content_digest=content_digest).first()
    host = _hosts("oci-digest", image_digest).first()
    if document is None or host is None:
        return False
    return Edge.objects.filter(edge_type="DESCRIBES_HOST__computing_core", from_entity_id=document.entity_id, to_entity_id=host.entity_id, entity__deleted_at__isnull=True).exists()


def packages_on_grid(by_purl: dict[str, tuple[str, str, str]]) -> dict[str, tuple[str, str, str]]:
    """Of these packages by purl, those the grid holds under that key with that same purl.

    The key is ``(ecosystem, name, version)``; two purls can share it and differ in namespace or
    qualifiers, so the stored purl is compared too and a package that differs is left out.
    """
    if not by_purl:
        return {}
    names = {name for _, name, _ in by_purl.values()}
    held = {(ecosystem, name, version): purl for ecosystem, name, version, purl in Package.objects.filter(name__in=names).values_list("ecosystem", "name", "version", "purl")}
    return {purl: key for purl, key in by_purl.items() if held.get(key) == purl}


def sbom_document_exists(content_digest: str) -> bool:
    """Whether the grid already holds a document with these exact bytes.

    Its key is the digest alone, so a record some other collector wrote (possibly verified and signed)
    is the same node; this plugin links to it and never rewrites it.
    """
    return SbomDocument.objects.filter(content_digest=content_digest).exists()


#: The aws_core type an Anchore ECS container record is joined to.
ECS_CONTAINER_TYPE = "aws_core__aws_ecs_container"


#: The aws_core ECS types a run links to or may create (req-anchore-shared). The field each one's
#: own ARN is in is read from the type (``ecs_key``), never written here.
ECS_TYPES = {
    "container": ECS_CONTAINER_TYPE,
    "task": "aws_core__aws_ecs_task",
    "service": "aws_core__aws_ecs_service",
    "cluster": "aws_core__aws_ecs_cluster",
}


def ecs_key(kind: str) -> str | None:
    """The field an aws_core ECS type keeps its own ARN in; None when aws_core is not installed."""
    try:
        return keys.sole_field(get_model_class(ECS_TYPES[kind]))
    except KeyError:
        return None


def spine_key(entity_type: str, values: Any) -> str | None:
    """The natural key of a node of a registered type as the grid stores it; None when it cannot be composed."""
    try:
        return keys.spine_key(get_model_class(entity_type), values)
    except (KeyError, keys.KeyShapeError):
        return None


def declared_dimensions(names: frozenset[str]) -> frozenset[str]:
    """Which of these dimension keys have a Dimension node on the grid. A key with none must not be stamped."""
    return frozenset(get_model_class("dimension").objects.filter(name__in=names).values_list("name", flat=True))


def scheme_field(entity_type: str) -> str:
    """The field beside ``stable_id`` in a computing_core type's key (a host's, a cluster's)."""
    return keys.scheme_field(get_model_class(entity_type))


def aws_nodes_on_grid(entity_type: str, key: str | None, arns: set[str]) -> set[str] | None:
    """Which of these ARNs name a live node of an aws_core type on the grid; None when the type is not installed.

    An existence check only: the plugin links to a node it finds and writes no field of it
    (req-anchore-shared-1).
    """
    try:
        model = get_model_class(entity_type)
    except KeyError:
        return None
    if key is None:
        return None
    if not arns:
        return set()
    return set(model.objects.filter(**{f"{key}__in": arns}).values_list(key, flat=True))


def ecs_containers_on_grid(arns: set[str]) -> set[str] | None:
    """Which of these ARNs name a live aws_core ECS container on the grid; None when aws_core is not installed."""
    return aws_nodes_on_grid(ECS_CONTAINER_TYPE, ecs_key("container"), arns)


#: aws_core's two dimensions a created ECS node carries beside its type defaults: the name each has
#: had, newest first. aws_core renamed them and kept the nodes (``aws_account`` to ``aws.account``).
_AWS_DIMENSION_NAMES = {"account": ("aws.account", "aws_account"), "region": ("aws.region", "aws_region")}


def aws_dimension_names(seed: dict[str, Any] | None | bool = False) -> dict[str, str]:
    """The names the INSTALLED aws_core gives its account and region dimensions (req-anchore-shared-8).

    Read from aws_core's own dimension seed, not from the grid's Dimension table: the package is
    the code a run executes against, while the table lags it between a migrate and the next boot.
    A name is the newest one the seed declares; where the seed declares neither, or aws_core
    ships no seed, the oldest name stands, which is what such an aws_core stamps itself. So one
    release of this plugin is right before and after the rename. ``seed`` is for tests.
    """
    if seed is False:
        seed = _aws_core_seed()
    declared = set() if seed is None else _declared_dimension_names(seed)
    return {role: next((name for name in names if name in declared), names[-1]) for role, names in _AWS_DIMENSION_NAMES.items()}


class AwsSeedUnreadable(RuntimeError):
    """aws_core ships a dimension seed that could not be read or is not the document expected."""


def _declared_dimension_names(seed: Any) -> set[str]:
    """The names of the dimension nodes a GRIFT seed declares; raises on any shape it does not recognise."""
    wrong = AwsSeedUnreadable("aws_core's dimension seed is not a GRIFT document of batches holding nodes")
    if not isinstance(seed, dict) or not isinstance(seed.get("batches"), list):
        raise wrong
    declared: set[str] = set()
    for batch in seed["batches"]:
        if not isinstance(batch, dict) or not isinstance(batch.get("nodes", []), list):
            raise wrong
        for node in batch.get("nodes", []):
            if not isinstance(node, dict) or not isinstance(node.get("entity"), dict):
                raise wrong
            if node["entity"].get("entity_type") == "dimension":
                body = node.get("node")
                if not isinstance(body, dict) or not isinstance(body.get("name"), str):
                    raise wrong
                declared.add(body["name"])
    return declared


def _aws_core_seed() -> Any:
    """aws_core's dimension seed as installed; None only when aws_core is not installed or ships none.

    A seed that is there and cannot be read or parsed is not the same as no seed: falling back to
    the old names then would mislabel every node created. That raises instead. The document's
    shape is checked where it is read (``_declared_dimension_names``).
    """
    import json
    from importlib import resources

    try:
        path = resources.files("tap_plugin.aws_core") / "grift" / "dimension.grift.json"
    except ModuleNotFoundError:
        return None
    try:
        if not path.is_file():
            return None
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AwsSeedUnreadable(f"aws_core's dimension seed could not be read ({type(exc).__name__})") from None


def default_dimensions(entity_type: str) -> dict[str, str]:
    """The registered model's default dimensions for a type this plugin does not import."""
    return dict(get_model_class(entity_type).DEFAULT_DIMENSIONS)


def _hosts(scheme: str, stable_id: str) -> Any:
    """The live hosts under one identifier scheme and identifier, by whatever the host's key fields are called."""
    return Host.objects.filter(**{keys.scheme_field(Host): scheme, keys.STABLE_ID: stable_id})


def host_exists(realm: str, stable_id: str) -> bool:
    """Whether the grid holds a live host under this realm and identifier."""
    return _hosts(realm, stable_id).exists()


def refused_annotation_keys() -> frozenset[str] | None:
    """The annotation keys computing_core refuses on write, or None when the installed one stores no annotation.

    The list is computing_core's (req-computing-core-kubernetes-10); a write carrying one of its
    keys is refused whole, so they are left out before the write rather than sent and lost.
    """
    try:
        from tap_plugin.computing_core.models.kubernetes_namespace import MANIFEST_ANNOTATION_KEYS
    except ImportError:
        return None
    return frozenset(MANIFEST_ANNOTATION_KEYS)


def types_installed(entity_types: list[str]) -> bool:
    """Whether every one of these types is registered: a computing_core older than its Kubernetes types has none."""
    try:
        for entity_type in entity_types:
            get_model_class(entity_type)
    except KeyError:
        return False
    return True
