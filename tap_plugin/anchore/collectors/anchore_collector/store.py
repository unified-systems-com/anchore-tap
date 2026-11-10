"""What the grid already holds: the reads a run needs before it writes.

The scanner reads are of this plugin's own nodes; the host and vulnerability reads are existence
checks on two shared types (computing_core's image host, compliance_core's vulnerability), which
this plugin links to and never rewrites. All go through the models' default manager, which excludes
tombstoned rows and is guarded to a bound actor (the collector task binds one).

The ECS container read is of a type this plugin does not import: aws_core is an optional
dependency (req-anchore-shared-4), so its model is taken from the registry by name, and its
absence is an answer, not an error.
"""

from tap_plugin.compliance_core.models.compliance_vulnerability import ComplianceVulnerability
from tap_plugin.computing_core.models.host import Host
from tap_plugin.computing_core.models.sbom_document import SbomDocument

from tap_grid.registry import get_model_class
from tap_plugin.anchore.models.finding import AnchoreFinding
from tap_plugin.anchore.models.scan_run import AnchoreScanRun


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
    return Host.objects.filter(realm="oci-digest", stable_id=digest).exists()


def known_vulnerabilities(ids: set[str]) -> set[str]:
    """Which of these identifiers the shared compliance_core vulnerability already holds, by exact match.

    No alias is resolved and no case is folded (req-anchore-findings-5).
    """
    if not ids:
        return set()
    return set(ComplianceVulnerability.objects.filter(vuln_id__in=ids).values_list("vuln_id", flat=True))


def sbom_document_exists(content_digest: str) -> bool:
    """Whether the grid already holds a document with these exact bytes.

    Its key is the digest alone, so a record some other collector wrote (possibly verified and signed)
    is the same node; this plugin links to it and never rewrites it.
    """
    return SbomDocument.objects.filter(content_digest=content_digest).exists()


#: The aws_core type an Anchore ECS container record is joined to, and the field its ARN is in.
ECS_CONTAINER_TYPE = "aws_core__aws_ecs_container"
ECS_CONTAINER_KEY = "container_arn"


#: The other aws_core ECS types a run may create (req-anchore-shared), each with its ARN field.
ECS_TYPES = {
    "container": (ECS_CONTAINER_TYPE, ECS_CONTAINER_KEY),
    "task": ("aws_core__aws_ecs_task", "task_arn"),
    "service": ("aws_core__aws_ecs_service", "service_arn"),
    "cluster": ("aws_core__aws_ecs_cluster", "cluster_arn"),
}


def aws_nodes_on_grid(entity_type: str, key: str, arns: set[str]) -> set[str] | None:
    """Which of these ARNs name a live node of an aws_core type on the grid; None when the type is not installed.

    An existence check only: the plugin links to a node it finds and writes no field of it
    (req-anchore-shared-1).
    """
    try:
        model = get_model_class(entity_type)
    except KeyError:
        return None
    if not arns:
        return set()
    return set(model.objects.filter(**{f"{key}__in": arns}).values_list(key, flat=True))


def ecs_containers_on_grid(arns: set[str]) -> set[str] | None:
    """Which of these ARNs name a live aws_core ECS container on the grid; None when aws_core is not installed."""
    return aws_nodes_on_grid(ECS_CONTAINER_TYPE, ECS_CONTAINER_KEY, arns)


def default_dimensions(entity_type: str) -> dict[str, str]:
    """The registered model's default dimensions for a type this plugin does not import."""
    return dict(get_model_class(entity_type).DEFAULT_DIMENSIONS)


def host_exists(realm: str, stable_id: str) -> bool:
    """Whether the grid holds a live host under this realm and identifier."""
    return Host.objects.filter(realm=realm, stable_id=stable_id).exists()


def types_installed(entity_types: list[str]) -> bool:
    """Whether every one of these types is registered: a computing_core older than its Kubernetes types has none."""
    try:
        for entity_type in entity_types:
            get_model_class(entity_type)
    except KeyError:
        return False
    return True
