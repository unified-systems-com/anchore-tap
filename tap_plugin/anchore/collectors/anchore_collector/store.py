"""What the grid already holds: the reads a run needs before it writes.

The scanner reads are of this plugin's own nodes; the host and vulnerability reads are existence
checks on two shared types (computing_core's image host, compliance_core's vulnerability), which
this plugin links to and never rewrites. All go through the models' default manager, which excludes
tombstoned rows and is guarded to a bound actor (the collector task binds one).
"""

from tap_plugin.compliance_core.models.compliance_vulnerability import ComplianceVulnerability
from tap_plugin.computing_core.models.host import Host

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
