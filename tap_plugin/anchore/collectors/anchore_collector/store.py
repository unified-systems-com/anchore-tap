"""What the grid already holds for one scanner: the two reads a run needs before it writes.

Both reads are of this plugin's own nodes, through the models' default manager, which excludes
tombstoned rows and is guarded to a bound actor (the collector task binds one).
"""

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
