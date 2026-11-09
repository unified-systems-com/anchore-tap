"""Anchore scan run — one collection of one scanner."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

#: What a list of scopes holds: each scope a run read, or did not read with the reason.
_SCOPES_READ = {"type": ["array", "null"], "items": {"type": "string"}}
_SCOPES_NOT_READ = {
    "type": ["array", "null"],
    "items": {
        "type": "object",
        "required": ["scope", "reason"],
        "additionalProperties": False,
        "properties": {"scope": {"type": "string"}, "reason": {"type": "string"}},
    },
}
_OBJECT_OR_NULL = {"type": ["object", "null"]}
_VERDICTS = ["pass", "warn", "error"]


class AnchoreScanRun(BaseModel):
    """One collection against one scanner: what was read, from what, and what was not.

    A finding is judged against the run that last saw it, so the run records the probe results
    (version, status, feed freshness), the self-test verdict, and every scope read or not read.
    A scope not read is never clean (req-anchore-states).

    Spec: specs/spec-anchore-v0.md (req-anchore-findings, req-anchore-probe, req-anchore-states).
    """

    ENTITY_TYPE: ClassVar[str] = "anchore__anchore_scan_run"
    ENTITY_NAME: ClassVar[str] = "Anchore Scan Run"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "One collection of one Anchore scanner: the probe results, the self-test verdict and the "
        "scopes read and not read."
    )
    ENTITY_ICON: ClassVar[str] = "anchore-scan-run"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"anchore.area": "run"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("scanner_key", "run_id")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "anchore__anchore_scanner"}], "edges": [{"type": "RUN_OF_SCANNER__anchore"}]},
    ]

    # Nothing in v0 points at a run.
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "scanner_key": {"type": "string", "minLength": 1},
        "run_id": {"type": "string", "minLength": 1},
        "started_at": {"type": ["string", "null"]},
        "finished_at": {"type": ["string", "null"]},
        "reported_version": {"type": ["string", "null"]},
        "status": _OBJECT_OR_NULL,
        "feeds": {"type": ["array", "null"]},
        "selftest_verdict": {"type": ["string", "null"], "enum": [*_VERDICTS, None]},
        "selftest_detail": _OBJECT_OR_NULL,
        "scopes_read": _SCOPES_READ,
        "scopes_not_read": _SCOPES_NOT_READ,
        "settings": _OBJECT_OR_NULL,
        "images_listed": {"type": ["integer", "null"], "minimum": 0},
        "images_selected": {"type": ["integer", "null"], "minimum": 0},
        "images_out_of_scope": {"type": ["integer", "null"], "minimum": 0},
        "images_not_in_anchore": {"type": ["integer", "null"], "minimum": 0},
        "inventory_stale": {"type": ["integer", "null"], "minimum": 0},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        name: {"validation": "jsonschema", "schema": schema}
        for name, schema in FIELD_CRUD_SCHEMA.items()
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["scanner_key", "run_id"]

    scanner_key = models.CharField(max_length=1024, db_index=True, help_text="The scanner this run read (credential.scanner_key).")
    run_id = models.CharField(max_length=64, help_text="Identity within the scanner: an id the collector mints once per run.")
    started_at = models.DateTimeField(null=True, blank=True, default=None, help_text="When the collector began the run; null when unobserved.")
    finished_at = models.DateTimeField(null=True, blank=True, default=None, help_text="When the run ended; null while unfinished or unobserved.")
    reported_version = models.CharField(
        max_length=64, null=True, blank=True, default=None, help_text="The version the instance reported in this run's probe; null when the probe was not read."
    )
    status = models.JSONField(
        null=True, blank=True, default=None, help_text="The body of the instance's status read as returned (the /status response); null when not read."
    )
    feeds = models.JSONField(
        null=True, blank=True, default=None, help_text="The instance's feed list as returned (the /system/feeds response), recording feed freshness; null when not read."
    )
    selftest_verdict = models.CharField(
        max_length=8, null=True, blank=True, default=None, help_text="The per-run schema self-test outcome: pass, warn or error; null when it did not run."
    )
    selftest_detail = models.JSONField(
        null=True, blank=True, default=None, help_text="What the self-test compared and found, so a verdict can be audited; null when it did not run."
    )
    scopes_read = models.JSONField(
        null=True, blank=True, default=None, help_text="Scopes this run read successfully (for example an image digest); [] when it read none, null when unobserved."
    )
    scopes_not_read = models.JSONField(
        null=True, blank=True, default=None, help_text="Scopes this run could not read, each with the reason; [] when none were missed, null when unobserved."
    )
    settings = models.JSONField(
        null=True, blank=True, default=None, help_text="The scope and create settings this run used, as configured (req-anchore-scope-14); never a credential. Null when unobserved."
    )
    images_listed = models.IntegerField(null=True, blank=True, default=None, help_text="Images in Anchore's list for the account in this run; null when the run did not get that far.")
    images_selected = models.IntegerField(null=True, blank=True, default=None, help_text="Digests the scope selected for reading in this run; null when the run did not get that far.")
    images_out_of_scope = models.IntegerField(null=True, blank=True, default=None, help_text="Listed images the scope left out in this run; their findings were not touched; null when the run did not get that far.")
    images_not_in_anchore = models.IntegerField(null=True, blank=True, default=None, help_text="Selected running digests Anchore's image list does not hold; null when the run did not get that far.")
    inventory_stale = models.IntegerField(null=True, blank=True, default=None, help_text="Inventory records older than the freshness window, or with no last_seen; null when the run did not get that far.")

    class Meta(BaseModel.Meta):
        db_table = "anchore_scan_run"

    def get_name(self) -> str:
        return f"run {self.run_id}" if self.run_id else ""

    def __str__(self) -> str:
        return self.get_name()
