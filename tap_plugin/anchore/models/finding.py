"""Anchore finding — one assertion that a package in an image or source is affected, as Anchore returned it."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

_STR_OR_NULL = {"type": ["string", "null"]}
_BOOL_OR_NULL = {"type": ["boolean", "null"]}
_LIST_OR_NULL = {"type": ["array", "null"]}
_STATES = ["current", "resolved"]
_TARGET_KINDS = ["image", "source"]


class AnchoreFinding(BaseModel):
    """What Anchore asserted about one vulnerability in one package of one target.

    Every Anchore field is stored as Anchore returned it: no severity scale, fix model or
    identifier choice is applied (req-anchore-findings-3). A field the response did not carry is
    null; an observed-empty list is [] (req-anchore-states-2). The key names the assertion and
    never the run, so two runs reporting the same assertion are one finding (-2), and it begins
    with the scanner so another instance or account never shares or resolves it (-6).

    Spec: specs/spec-anchore-v0.md (req-anchore-findings).
    """

    ENTITY_TYPE: ClassVar[str] = "anchore__anchore_finding"
    ENTITY_NAME: ClassVar[str] = "Anchore Finding"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "Anchore's assertion that a package in an image or repository source is affected by a "
        "vulnerability, holding Anchore's fields as returned and the run that last saw it."
    )
    ENTITY_ICON: ClassVar[str] = "anchore-finding"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"anchore.area": "finding"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = (
        "scanner_key",
        "vulnerability_id",
        "target_kind",
        "target_key",
        "package_key",
    )

    # FOUND_IN_SBOM__anchore (a source finding to its sbom_document) is specified but not defined:
    # computing_core declares sbom_document INBOUND_EDGES empty on purpose, so the grid refuses it
    # until computing_core allows it (spec-anchore-v0.md, req-anchore-findings).
    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "computing_core__host"}], "edges": [{"type": "FOUND_ON_IMAGE__anchore"}]},
        {"nodes": [{"type": "computing_core__package"}], "edges": [{"type": "FOUND_IN_PACKAGE__anchore"}]},
    ]

    # A finding is reached by traversal and nothing in v0 points at it (req-anchore-findings-4).
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "scanner_key": {"type": "string", "minLength": 1},
        "vulnerability_id": {"type": "string", "minLength": 1},
        "target_kind": {"type": "string", "enum": _TARGET_KINDS},
        "target_key": {"type": "string", "minLength": 1},
        "package_key": {"type": "string", "minLength": 1, "maxLength": 1400},
        "state": {"type": ["string", "null"], "enum": [*_STATES, None]},
        "last_seen_run_id": _STR_OR_NULL,
        "severity": _STR_OR_NULL,
        "fix": _STR_OR_NULL,
        "suggested_fix_version": _STR_OR_NULL,
        "fix_observed_at": _STR_OR_NULL,
        "will_not_fix": _BOOL_OR_NULL,
        "is_kev": _BOOL_OR_NULL,
        "epss": _LIST_OR_NULL,
        "nvd_data": _LIST_OR_NULL,
        "vendor_data": _LIST_OR_NULL,
        "annotation_status": _STR_OR_NULL,
        "annotation_uuid": _STR_OR_NULL,
        "description": _STR_OR_NULL,
        "url": _STR_OR_NULL,
        "feed": _STR_OR_NULL,
        "feed_group": _STR_OR_NULL,
        "detected_at": _STR_OR_NULL,
        "inherited_from_base": _BOOL_OR_NULL,
        "package": {"type": ["string", "null"], "maxLength": 255},
        "package_name": _STR_OR_NULL,
        "package_version": _STR_OR_NULL,
        "package_type": _STR_OR_NULL,
        "package_path": {"type": ["string", "null"], "maxLength": 1024},
        "purl": _STR_OR_NULL,
        "package_cpe": _STR_OR_NULL,
        "package_cpe23": _STR_OR_NULL,
        "matched_on_cpes": _LIST_OR_NULL,
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        name: {"validation": "jsonschema", "schema": schema} for name, schema in FIELD_CRUD_SCHEMA.items()
    }
    CREATE_REQUIRED: ClassVar[list[str]] = [
        "scanner_key",
        "vulnerability_id",
        "target_kind",
        "target_key",
        "package_key",
    ]

    # Identity (the columns the natural key rests on; none is computed in a collector's id recipe).
    # package_key is a JSON array of package (255) and package_path (1024): at most 1288 characters,
    # inside its own 1400, so a value past either width is refused and never truncated into a collision.
    scanner_key = models.CharField(max_length=1024, db_index=True, help_text="The scanner (instance and account) that asserted it.")
    vulnerability_id = models.CharField(max_length=255, db_index=True, help_text="The identifier Anchore reports in its vuln field, exactly as returned; no alias is resolved.")
    target_kind = models.CharField(max_length=16, help_text="What was scanned: image or source.")
    target_key = models.CharField(max_length=512, help_text="The target within the scanner: the image digest, or the source's Anchore id.")
    package_key = models.CharField(
        max_length=1400,
        help_text="The package within the target: a compact JSON array of Anchore's package and package_path as returned (null for an absent part).",
    )

    # State, kept apart from what Anchore said.
    state = models.CharField(max_length=16, null=True, blank=True, default=None, db_index=True, help_text="current while a read reports it, resolved once a successful read of its target no longer does; null when never observed.")
    last_seen_run_id = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="The run_id of the scan run that last saw this assertion.")

    # Anchore's fields, as returned.
    severity = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="Anchore's severity string exactly as returned: no enum, case change or mapping.")
    fix = models.CharField(max_length=512, null=True, blank=True, default=None, help_text="Anchore's fix field as returned; null when the response did not carry it, which is not 'no fix'.")
    suggested_fix_version = models.CharField(max_length=512, null=True, blank=True, default=None, help_text="Anchore's suggested_fix_version as returned; null when not carried.")
    fix_observed_at = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="Anchore's fix_observed_at timestamp as the string returned; null when not carried.")
    will_not_fix = models.BooleanField(null=True, blank=True, default=None, help_text="Anchore's will_not_fix; null when not carried, never false by default.")
    is_kev = models.BooleanField(null=True, blank=True, default=None, help_text="Anchore's is_kev flag; null when not carried.")
    epss = models.JSONField(null=True, blank=True, default=None, help_text="Anchore's epss list (epss and percentile entries) as returned; [] when observed empty, null when not carried. Source: the image vulnerabilities response.")
    nvd_data = models.JSONField(null=True, blank=True, default=None, help_text="Anchore's nvd_data list as returned, every entry kept; null when not carried. Source: the image vulnerabilities response.")
    vendor_data = models.JSONField(null=True, blank=True, default=None, help_text="Anchore's vendor_data list as returned, every entry kept; null when not carried. Source: the image vulnerabilities response.")
    annotation_status = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="Anchore's annotation_status as returned.")
    annotation_uuid = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="Anchore's annotation_uuid as returned.")
    description = models.TextField(null=True, blank=True, default=None, help_text="Anchore's description of the vulnerability as returned.")
    url = models.CharField(max_length=1024, null=True, blank=True, default=None, help_text="Anchore's url for the vulnerability as returned.")
    feed = models.CharField(max_length=128, null=True, blank=True, default=None, help_text="The Anchore feed the match came from, as returned.")
    feed_group = models.CharField(max_length=128, null=True, blank=True, default=None, help_text="The Anchore feed group, as returned.")
    detected_at = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="When Anchore says it detected the match, as the string returned.")
    inherited_from_base = models.BooleanField(null=True, blank=True, default=None, help_text="Anchore's inherited_from_base flag; null when not carried.")
    package = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="Anchore's package field as returned.")
    package_name = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="Anchore's package_name as returned.")
    package_version = models.CharField(max_length=255, null=True, blank=True, default=None, help_text="Anchore's package_version as returned.")
    package_type = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="Anchore's package_type as returned.")
    package_path = models.CharField(max_length=1024, null=True, blank=True, default=None, help_text="Anchore's package_path as returned.")
    purl = models.CharField(max_length=1024, null=True, blank=True, default=None, help_text="Anchore's purl for the package as returned.")
    package_cpe = models.CharField(max_length=512, null=True, blank=True, default=None, help_text="Anchore's package_cpe as returned.")
    package_cpe23 = models.CharField(max_length=512, null=True, blank=True, default=None, help_text="Anchore's package_cpe23 as returned.")
    matched_on_cpes = models.JSONField(null=True, blank=True, default=None, help_text="Anchore's matched_on_cpes list as returned; null when not carried. Source: the image vulnerabilities response.")

    class Meta(BaseModel.Meta):
        db_table = "anchore_finding"

    def get_name(self) -> str:
        if not self.vulnerability_id:
            return ""
        # Entity.name is 255 characters; the display name is a projection, so it is cut to fit and
        # the full values stay in their own columns.
        return f"{self.vulnerability_id} · {self.package_name or self.package or self.target_key}"[:255]

    def __str__(self) -> str:
        return self.get_name()
