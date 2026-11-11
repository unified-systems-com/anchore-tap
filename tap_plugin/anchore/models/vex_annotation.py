"""Anchore VEX annotation — a statement on whether one vulnerability matters for one package of a scope."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

_STR_OR_NULL = {"type": ["string", "null"]}


class AnchoreVexAnnotation(BaseModel):
    """A VEX statement Anchore holds: "this vulnerability, in this package, is not affected, because …".

    Anchore keeps these at two scopes, an image and an application version, with the same fields.
    The statement is the scanner's record as returned. It is not applied to any finding here and
    is never turned into a remediation decision by this plugin: it is evidence, linked to what it
    is about.

    Identity is ``(scanner_key, scope_kind, scope_id, annotation_id)``: the scope is in the key
    because an identifier is Anchore's own and only known to be unique where it was read. An
    annotation a later whole read of its scope no longer returns is kept and marked
    ``withdrawn``, so a retracted "not affected" cannot be read as standing. A read that failed
    withdraws nothing.

    The free-text fields are what an Anchore user typed. They are stored as returned and are not
    scanned or redacted; who may read them is the grid's read authorization.

    Spec: specs/spec-anchore-v0.md (req-anchore-vex).
    """

    ENTITY_TYPE: ClassVar[str] = "anchore__anchore_vex_annotation"
    ENTITY_NAME: ClassVar[str] = "Anchore VEX Annotation"
    ENTITY_DESCRIPTION: ClassVar[str] = "A VEX statement Anchore holds on one vulnerability in one package of an image or an application version: its status, its justification and the author's notes."
    ENTITY_ICON: ClassVar[str] = "anchore-vex-annotation"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"anchore.area": "annotation"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("scanner_key", "scope_kind", "scope_id", "annotation_id")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "computing_core__host"}], "edges": [{"type": "ANNOTATES_IMAGE__anchore"}]},
        {"nodes": [{"type": "anchore__anchore_finding"}], "edges": [{"type": "ANNOTATES_FINDING__anchore"}]},
        {"nodes": [{"type": "computing_core__package"}], "edges": [{"type": "ABOUT_PACKAGE__anchore"}]},
        {"nodes": [{"type": "compliance_core__compliance_vulnerability"}], "edges": [{"type": "ABOUT_VULNERABILITY__anchore"}]},
    ]

    # Nothing points at a statement; what it concerns is reached from it.
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "scanner_key": {"type": "string", "minLength": 1},
        "scope_kind": {"type": "string", "enum": ["image", "app_version"]},
        "scope_id": {"type": "string", "minLength": 1},
        "annotation_id": {"type": "string", "minLength": 1},
        "state": {"type": "string", "enum": ["current", "withdrawn"]},
        "vulnerability_id": {"type": "string", "minLength": 1},
        "package_name": _STR_OR_NULL,
        "package_version": _STR_OR_NULL,
        "package_type": _STR_OR_NULL,
        "status": _STR_OR_NULL,
        "justification": _STR_OR_NULL,
        "status_notes": _STR_OR_NULL,
        "impact_statement": _STR_OR_NULL,
        "action_statement": _STR_OR_NULL,
        "additional_details": _STR_OR_NULL,
        "source_type": _STR_OR_NULL,
        "source_name": _STR_OR_NULL,
        "annotation_version": {"type": ["integer", "null"], "minimum": 0},
        "annotation_created_at": _STR_OR_NULL,
        "annotation_updated_at": _STR_OR_NULL,
        "last_seen_run_id": _STR_OR_NULL,
        "record": {"type": ["object", "null"]},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        name: {"validation": "jsonschema", "schema": schema}
        for name, schema in FIELD_CRUD_SCHEMA.items()
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["scanner_key", "scope_kind", "scope_id", "annotation_id", "vulnerability_id"]

    scanner_key = models.CharField(max_length=1024, db_index=True, help_text="The scanner that holds the statement (credential.scanner_key).")
    scope_kind = models.CharField(max_length=16, help_text="What the statement is scoped to: image or app_version. Part of the identity.")
    scope_id = models.CharField(max_length=512, help_text="The scope's identifier: an image digest, or an application version id. Part of the identity.")
    annotation_id = models.CharField(max_length=64, help_text="Anchore's uuid for the annotation, as returned. Part of the identity.")
    state = models.CharField(
        max_length=16,
        default="current",
        help_text="current: Anchore returned it on the last whole read of its scope. withdrawn: a later whole read no longer returned it. A withdrawn statement is kept and is not one to rely on.",
    )
    vulnerability_id = models.CharField(max_length=255, db_index=True, help_text="The vulnerability the statement is about, as returned.")
    package_name = models.CharField(max_length=512, null=True, blank=True, default=None, help_text="The package the statement is scoped to. Null when Anchore returned no package scope; that is not widened to every package.")
    package_version = models.CharField(max_length=512, null=True, blank=True, default=None, help_text="The package version the statement is scoped to. Null with no package scope.")
    package_type = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="Anchore's package type for the scope, as returned. Null with no package scope.")
    status = models.CharField(max_length=32, null=True, blank=True, default=None, db_index=True, help_text="The VEX status as returned: not_affected, affected, fixed or under_investigation.")
    justification = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="Anchore's justification for a not_affected status, as returned. Null when none was given.")
    status_notes = models.TextField(null=True, blank=True, default=None, help_text="The author's notes on the status. Free text an Anchore user typed, stored as returned.")
    impact_statement = models.TextField(null=True, blank=True, default=None, help_text="The author's statement of impact. Free text an Anchore user typed, stored as returned.")
    action_statement = models.TextField(null=True, blank=True, default=None, help_text="The author's statement of the action taken. Free text an Anchore user typed, stored as returned.")
    additional_details = models.TextField(null=True, blank=True, default=None, help_text="The author's further detail. Free text an Anchore user typed, stored as returned.")
    source_type = models.CharField(max_length=32, null=True, blank=True, default=None, help_text="Where the statement came from, as returned: external (a vendor's) or user (made in Anchore).")
    source_name = models.CharField(max_length=512, null=True, blank=True, default=None, help_text="The source's name as returned: an organization for a user statement, a vendor for an external one.")
    annotation_version = models.PositiveIntegerField(null=True, blank=True, default=None, help_text="Anchore's version number of the annotation. Null when not returned.")
    annotation_created_at = models.DateTimeField(null=True, blank=True, default=None, help_text="When Anchore says the annotation was created; null when not returned or unreadable.")
    annotation_updated_at = models.DateTimeField(null=True, blank=True, default=None, help_text="When Anchore says the annotation was last updated; null when not returned or unreadable.")
    last_seen_run_id = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="The run that last read this annotation.")
    record = models.JSONField(null=True, blank=True, default=None, help_text="The annotation exactly as Anchore returned it, its package scope included. Source: GET /images/{image_digest}/vuln-annotations.")

    class Meta(BaseModel.Meta):
        db_table = "anchore_vex_annotation"

    def get_name(self) -> str:
        said = self.status or "unstated"
        if self.state == "withdrawn":
            said = f"withdrawn {said}"
        return f"{said} · {self.vulnerability_id}"

    def __str__(self) -> str:
        return self.get_name()
