"""Anchore scanner — one Anchore instance and account."""

import json
from typing import Any, ClassVar

from django.core.exceptions import ValidationError
from django.db import models

from tap_grid.models import BaseModel


class AnchoreScanner(BaseModel):
    """One Anchore instance read through one account.

    Its identity is the canonical API root and the account together, so two accounts on one
    instance, or two instances on one host, are two scanners and never share a finding. The
    reported version is a fact about the scanner at the time it was last read, not part of its key.

    Spec: specs/spec-anchore-v0.md (req-anchore-findings, req-anchore-scope-walk-4, -5).
    """

    ENTITY_TYPE: ClassVar[str] = "anchore__anchore_scanner"
    ENTITY_NAME: ClassVar[str] = "Anchore Scanner"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "One Anchore Enterprise instance read through one account: the source every Anchore finding, "
        "scan run and annotation is attributed to."
    )
    ENTITY_ICON: ClassVar[str] = "anchore-scanner"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"anchore.area": "run"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("scanner_key",)

    # A scanner is only ever the far end: nothing in v0 starts at it.
    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "anchore__anchore_scan_run"}], "edges": [{"type": "RUN_OF_SCANNER__anchore"}]},
    ]

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "scanner_key": {"type": "string", "minLength": 1},
        "api_root": {"type": "string", "minLength": 1},
        "account": {"type": "string", "minLength": 1},
        "reported_version": {"type": ["string", "null"]},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        "scanner_key": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "api_root": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "account": {"validation": "jsonschema", "schema": {"type": "string", "minLength": 1}},
        "reported_version": {"validation": "jsonschema", "schema": {"type": ["string", "null"]}},
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["scanner_key", "api_root", "account"]

    scanner_key = models.CharField(
        max_length=1024,
        db_index=True,
        help_text="Identity: a compact JSON array of the canonical API root and the account (credential.scanner_key).",
    )
    api_root = models.CharField(
        max_length=512, help_text="The canonical API root as credential.canonical_root writes it: https, lower-cased host, port unless 443, and the path exactly as configured."
    )
    account = models.CharField(max_length=255, help_text="The Anchore account this scanner reads through.")
    reported_version = models.CharField(
        max_length=64,
        null=True,
        blank=True,
        default=None,
        help_text="The version the instance reported when last probed; null when never observed. Not part of identity.",
    )

    class Meta(BaseModel.Meta):
        db_table = "anchore_scanner"

    def validate(self) -> None:
        """The key must say what the columns say.

        scanner_key is the credential's compact JSON array of the canonical API root and the account
        (credential.scanner_key), so a record whose key names one instance and account while its
        columns name another is refused rather than stored under a misleading display name.
        """
        try:
            named = json.loads(self.scanner_key)
        except (TypeError, ValueError):
            named = None
        if named != [self.api_root, self.account]:
            raise ValidationError({"scanner_key": ["scanner_key must be the JSON array [api_root, account]"]})

    def get_name(self) -> str:
        return f"{self.api_root} · {self.account}"[:255] if self.api_root else ""

    def __str__(self) -> str:
        return self.get_name()
