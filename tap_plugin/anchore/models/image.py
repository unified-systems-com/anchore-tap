"""Anchore image — Anchore's own record of one image it holds."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

_STR_OR_NULL = {"type": ["string", "null"]}


class AnchoreImage(BaseModel):
    """Anchore's record of one image: whether it analyzed it, when, and the record as it returned it.

    The image itself is the ``computing_core`` host keyed by its digest, and facts true of the
    image whoever looks (its name, operating system, architecture) belong there. This node holds
    what is Anchore's: the state of its analysis and the whole image record exactly as its API
    returned it, so nothing Anchore said about the image is dropped (req-anchore-image-1).

    Identity is ``(scanner_key, image_digest)``: one record per Anchore instance and account.

    Spec: specs/spec-anchore-v0.md (req-anchore-image).
    """

    ENTITY_TYPE: ClassVar[str] = "anchore__anchore_image"
    ENTITY_NAME: ClassVar[str] = "Anchore Image"
    ENTITY_DESCRIPTION: ClassVar[str] = "Anchore's record of one image it holds: the state of its analysis and the image record as Anchore returned it."
    ENTITY_ICON: ClassVar[str] = "anchore-image"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"anchore.area": "image"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("scanner_key", "image_digest")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "computing_core__host"}], "edges": [{"type": "RECORDS_IMAGE__anchore"}]},
    ]

    # Nothing points at Anchore's record of an image; what concerns the image points at its host.
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "scanner_key": {"type": "string", "minLength": 1},
        "image_digest": {"type": "string", "minLength": 1},
        "reference": _STR_OR_NULL,
        "analysis_status": _STR_OR_NULL,
        "image_status": _STR_OR_NULL,
        "parent_digest": _STR_OR_NULL,
        "created_at": _STR_OR_NULL,
        "last_updated": _STR_OR_NULL,
        "record": {"type": ["object", "null"]},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        name: {"validation": "jsonschema", "schema": schema}
        for name, schema in FIELD_CRUD_SCHEMA.items()
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["scanner_key", "image_digest"]

    scanner_key = models.CharField(max_length=1024, db_index=True, help_text="The scanner that holds it (credential.scanner_key).")
    image_digest = models.CharField(max_length=512, help_text="The image digest as Anchore lists it. Identity.")
    reference = models.CharField(
        max_length=2048, null=True, blank=True, default=None, help_text="The first of the image's full tag references in sorted order, for display; null when Anchore lists none. Every tag is in record."
    )
    analysis_status = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="Anchore's analysis_status as returned (analyzed, analyzing, not_analyzed, analysis_failed).")
    image_status = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="Anchore's image_status as returned (active, inactive, disabled).")
    parent_digest = models.CharField(
        max_length=512, null=True, blank=True, default=None, help_text="Anchore's parent_digest as returned: the digest of the manifest list that described this image, where there was one."
    )
    created_at = models.DateTimeField(null=True, blank=True, default=None, help_text="When Anchore created its record of the image; null when not returned or unreadable.")
    last_updated = models.DateTimeField(null=True, blank=True, default=None, help_text="When Anchore last updated its record; null when not returned or unreadable.")
    record = models.JSONField(
        null=True,
        blank=True,
        default=None,
        help_text="The image's entry in Anchore's image list exactly as returned, every key kept. Source: GET /images. Null on a row written before this was recorded.",
    )

    class Meta(BaseModel.Meta):
        db_table = "anchore_image"

    def get_name(self) -> str:
        return self.reference or self.image_digest or ""

    def __str__(self) -> str:
        return self.get_name()
