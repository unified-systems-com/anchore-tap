"""Anchore runtime image — an image Anchore's inventory reported in use in one context."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel


class AnchoreRuntimeImage(BaseModel):
    """One image in use in one inventory context, as Anchore's runtime inventory reported it.

    This is the scanner's own observation: its agent saw this digest running in this context
    and last saw it at ``last_seen``. It is written for every inventory item a run selects,
    whatever else the run creates (req-anchore-scope-12), so what Anchore saw is on the grid on
    a node this plugin owns and conflicts with no other collector's.

    Identity is ``(scanner_key, inventory_type, context, image_digest)``. The key is the digest,
    not the tag: the Kubernetes agent can fill a missing tag with the digest, so a tag can be
    synthetic. A record that disappears from Anchore is not proof that a workload stopped (it may
    be expiry or an agent outage), so this node is never closed or deleted on absence;
    ``last_seen`` is the only age signal (req-anchore-inventory-3).

    Spec: specs/spec-anchore-v0.md (req-anchore-inventory, req-anchore-scope).
    """

    ENTITY_TYPE: ClassVar[str] = "anchore__anchore_runtime_image"
    ENTITY_NAME: ClassVar[str] = "Anchore Runtime Image"
    ENTITY_DESCRIPTION: ClassVar[str] = (
        "An image Anchore's runtime inventory reported in use in one context (a Kubernetes cluster "
        "and namespace, or an ECS cluster), with when Anchore last saw it."
    )
    ENTITY_ICON: ClassVar[str] = "anchore-runtime-image"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"anchore.area": "runtime"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("scanner_key", "inventory_type", "context", "image_digest")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "computing_core__host"}], "edges": [{"type": "OBSERVES_IMAGE__anchore"}]},
    ]

    # Nothing points at an observation.
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "scanner_key": {"type": "string", "minLength": 1},
        "inventory_type": {"type": "string", "minLength": 1},
        "context": {"type": "string", "minLength": 1},
        "image_digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
        "image_tag": {"type": ["string", "null"]},
        "created_at": {"type": ["string", "null"]},
        "last_updated": {"type": ["string", "null"]},
        "last_seen": {"type": ["string", "null"]},
        "analyzed_digests": {"type": ["array", "null"], "items": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"}, "uniqueItems": True},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        name: {"validation": "jsonschema", "schema": schema}
        for name, schema in FIELD_CRUD_SCHEMA.items()
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["scanner_key", "inventory_type", "context", "image_digest"]

    scanner_key = models.CharField(max_length=1024, db_index=True, help_text="The scanner that reported it (credential.scanner_key).")
    inventory_type = models.CharField(max_length=32, help_text="Anchore's inventory type as returned: kubernetes or ecs.")
    context = models.CharField(
        max_length=1024, help_text="Anchore's inventory context as returned: for Kubernetes the cluster name, a slash and the namespace."
    )
    image_digest = models.CharField(max_length=71, help_text="The image digest as returned: sha256: and 64 hex characters. Identity.")
    image_tag = models.CharField(
        max_length=2048, null=True, blank=True, default=None, help_text="The image tag as returned; may be synthetic (the digest). Null when not returned."
    )
    created_at = models.DateTimeField(null=True, blank=True, default=None, help_text="Anchore's created_at for the record; null when not returned or unreadable.")
    last_updated = models.DateTimeField(null=True, blank=True, default=None, help_text="Anchore's last_updated for the record; null when not returned or unreadable.")
    last_seen = models.DateTimeField(
        null=True, blank=True, default=None, help_text="When Anchore's agent last reported this image in this context; null when not returned or unreadable."
    )

    analyzed_digests = models.JSONField(
        null=True,
        blank=True,
        default=None,
        help_text=(
            "The digests of the images Anchore analyzed that this run read on behalf of image_digest. The digest itself when Anchore lists it as an image; "
            "otherwise each image whose parent_digest it is (a runtime reports a multi-platform image by its index digest, and Anchore analyzes one "
            "platform's image under its own). Empty when Anchore holds none in scope; null on a row written before this was recorded. "
            "Source: the image list's image_digest and parent_digest."
        ),
    )

    class Meta(BaseModel.Meta):
        db_table = "anchore_runtime_image"

    def get_name(self) -> str:
        what = self.image_tag or self.image_digest
        return f"{what} in {self.context}" if what and self.context else what or ""

    def __str__(self) -> str:
        return self.get_name()
