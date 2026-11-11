"""Anchore policy evaluation — Anchore's verdict on one image under one tag and one policy."""

from typing import Any, ClassVar

from django.db import models

from tap_grid.models import BaseModel

_STR_OR_NULL = {"type": ["string", "null"]}
_BOOL_OR_NULL = {"type": ["boolean", "null"]}


class AnchorePolicyEvaluation(BaseModel):
    """Anchore's evaluation of an image against a policy: pass or fail, the action, and why.

    Anchore evaluates an image under a tag, because a policy's mapping rules choose what applies
    by registry, repository and tag. So one image has one evaluation per tag it carries and per
    policy. This node is the scanner's verdict as it returned it; it is not interpreted here.

    Identity is ``(scanner_key, image_digest, evaluated_tag, policy_id)``. A later evaluation of
    the same four replaces the fields. An evaluation for a tag the image no longer carries is not
    removed: absence from a later read is not proof Anchore withdrew it.

    Spec: specs/spec-anchore-v0.md (req-anchore-image-policy).
    """

    ENTITY_TYPE: ClassVar[str] = "anchore__anchore_policy_evaluation"
    ENTITY_NAME: ClassVar[str] = "Anchore Policy Evaluation"
    ENTITY_DESCRIPTION: ClassVar[str] = "Anchore's evaluation of one image, under one tag, against one policy: pass or fail, the final action, and the evaluation as returned."
    ENTITY_ICON: ClassVar[str] = "anchore-policy-evaluation"
    DEFAULT_DIMENSIONS: ClassVar[dict[str, str]] = {"anchore.area": "policy"}
    NATURAL_KEY: ClassVar[tuple[str, ...]] = ("scanner_key", "image_digest", "evaluated_tag", "policy_id")

    OUTBOUND_EDGES: ClassVar[list[dict[str, Any]]] = [
        {"nodes": [{"type": "computing_core__host"}], "edges": [{"type": "EVALUATES_IMAGE__anchore"}]},
    ]

    # Nothing points at a verdict; what concerns the image points at its host.
    INBOUND_EDGES: ClassVar[list[dict[str, Any]]] = []

    FIELD_CRUD_SCHEMA: ClassVar[dict[str, Any]] = {
        "scanner_key": {"type": "string", "minLength": 1},
        "image_digest": {"type": "string", "minLength": 1},
        "evaluated_tag": {"type": "string", "minLength": 1},
        "policy_id": {"type": "string", "minLength": 1},
        "status": _STR_OR_NULL,
        "final_action": _STR_OR_NULL,
        "final_action_reason": _STR_OR_NULL,
        "number_of_findings": {"type": ["integer", "null"], "minimum": 0},
        "evaluation_time": _STR_OR_NULL,
        "comparison_image_digest": _STR_OR_NULL,
        "image_allowlisted": _BOOL_OR_NULL,
        "image_denylisted": _BOOL_OR_NULL,
        "last_seen_run_id": _STR_OR_NULL,
        "record": {"type": ["object", "null"]},
    }
    FIELD_VALIDATION_SCHEMA: ClassVar[dict[str, Any]] = {
        name: {"validation": "jsonschema", "schema": schema}
        for name, schema in FIELD_CRUD_SCHEMA.items()
    }
    CREATE_REQUIRED: ClassVar[list[str]] = ["scanner_key", "image_digest", "evaluated_tag", "policy_id"]

    scanner_key = models.CharField(max_length=1024, db_index=True, help_text="The scanner that evaluated it (credential.scanner_key).")
    image_digest = models.CharField(max_length=512, help_text="The digest of the image evaluated. Part of the identity.")
    evaluated_tag = models.CharField(
        max_length=512,
        help_text="The full tag the image was evaluated under: the one asked for, which the response must not contradict. Part of the identity, so bounded to keep the key's index within what PostgreSQL can hold.",
    )
    policy_id = models.CharField(max_length=255, help_text="The id of the policy Anchore evaluated against, as returned. Part of the identity.")
    status = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="Anchore's status as returned: pass or fail. Null when the evaluation carried none.")
    final_action = models.CharField(max_length=16, null=True, blank=True, default=None, help_text="Anchore's final_action as returned: stop, go or warn.")
    final_action_reason = models.CharField(
        max_length=64, null=True, blank=True, default=None, help_text="Why the final action is what it is, as returned: policy_evaluation, allowlisted or denylisted."
    )
    number_of_findings = models.PositiveIntegerField(null=True, blank=True, default=None, help_text="Anchore's number_of_findings for the evaluation. Null when not returned.")
    evaluation_time = models.DateTimeField(null=True, blank=True, default=None, help_text="When Anchore evaluated; null when not returned or unreadable.")
    comparison_image_digest = models.CharField(
        max_length=512, null=True, blank=True, default=None, help_text="The base image Anchore compared against for this evaluation, as returned; null when it named none."
    )
    image_allowlisted = models.BooleanField(null=True, blank=True, default=None, help_text="Anchore's image_allowlisted as returned.")
    image_denylisted = models.BooleanField(null=True, blank=True, default=None, help_text="Anchore's image_denylisted as returned.")
    last_seen_run_id = models.CharField(max_length=64, null=True, blank=True, default=None, help_text="The run that last read this evaluation.")
    record = models.JSONField(
        null=True,
        blank=True,
        default=None,
        help_text="The evaluation exactly as Anchore returned it, its findings and matched rules included. Source: GET /images/{image_digest}/check.",
    )

    class Meta(BaseModel.Meta):
        db_table = "anchore_policy_evaluation"

    def get_name(self) -> str:
        verdict = self.status or "unevaluated"
        return f"{verdict} · {self.evaluated_tag}" if self.evaluated_tag else verdict

    def __str__(self) -> str:
        return self.get_name()
