"""Turn Anchore's responses into GRIFT node and edge envelopes (req-anchore-findings, req-anchore-states).

Nodes are named by batch-local ``ref`` and found again by the grid through each model's declared
natural key, so nothing here derives an id. Every Anchore value is carried as returned: a key the
response did not carry is null (unobserved), never a default, and a value the model cannot hold is
dropped to null and listed, never altered or guessed. No interpretation: severity, fix state and
identifiers pass through untouched.

Reads no grid and no network; it needs Django only for the model classes it reads field rules from.
"""

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

import jsonschema
from django.db import models as dj_models

from tap_plugin.computing_core.models.host import Host
from tap_plugin.computing_core.models.sbom_document import SbomDocument

from tap_plugin.anchore import keys, scope
from tap_plugin.anchore.models.finding import AnchoreFinding, package_key_for
from tap_plugin.anchore.models.image import AnchoreImage
from tap_plugin.anchore.models.policy_evaluation import AnchorePolicyEvaluation
from tap_plugin.anchore.models.runtime_image import AnchoreRuntimeImage
from tap_plugin.anchore.models.scan_run import AnchoreScanRun
from tap_plugin.anchore.models.scanner import AnchoreScanner
from tap_plugin.anchore.models.vex_annotation import AnchoreVexAnnotation

#: Anchore finding key -> AnchoreFinding field, where the two differ.
_RENAMED = {"vuln": "vulnerability_id"}
#: The response keys a finding takes; any other key the entry carries is counted, not stored.
_CARRIED = (
    "severity", "fix", "suggested_fix_version", "fix_observed_at", "will_not_fix", "is_kev", "epss",
    "nvd_data", "vendor_data", "annotation_status", "annotation_uuid", "description", "url", "feed",
    "feed_group", "detected_at", "inherited_from_base", "package", "package_name", "package_version",
    "package_type", "package_path", "purl", "package_cpe", "package_cpe23", "matched_on_cpes",
)
CURRENT = "current"
RESOLVED = "resolved"


#: An image digest as the image host's key holds it (computing_core: realm oci-digest).
OCI_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
IMAGE_REALM = "oci-digest"

#: The SBOM source id -> the format name recorded on the document. cyclonedx and spdx are the names
#: computing_core uses; Anchore's native document is named for Anchore, not for any tool inside it.
SBOM_FORMATS = {"sbom_native": "anchore-native", "sbom_spdx": "spdx", "sbom_cyclonedx": "cyclonedx"}


@dataclass
class Decomposition:
    """What one image's vulnerabilities became, and what could not be carried."""

    nodes: list[dict[str, Any]] = field(default_factory=list)
    seen_keys: set[tuple[str, str]] = field(default_factory=set)
    skipped_entries: int = 0
    duplicate_entries: int = 0
    dropped_fields: list[dict[str, str]] = field(default_factory=list)
    uncarried_keys: set[str] = field(default_factory=set)


def _fit(model: type[dj_models.Model], name: str, value: Any, schema: dict[str, Any]) -> tuple[Any, str | None]:
    """The value if the model can hold it, else (None, why)."""
    if value is None:
        return None, None
    try:
        jsonschema.validate(value, schema)
    except jsonschema.ValidationError:
        return None, "not the form the model holds"
    column = model._meta.get_field(name)
    limit = getattr(column, "max_length", None)
    if limit is not None and isinstance(value, str) and len(value) > limit:
        return None, f"longer than {limit} characters"
    return value, None


#: The dimension that scopes an Anchore-owned node to the instance and account it was read from
#: (req-anchore-dimensions-2). Its value is the node's scanner key.
INSTANCE_DIMENSION = "anchore.instance"
#: The slug prefix of the types this plugin owns.
OWN_TYPE_PREFIX = "anchore__"


def envelope(ref: str, model: Any, name: str, fields: dict[str, Any]) -> dict[str, Any]:
    """A node of a model this module imports, with the type's dimensions.

    A node of one of this plugin's own types also says which instance it came from. Every own
    type is keyed under a scanner key, so one without it is refused here and not written
    unscoped: the instance dimension is what a filter or a removal by scope relies on. A node of
    another plugin's type (an image host, an SBOM document) never carries it.
    """
    dimensions = dict(model.DEFAULT_DIMENSIONS)
    if model.ENTITY_TYPE.startswith(OWN_TYPE_PREFIX):
        scanner_key = fields.get("scanner_key")
        if not isinstance(scanner_key, str) or not scanner_key:
            raise ValueError(f"{model.ENTITY_TYPE} node has no scanner_key; it cannot be scoped to an Anchore instance")
        dimensions[INSTANCE_DIMENSION] = scanner_key
    return {
        "entity": {"ref": ref, "entity_type": model.ENTITY_TYPE, "name": name[:255] or model.ENTITY_NAME, "dimensions": dimensions},
        "node": fields,
    }


def edge(ref: str, slug: str, from_ref: str, to_ref: str) -> dict[str, Any]:
    return {
        "entity": {"ref": ref, "entity_type": "edge", "name": slug, "dimensions": {}},
        "edge": {"from_ref": from_ref, "to_ref": to_ref, "edge_type": slug, "properties": {}},
    }


def edge_to_key(ref: str, slug: str, from_ref: str, entity_type: str, key: dict[str, str], properties: dict[str, Any] | None = None) -> dict[str, Any]:
    """An edge from a node of this batch to a node named by type and natural key, which must already exist or be in the batch."""
    return {
        "entity": {"ref": ref, "entity_type": "edge", "name": slug, "dimensions": {}},
        "edge": {"from_ref": from_ref, "to_key": {"entity_type": entity_type, "key": key}, "edge_type": slug, "properties": dict(properties or {})},
    }


def edge_between_keys(ref: str, slug: str, from_type: str, from_key: dict[str, str], to_type: str, to_key: dict[str, str]) -> dict[str, Any]:
    """An edge between two nodes both named by type and natural key, each already on the grid or in the batch."""
    return {
        "entity": {"ref": ref, "entity_type": "edge", "name": slug, "dimensions": {}},
        "edge": {
            "from_key": {"entity_type": from_type, "key": from_key},
            "to_key": {"entity_type": to_type, "key": to_key},
            "edge_type": slug,
            "properties": {},
        },
    }


def edge_ends(ref: str, slug: str, source: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    """An edge whose ends are each a node of this batch (``{"ref": ...}``) or one named by type and natural key
    (``{"entity_type": ..., "key": {...}}``), which must already be on the grid."""
    body: dict[str, Any] = {"edge_type": slug, "properties": {}}
    for side, end in (("from", source), ("to", target)):
        if "ref" in end:
            body[f"{side}_ref"] = end["ref"]
        else:
            body[f"{side}_key"] = {"entity_type": end["entity_type"], "key": end["key"]}
    return {"entity": {"ref": ref, "entity_type": "edge", "name": slug, "dimensions": {}}, "edge": body}


def provider_node(ref: str, entity_type: str, name: str, fields: dict[str, Any], default_dimensions: dict[str, str], arn: Any) -> dict[str, Any]:
    """A node of a provider's type, created because the grid had none (req-anchore-shared, rule 8).

    It carries the dimensions the provider's own collector stamps, so it does not look foreign:
    the model's defaults, and ``cloud``, ``aws_region`` and ``aws_account`` read from the ARN.
    It never carries an Anchore dimension.
    """
    dimensions = {**default_dimensions, "cloud": "aws", "aws_region": arn.region, "aws_account": arn.account}
    return {"entity": {"ref": ref, "entity_type": entity_type, "name": name[:255], "dimensions": dimensions}, "node": fields}


def typed_node(ref: str, entity_type: str, name: str, fields: dict[str, Any], dimensions: dict[str, str]) -> dict[str, Any]:
    """A node of a type named by slug, with the dimensions its model declares."""
    return {"entity": {"ref": ref, "entity_type": entity_type, "name": name[:255] or entity_type, "dimensions": dict(dimensions)}, "node": fields}


def host_node(ref: str, digest: str, name: str | None = None, os: str | None = None) -> dict[str, Any]:
    """The image host for a digest: the computing_core host with realm oci-digest. Written only where none exists.

    ``name`` and ``os`` are set where Anchore's image record gives them (req-anchore-image-3); a
    host staged for a digest Anchore has no record of carries the digest alone.
    """
    fields: dict[str, Any] = {**host_key(digest), "kind": "container"}
    if name:
        fields["name"] = name
    if os:
        fields["os"] = os
    return envelope(ref, Host, name or digest, fields)


def host_fill(ref: str, digest: str, display: str, name: str | None, os: str | None) -> dict[str, Any]:
    """A write of only the name and operating system a host on the grid lacks; every other field is left as it is.

    ``display`` is the host's name as it will stand after the write, which the envelope must carry.
    """
    fields: dict[str, Any] = host_key(digest)
    if name:
        fields["name"] = name
    if os:
        fields["os"] = os
    return envelope(ref, Host, display, fields)


_MAX_HOST_NAME = 255
_MAX_HOST_OS = Host._meta.get_field("os").max_length or 255


def image_naming(image: Any) -> tuple[str | None, str | None]:
    """(display reference, operating system) from Anchore's image record, each None where it gives none.

    The reference is the first of the record's full tags in sorted order, so the choice does not
    move with the order Anchore lists them. The operating system is the distribution and its
    version as Anchore reports them.
    """
    if not isinstance(image, dict):
        return None, None
    tags = sorted(d["full_tag"] for d in image.get("image_detail") or [] if isinstance(d, dict) and isinstance(d.get("full_tag"), str) and d["full_tag"])
    name = next((tag for tag in tags if len(tag) <= _MAX_HOST_NAME), None)
    content = image.get("image_content")
    metadata = content.get("metadata") if isinstance(content, dict) else None
    distro = metadata.get("distro") if isinstance(metadata, dict) else None
    version = metadata.get("distro_version") if isinstance(metadata, dict) else None
    os = " ".join(part for part in (distro, version) if isinstance(part, str) and part) or None
    # A value the host's column cannot hold is not sent: it would fail the batch, and it is in the record.
    return name, os if os is not None and len(os) <= _MAX_HOST_OS else None


#: The image facts computing_core's host holds beyond its name and operating system (computing_core v0.10.6).
IMAGE_FACT_FIELDS = ("architecture", "image_size_bytes", "image_layer_count")


def image_facts(image: Any) -> dict[str, Any]:
    """What Anchore's image record says of the image itself, by the host field that holds it; a fact it does not give is left out.

    ``name`` and ``os`` as :func:`image_naming` gives them; ``architecture``, ``image_size_bytes`` and
    ``image_layer_count`` from the record's content metadata, each only where it has the type and
    range the host's field holds. Anchore's record has no build time for the image: its
    ``created_at`` is when Anchore made its own record, so ``image_built_at`` is never written.
    """
    name, os = image_naming(image)
    facts: dict[str, Any] = {key: value for key, value in (("name", name), ("os", os)) if value}
    content = image.get("image_content") if isinstance(image, dict) else None
    metadata = content.get("metadata") if isinstance(content, dict) else None
    if not isinstance(metadata, dict):
        return facts
    arch = metadata.get("arch")
    if isinstance(arch, str) and 0 < len(arch) <= 32:
        facts["architecture"] = arch
    for field_name, key, ceiling in (("image_size_bytes", "image_size", 9223372036854775807), ("image_layer_count", "layer_count", 2147483647)):
        value = metadata.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= ceiling:
            facts[field_name] = value
    return facts


_TAG_LIMITS = (("registry", 255), ("repo", 255), ("tag", 128))


def image_tag_rows(image: Any) -> list[dict[str, Any]]:
    """The tags Anchore lists for an image, as ``{registry, repository, tag, reference, detected_at}``, one per distinct tag, sorted.

    A detail missing a part, or with a part longer than computing_core's ``image_tag`` holds, names
    no tag and is left out. ``detected_at`` is Anchore's ``tag_detected_at`` where it reads as a time.
    """
    out: dict[tuple[str, str, str], dict[str, Any]] = {}
    for detail in (image.get("image_detail") or []) if isinstance(image, dict) else []:
        if not isinstance(detail, dict):
            continue
        parts = [detail.get(key) for key, _ in _TAG_LIMITS]
        if not all(isinstance(part, str) and 0 < len(part) <= limit for part, (_, limit) in zip(parts, _TAG_LIMITS, strict=True)):
            continue
        seen = scope.parse_time(detail.get("tag_detected_at"))
        out.setdefault((parts[0], parts[1], parts[2]), {"registry": parts[0], "repository": parts[1], "tag": parts[2], "reference": f"{parts[0]}/{parts[1]}:{parts[2]}", "detected_at": seen.isoformat() if seen is not None else None})
    return [out[key] for key in sorted(out)]


def image_tag_node(ref: str, row: dict[str, Any]) -> dict[str, Any]:
    """computing_core's image tag for one of Anchore's tag details."""
    return typed_node(ref, "computing_core__image_tag", row["reference"], {"registry": row["registry"], "repository": row["repository"], "tag": row["tag"]}, {"tap.computing": "runtime"})


def image_tags(image: Any) -> list[str]:
    """Every distinct full tag reference of an image record, sorted."""
    details = image.get("image_detail") if isinstance(image, dict) else None
    return sorted({d["full_tag"] for d in details or [] if isinstance(d, dict) and isinstance(d.get("full_tag"), str) and d["full_tag"]})


#: The longest tag an evaluation can be keyed by.
MAX_EVALUATED_TAG = 512


def policy_evaluation_node(ref: str, scanner_key: str, digest: str, tag: str, body: dict[str, Any], run_id: str) -> dict[str, Any] | None:
    """Anchore's verdict on an image under one tag (req-anchore-image-policy-1), or None when the response names no policy, holds no evaluation, or says it evaluated another tag or another image.

    The response's first evaluation is the one stored: without ``history`` Anchore returns the
    latest. The whole response is kept in ``record``.
    """
    policy_id = body.get("policy_id")
    evaluations = body.get("evaluations")
    evaluation = evaluations[0] if isinstance(evaluations, list) and evaluations and isinstance(evaluations[0], dict) else None
    if not isinstance(policy_id, str) or not policy_id or len(policy_id) > 255 or evaluation is None or len(tag) > MAX_EVALUATED_TAG:
        return None
    # The verdict is filed under the tag asked for. A response that says it evaluated some other tag
    # is not a verdict on this one, and policy is tag-sensitive, so it is not stored under it.
    said = body.get("evaluated_tag")
    if isinstance(said, str) and said and said != tag:
        return None
    # Likewise a response that names another image is not this image's verdict.
    about = body.get("image_digest")
    if isinstance(about, str) and about and about != digest:
        return None

    def text(name: str, limit: int) -> str | None:
        value = evaluation.get(name)
        return value if isinstance(value, str) and len(value) <= limit else None

    def flag(name: str) -> bool | None:
        value = evaluation.get(name)
        return value if isinstance(value, bool) else None

    count = evaluation.get("number_of_findings")
    when = scope.parse_time(evaluation.get("evaluation_time"))
    fields: dict[str, Any] = {
        "scanner_key": scanner_key,
        "image_digest": digest,
        "evaluated_tag": tag,
        "policy_id": policy_id,
        "state": CURRENT,
        "status": text("status", 16),
        "final_action": text("final_action", 16),
        "final_action_reason": text("final_action_reason", 64),
        "number_of_findings": count if isinstance(count, int) and not isinstance(count, bool) and 0 <= count <= 2147483647 else None,
        "evaluation_time": when.isoformat() if when is not None else None,
        "comparison_image_digest": text("comparison_image_digest", 512),
        "image_allowlisted": flag("image_allowlisted"),
        "image_denylisted": flag("image_denylisted"),
        "last_seen_run_id": run_id,
        "record": body,
    }
    return envelope(ref, AnchorePolicyEvaluation, f"{fields['status'] or 'unevaluated'} · {tag}", fields)


SUPERSEDED = "superseded"


def superseded_policy_node(row: AnchorePolicyEvaluation, ref: str) -> dict[str, Any]:
    """A verdict a later read replaced: every field re-sent as stored, with only the state changed."""
    fields = {name: getattr(row, name) for name in AnchorePolicyEvaluation.FIELD_CRUD_SCHEMA}
    fields["state"] = SUPERSEDED
    fields["evaluation_time"] = row.evaluation_time.isoformat() if row.evaluation_time is not None else None
    return envelope(ref, AnchorePolicyEvaluation, f"superseded {row.status or 'unevaluated'} · {row.evaluated_tag}", fields)


WITHDRAWN = "withdrawn"
#: The VEX annotation's own columns that hold text as returned, each with the longest value its column takes.
_VEX_TEXT = {"status": 32, "justification": 64, "status_notes": None, "impact_statement": None, "action_statement": None, "additional_details": None}


def vex_annotation_node(ref: str, scanner_key: str, scope_kind: str, scope_id: str, item: Any, run_id: str) -> dict[str, Any] | None:
    """One VEX annotation of a scope as Anchore returned it (req-anchore-vex-1), or None when it has no usable uuid or vulnerability id.

    ``item`` is one entry of the list: the annotation and, beside it, the package it is scoped
    to. A null package scope stays null (req-anchore-vex-5). The whole entry is kept in ``record``.
    """
    annotation = item.get("annotation") if isinstance(item, dict) else None
    if not isinstance(annotation, dict):
        return None
    uuid_, vulnerability = annotation.get("uuid"), annotation.get("vulnerability_id")
    if not (isinstance(uuid_, str) and 0 < len(uuid_) <= 64 and isinstance(vulnerability, str) and 0 < len(vulnerability) <= 255):
        return None

    def text(holder: Any, name: str, limit: int | None) -> str | None:
        value = holder.get(name) if isinstance(holder, dict) else None
        return value if isinstance(value, str) and (limit is None or len(value) <= limit) else None

    package, source = item.get("package_identifier"), annotation.get("source")
    version = annotation.get("version")
    created, updated = scope.parse_time(annotation.get("created_at")), scope.parse_time(annotation.get("updated_at"))
    fields: dict[str, Any] = {
        "scanner_key": scanner_key,
        "scope_kind": scope_kind,
        "scope_id": scope_id,
        "annotation_id": uuid_,
        "state": CURRENT,
        "vulnerability_id": vulnerability,
        "package_name": text(package, "name", 512),
        "package_version": text(package, "version", 512),
        "package_type": text(package, "type", 64),
        **{name: text(annotation, name, limit) for name, limit in _VEX_TEXT.items()},
        "source_type": text(source, "type", 32),
        "source_name": text(source, "name", 512),
        "annotation_version": version if isinstance(version, int) and not isinstance(version, bool) and 0 <= version <= 2147483647 else None,
        "annotation_created_at": created.isoformat() if created is not None else None,
        "annotation_updated_at": updated.isoformat() if updated is not None else None,
        "last_seen_run_id": run_id,
        "record": item,
    }
    return envelope(ref, AnchoreVexAnnotation, f"{fields['status'] or 'unstated'} · {vulnerability}", fields)


def withdrawn_vex_node(row: AnchoreVexAnnotation, ref: str) -> dict[str, Any]:
    """A statement a later whole read of its scope no longer returned: every field re-sent as stored, with only the state changed."""
    fields = {name: getattr(row, name) for name in AnchoreVexAnnotation.FIELD_CRUD_SCHEMA}
    fields["state"] = WITHDRAWN
    for name in ("annotation_created_at", "annotation_updated_at"):
        fields[name] = fields[name].isoformat() if fields[name] is not None else None
    return envelope(ref, AnchoreVexAnnotation, f"withdrawn {row.status or 'unstated'} · {row.vulnerability_id}", fields)


def image_node(ref: str, scanner_key: str, image: dict[str, Any]) -> dict[str, Any]:
    """Anchore's record of one image (req-anchore-image-1): the analysis state, and the record as returned."""
    reference, _ = image_naming(image)
    fields: dict[str, Any] = {"scanner_key": scanner_key, "image_digest": image["image_digest"], "reference": reference, "record": image}
    for name, limit in (("analysis_status", 64), ("image_status", 64), ("parent_digest", 512)):
        value = image.get(name)
        fields[name] = value if isinstance(value, str) and len(value) <= limit else None
    for name in ("created_at", "last_updated"):
        seen = scope.parse_time(image.get(name))
        fields[name] = seen.isoformat() if seen is not None else None
    return envelope(ref, AnchoreImage, reference or image["image_digest"], fields)


def host_key(digest: str) -> dict[str, str]:
    return {keys.scheme_field(Host): IMAGE_REALM, keys.STABLE_ID: digest}


#: The longest inventory type and context the runtime image node can hold.
MAX_INVENTORY_TYPE = 32
MAX_CONTEXT = 1024
_MAX_IMAGE_TAG = 2048


def runtime_image_identified(item: Any) -> bool:
    """Whether an inventory item names the inventory type and context a runtime image node is keyed by."""
    kind, context = item.get("inventory_type"), item.get("context")
    return isinstance(kind, str) and 0 < len(kind) <= MAX_INVENTORY_TYPE and isinstance(context, str) and 0 < len(context) <= MAX_CONTEXT


def runtime_image_node(ref: str, scanner_key: str, item: Any, analyzed: list[str] | None = None) -> dict[str, Any]:
    """Anchore's observation that an image was in use in a context (req-anchore-inventory, req-anchore-scope-12).

    The item must be identified (:func:`runtime_image_identified`) and carry a sha256 digest. A tag
    or a time the response did not carry, or that the model cannot hold, is null (req-anchore-states-2).
    """
    tag = item.get("image_tag")
    fields: dict[str, Any] = {
        "scanner_key": scanner_key,
        "inventory_type": item["inventory_type"],
        "context": item["context"],
        "image_digest": item["image_digest"],
        "image_tag": tag if isinstance(tag, str) and len(tag) <= _MAX_IMAGE_TAG else None,
        # The analyzed images read on this digest's behalf (req-anchore-scope-16); the digest above stays the running one.
        "analyzed_digests": analyzed,
        "record": dict(item),
    }
    for name in ("created_at", "last_updated", "last_seen"):
        seen = scope.parse_time(item.get(name))
        fields[name] = seen.isoformat() if seen is not None else None
    return envelope(ref, AnchoreRuntimeImage, f"{fields['image_tag'] or fields['image_digest']} in {fields['context']}", fields)


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def loads_strict(body: bytes) -> Any:
    """Parse a body as JSON as the standard defines it: Python's NaN, Infinity and -Infinity are refused."""
    return json.loads(body, parse_constant=_no_constant)


def sbom_header(source_id: str, document: Any) -> dict[str, Any]:
    """What a CycloneDX document says about itself, as far as the document record holds it; nothing is parsed into packages.

    ``document`` is the body already parsed. Other formats state nothing here. A value the record
    cannot hold is left out, so the record's own default stands rather than a guess.
    """
    if source_id != "sbom_cyclonedx" or not isinstance(document, dict):
        return {}
    metadata = document.get("metadata") if isinstance(document.get("metadata"), dict) else {}
    candidates = {
        "spec_version": document.get("specVersion"),
        "serial_number": document.get("serialNumber"),
        "revision": document.get("version"),
        "produced_at": metadata.get("timestamp"),
        "component_count": len(document["components"]) if isinstance(document.get("components"), list) else None,
    }
    out: dict[str, Any] = {}
    for name, value in candidates.items():
        if value is None:
            continue
        try:
            jsonschema.validate(value, SbomDocument.FIELD_CRUD_SCHEMA[name])
        except jsonschema.ValidationError:
            continue
        out[name] = value
    return out


#: How the note on a document this plugin recorded without parsing begins; it is how the plugin knows its own.
UNSIGNED_NOTE_PREFIX = "unsigned; read from"


def unsigned_note(api_root: str, account: str) -> str:
    """The note on a document this plugin records without parsing, naming where it was read from."""
    note = f"{UNSIGNED_NOTE_PREFIX} {api_root} as {account}"
    if len(note) > 255 or re.search(r"[\x00-\x1f\x7f]", note):
        note = f"{UNSIGNED_NOTE_PREFIX} an Anchore instance"
    return note


def sbom_node(ref: str, source_id: str, body: bytes, document: Any, subject_digest: str, api_root: str, account: str) -> dict[str, Any]:
    """The record that one SBOM existed: the digest of its exact bytes, never the body. Never marked verified."""
    note = unsigned_note(api_root, account)
    digest = hashlib.sha256(body).hexdigest()
    fields: dict[str, Any] = {
        "content_digest": digest,
        "format": SBOM_FORMATS[source_id],
        **sbom_header(source_id, document),
        "subject_digest": subject_digest if re.fullmatch(r"[a-z0-9]{1,31}:[0-9a-f]{1,128}", subject_digest) else "",
        "verified": None,
        "verification_note": note,
    }
    return envelope(ref, SbomDocument, f"{SBOM_FORMATS[source_id]} {digest[:12]}", fields)


def finding_fields(entry: dict[str, Any], scanner_key: str, target_key: str, run_id: str, dropped: list[dict[str, str]], base_digest: str | None = None) -> dict[str, Any] | None:
    """The AnchoreFinding fields for one vulnerability entry, or None when its identity cannot be held exactly.

    ``base_digest`` is the base image the response says it compared against. Without one a false
    ``inherited_from_base`` is stored as null (req-anchore-base-image-3): "not inherited" with no
    base named is not an observation. A true flag is kept: it says a base held the package.
    """
    vuln = entry.get("vuln")
    if not isinstance(vuln, str) or not vuln or len(vuln) > 255:
        return None
    fields: dict[str, Any] = {
        "scanner_key": scanner_key,
        "vulnerability_id": vuln,
        "target_kind": "image",
        "target_key": target_key,
        "state": CURRENT,
        "last_seen_run_id": run_id,
    }
    unidentifiable = False
    for key in _CARRIED:
        value, why = _fit(AnchoreFinding, key, entry.get(key), AnchoreFinding.FIELD_CRUD_SCHEMA[key])
        # A package value the model cannot hold is part of the finding's identity: storing the entry
        # with it nulled would make two different packages one assertion, so the entry is not stored.
        part_of_identity = why is not None and key in ("package", "package_path")
        unidentifiable = unidentifiable or part_of_identity
        if why is not None:
            dropped.append({"vulnerability": vuln, "field": key, "reason": why, "effect": "entry not stored" if part_of_identity else "stored as unobserved"})
        fields[key] = value
    if unidentifiable:
        return None
    fields["package_key"] = package_key_for(fields["package"], fields["package_path"])
    # Nothing Anchore said is dropped: the entry as returned rides beside the fields taken from it (req-anchore-record-1).
    fields["record"] = entry
    fields["base_digest"] = base_digest
    if base_digest is None and fields["inherited_from_base"] is False:
        fields["inherited_from_base"] = None
    return fields


def decompose_image(entries: list[Any], scanner_key: str, target_key: str, run_id: str, ref_prefix: str, base_digest: str | None = None) -> Decomposition:
    """Finding nodes for one image's vulnerability entries; an assertion seen twice becomes one node."""
    out = Decomposition()
    for entry in entries:
        if not isinstance(entry, dict):
            out.skipped_entries += 1
            continue
        out.uncarried_keys.update(set(entry) - set(_CARRIED) - set(_RENAMED))
        fields = finding_fields(entry, scanner_key, target_key, run_id, out.dropped_fields, base_digest)
        if fields is None:
            out.skipped_entries += 1
            continue
        key = (fields["vulnerability_id"], fields["package_key"])
        if key in out.seen_keys:
            out.duplicate_entries += 1
            continue
        out.seen_keys.add(key)
        out.nodes.append(envelope(f"{ref_prefix}:{len(out.nodes)}", AnchoreFinding, f"{fields['vulnerability_id']} · {fields['package_name'] or fields['package'] or target_key}", fields))
    return out


def resolved_node(row: AnchoreFinding, run_id: str, ref: str) -> dict[str, Any]:
    """A previously current finding that a successful read of its image no longer reports.

    Every field is re-sent as it was stored, because a write replaces the node; only the state and
    the run that observed the absence change. The assertion is not deleted and not interpreted.
    """
    fields = {name: getattr(row, name) for name in AnchoreFinding.FIELD_CRUD_SCHEMA}
    fields["state"] = RESOLVED
    fields["last_seen_run_id"] = row.last_seen_run_id
    return envelope(ref, AnchoreFinding, row.get_name(), fields)


def scanner_node(ref: str, api_root: str, account: str, scanner_key: str, version: str | None) -> dict[str, Any]:
    fields = {"scanner_key": scanner_key, "api_root": api_root, "account": account, "reported_version": version}
    return envelope(ref, AnchoreScanner, f"{api_root} · {account}", fields)


def scan_run_node(ref: str, scanner_key: str, run_id: str, **observed: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {"scanner_key": scanner_key, "run_id": run_id, **observed}
    unknown = set(observed) - set(AnchoreScanRun.FIELD_CRUD_SCHEMA)
    if unknown:
        raise ValueError(f"not scan run fields: {sorted(unknown)}")
    return envelope(ref, AnchoreScanRun, f"run {run_id}", fields)


def new_run_id() -> str:
    return uuid.uuid4().hex
