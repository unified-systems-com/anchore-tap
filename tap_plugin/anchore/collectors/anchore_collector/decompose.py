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

from tap_plugin.anchore import scope
from tap_plugin.anchore.models.finding import AnchoreFinding, package_key_for
from tap_plugin.anchore.models.runtime_image import AnchoreRuntimeImage
from tap_plugin.anchore.models.scan_run import AnchoreScanRun
from tap_plugin.anchore.models.scanner import AnchoreScanner

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


def envelope(ref: str, model: Any, name: str, fields: dict[str, Any]) -> dict[str, Any]:
    return {
        "entity": {"ref": ref, "entity_type": model.ENTITY_TYPE, "name": name[:255] or model.ENTITY_NAME, "dimensions": dict(model.DEFAULT_DIMENSIONS)},
        "node": fields,
    }


def edge(ref: str, slug: str, from_ref: str, to_ref: str) -> dict[str, Any]:
    return {
        "entity": {"ref": ref, "entity_type": "edge", "name": slug, "dimensions": {}},
        "edge": {"from_ref": from_ref, "to_ref": to_ref, "edge_type": slug, "properties": {}},
    }


def edge_to_key(ref: str, slug: str, from_ref: str, entity_type: str, key: dict[str, str]) -> dict[str, Any]:
    """An edge from a node of this batch to a node named by type and natural key, which must already exist or be in the batch."""
    return {
        "entity": {"ref": ref, "entity_type": "edge", "name": slug, "dimensions": {}},
        "edge": {"from_ref": from_ref, "to_key": {"entity_type": entity_type, "key": key}, "edge_type": slug, "properties": {}},
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


def host_node(ref: str, digest: str) -> dict[str, Any]:
    """The image host for a digest: the computing_core host with realm oci-digest. Written only where none exists."""
    return envelope(ref, Host, digest, {"realm": IMAGE_REALM, "stable_id": digest, "kind": "container"})


def host_key(digest: str) -> dict[str, str]:
    return {"realm": IMAGE_REALM, "stable_id": digest}


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


def sbom_node(ref: str, source_id: str, body: bytes, document: Any, subject_digest: str, api_root: str, account: str) -> dict[str, Any]:
    """The record that one SBOM existed: the digest of its exact bytes, never the body. Never marked verified."""
    note = f"{UNSIGNED_NOTE_PREFIX} {api_root} as {account}"
    if len(note) > 255 or re.search(r"[\x00-\x1f\x7f]", note):
        note = f"{UNSIGNED_NOTE_PREFIX} an Anchore instance"
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
