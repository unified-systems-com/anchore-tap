"""Turn Anchore's responses into GRIFT node and edge envelopes (req-anchore-findings, req-anchore-states).

Nodes are named by batch-local ``ref`` and found again by the grid through each model's declared
natural key, so nothing here derives an id. Every Anchore value is carried as returned: a key the
response did not carry is null (unobserved), never a default, and a value the model cannot hold is
dropped to null and listed, never altered or guessed. No interpretation: severity, fix state and
identifiers pass through untouched.

Reads no grid and no network; it needs Django only for the model classes it reads field rules from.
"""

import uuid
from dataclasses import dataclass, field
from typing import Any

import jsonschema
from django.db import models as dj_models

from tap_plugin.anchore.models.finding import AnchoreFinding, package_key_for
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


def finding_fields(entry: dict[str, Any], scanner_key: str, target_key: str, run_id: str, dropped: list[dict[str, str]]) -> dict[str, Any] | None:
    """The AnchoreFinding fields for one vulnerability entry, or None when it names no usable identifier."""
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
    for key in _CARRIED:
        value, why = _fit(AnchoreFinding, key, entry.get(key), AnchoreFinding.FIELD_CRUD_SCHEMA[key])
        if why is not None:
            dropped.append({"vulnerability": vuln, "field": key, "reason": why})
        fields[key] = value
    fields["package_key"] = package_key_for(fields["package"], fields["package_path"])
    return fields


def decompose_image(entries: list[Any], scanner_key: str, target_key: str, run_id: str, ref_prefix: str) -> Decomposition:
    """Finding nodes for one image's vulnerability entries; an assertion seen twice becomes one node."""
    out = Decomposition()
    for entry in entries:
        if not isinstance(entry, dict):
            out.skipped_entries += 1
            continue
        out.uncarried_keys.update(set(entry) - set(_CARRIED) - set(_RENAMED))
        fields = finding_fields(entry, scanner_key, target_key, run_id, out.dropped_fields)
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
