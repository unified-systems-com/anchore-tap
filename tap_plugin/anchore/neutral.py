"""The neutral finding beside each Anchore finding (req-anchore-neutral).

A page that shows vulnerabilities from every scanner cannot read each scanner's own types. It
reads compliance_core's: a component carries a finding, and the finding concerns a shared
vulnerability record. So beside each ``anchore_finding`` this plugin writes one
``compliance_core__compliance_finding``, with the edges that shape needs. Anchore's own finding
stays the record of what Anchore said; the neutral one is the same assertion in the shape every
scanner shares, and an edge joins the two.

Pure: field values in, GRIFT fragments out. No grid is read here.
"""

import hashlib
import json
from typing import Any

from tap_plugin.anchore import scope

SOURCE = "anchore"
FINDING_TYPE = "compliance_core__compliance_finding"
VULNERABILITY_TYPE = "compliance_core__compliance_vulnerability"
CARRIES = "CARRIES_COMPLIANCE_FINDING__compliance_core"
CONCERNS = "CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core"
DETAILS = "DETAILS_COMPLIANCE_FINDING__anchore"

MAX_VULN_ID = 128
_MAX_NAME = 255
_MAX_SUMMARY = 500
#: Anchore writes this word, as text, where a finding has no fix.
_NO_FIX = "None"
#: Anchore finding states and the neutral status each is.
_STATUS = {"current": "open", "resolved": "resolved"}


def source_key(fields: dict[str, Any]) -> str:
    """What this plugin calls the finding: a digest of the five values that key Anchore's own node.

    A digest and not the values joined, because a scanner key and a target key can each be long
    and the neutral key column holds 512 characters. It is opaque to compliance_core by design.
    """
    parts = [fields["scanner_key"], fields["vulnerability_id"], fields["target_kind"], fields["target_key"], fields["package_key"]]
    return hashlib.sha256(json.dumps(parts, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def finding_key(fields: dict[str, Any]) -> dict[str, str]:
    return {"source": SOURCE, "source_key": source_key(fields)}


def finding_node(ref: str, fields: dict[str, Any], dimensions: dict[str, str]) -> dict[str, Any]:
    """The neutral finding for one Anchore finding. ``dimensions`` are compliance_core's defaults for the type."""
    vulnerability = fields["vulnerability_id"]
    component = fields.get("package_name") or fields.get("package") or fields["target_key"]
    name = f"{vulnerability} in {component}"[:_MAX_NAME]
    said = [part for part in (fields.get("severity"), f"fix {fields['fix']}" if _has_fix(fields.get("fix")) else None) if part]
    detected = scope.parse_time(fields.get("detected_at"))
    node: dict[str, Any] = {
        **finding_key(fields),
        "name": name,
        "summary": ", ".join(said)[:_MAX_SUMMARY],
        "status": _STATUS.get(fields.get("state") or "current", "open"),
        # When Anchore first detected it; left out where Anchore gave none, so a stored value is kept.
        **({"first_detected_at": detected.isoformat()} if detected is not None else {}),
    }
    return {"entity": {"ref": ref, "entity_type": FINDING_TYPE, "name": name, "dimensions": dict(dimensions)}, "node": node}


def _has_fix(fix: Any) -> bool:
    return isinstance(fix, str) and bool(fix.strip()) and fix.strip() != _NO_FIX


def concerns_properties(fields: dict[str, Any]) -> dict[str, Any]:
    """What rides the edge from the finding to the vulnerability: the fix for this component, as Anchore gave it."""
    fix = fields.get("fix")
    properties: dict[str, Any] = {"fixed_versions": [part.strip() for part in fix.split(",") if part.strip()] if _has_fix(fix) else []}
    if fields.get("will_not_fix") is True:
        properties["fix_state"] = "wont-fix"
    elif _has_fix(fix):
        properties["fix_state"] = "fixed"
    elif isinstance(fix, str) and fix.strip() == _NO_FIX:
        properties["fix_state"] = "not-fixed"
    # No fix_state where Anchore's record carried no fix field at all: absent means the source said nothing.
    return properties


def cvss_of(fields: dict[str, Any]) -> dict[str, Any]:
    """The CVSS base score Anchore returned with a finding, from NVD's data, or nothing.

    Version 3 is preferred to version 2 wherever it is found, and within a version the primary
    NVD entry to a secondary: a secondary entry's version 3 score is used before a primary
    entry's version 2. Anchore writes a negative number where it has no score; that is not a score.
    """
    entries = [e for e in fields.get("nvd_data") or [] if isinstance(e, dict)]
    entries.sort(key=lambda e: e.get("type") != "Primary")
    for version, label in (("cvss_v3", "3"), ("cvss_v2", "2")):
        for entry in entries:
            scores = entry.get(version)
            score = scores.get("base_score") if isinstance(scores, dict) else None
            if isinstance(score, (int, float)) and not isinstance(score, bool) and 0 <= score <= 10:
                source = entry.get("source") if isinstance(entry.get("source"), str) and entry.get("source") else "NVD"
                return {"cvss_score": float(score), "cvss_version": label, "cvss_source": f"{source}, as returned by Anchore"}
    return {}


def vulnerability_node(ref: str, vuln_id: str, dimensions: dict[str, str] | None, scores: dict[str, Any]) -> dict[str, Any]:
    """The shared vulnerability record: its identifier, and Anchore's CVSS where there is one to give.

    ``dimensions`` are the type's defaults for a record being created, and the record's own
    dimensions, as the grid holds them, for a record being given a score. A fill must send the
    held ones back unchanged: the importer requires a map on every node, and this plugin has no
    business restamping a record another producer wrote.
    """
    return {"entity": {"ref": ref, "entity_type": VULNERABILITY_TYPE, "name": vuln_id, "dimensions": dict(dimensions or {})}, "node": {"vuln_id": vuln_id, **scores}}


def usable_vuln_id(vuln_id: Any) -> bool:
    return isinstance(vuln_id, str) and 0 < len(vuln_id) <= MAX_VULN_ID
