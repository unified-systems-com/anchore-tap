"""Check a response body against the committed extract's schema before any node is written
(req-anchore-selftest-6).

The self-test compares descriptions; this checks the data itself, so a deployment whose description
cannot be fetched is still covered, and a response that does not have the shape the parser expects
never reaches it. No grid, no network, no Django.

The extract keeps OpenAPI 3.0 schemas, where ``nullable: true`` widens a type; JSON Schema reads that
keyword as nothing, so it is rewritten first. A failure names the path inside the body and the rule
that failed, never a value: a response can hold names, addresses and credentials.
"""

import copy
from dataclasses import dataclass
from typing import Any

import jsonschema

from tap_plugin.anchore.collectors.anchore_collector.manifest import Source


@dataclass(frozen=True)
class Validation:
    ok: bool
    reason: str | None


def _widen_nullable(node: Any) -> Any:
    """Rewrite OpenAPI 3.0 ``nullable: true`` into a JSON Schema type union (and an allowed None in an enum)."""
    if isinstance(node, list):
        return [_widen_nullable(n) for n in node]
    if not isinstance(node, dict):
        return node
    out = {key: _widen_nullable(value) for key, value in node.items() if key != "nullable"}
    if node.get("nullable") is True:
        declared = out.get("type")
        if isinstance(declared, str):
            out["type"] = [declared, "null"]
        elif isinstance(declared, list) and "null" not in declared:
            out["type"] = [*declared, "null"]
        if isinstance(out.get("enum"), list) and None not in out["enum"]:
            out["enum"] = [*out["enum"], None]
    return out


def _schema_for(extract: dict[str, Any], path: str, status: int) -> dict[str, Any] | None:
    for op in extract.get("operations", []):
        if op.get("method") == "get" and op.get("path") == path and op.get("present") is not False:
            for response in op.get("responses", []):
                if str(response.get("status")) == str(status) and isinstance(response.get("schema"), dict):
                    return response["schema"]
    return None


def validate_body(extract: dict[str, Any], source: Source, status: int, body: Any) -> Validation:
    """Whether ``body``, received with ``status`` from ``source``, has the committed response shape.

    A status the extract has no schema for is not valid: the collector has no description of what it
    received, which is the situation this check exists to refuse.
    """
    schema = _schema_for(extract, source.path, status)
    if schema is None:
        return Validation(False, f"the committed extract has no response schema for HTTP {status}")
    try:
        validator = jsonschema.Draft202012Validator(_widen_nullable(copy.deepcopy(schema)))
        error = next(iter(sorted(validator.iter_errors(body), key=lambda e: [str(p) for p in e.absolute_path])), None)
    except jsonschema.SchemaError:
        return Validation(False, "the committed schema is not a usable JSON Schema")
    except RecursionError:
        return Validation(False, "the body nests too deeply to validate")
    if error is None:
        return Validation(True, None)
    where = "/" + "/".join(str(p) for p in error.absolute_path) if error.absolute_path else "(the body itself)"
    return Validation(False, f"the body does not match the committed shape at {where} ({error.validator})")
