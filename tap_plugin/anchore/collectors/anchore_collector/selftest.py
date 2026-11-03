"""The per-run schema self-test: compare an instance's own API description with the committed extract
(req-anchore-selftest).

Pure comparison, no I/O and no Django. The caller fetches the instance's OpenAPI file, reduces it
with the same reducer that built the committed extract (``req-anchore-selftest-5``) and passes both
extracts here, with the manifest's sources, so only what the collector reads is compared:

- error: a required source is gone or has no 2xx response; a field the parser requires is removed,
  changed type, or is no longer listed as required by its enclosing object, at any step of its path; a required parameter appears that the committed extract did not have.
- warn: an optional source is gone (listed as not read), an optional field is gone or changed type,
  a new enum value appears on a field the collector reads (or its enum is removed), or the instance's version differs.
- pass: nothing above (additive change the collector does not read is not looked at).

A result is a verdict plus every difference behind it, so a verdict can be audited from the scan run.
"""

from dataclasses import dataclass
from typing import Any

from tap_plugin.anchore.collectors.anchore_collector.manifest import Source
from tap_plugin.anchore.collectors.anchore_collector.paths import enum_of, required_along, resolve_chain, type_of

ERROR = "error"
WARN = "warn"
PASS = "pass"


@dataclass(frozen=True)
class Difference:
    level: str
    source_id: str
    message: str


@dataclass(frozen=True)
class SelfTestResult:
    verdict: str
    differences: tuple[Difference, ...]
    not_read: tuple[str, ...]

    def as_detail(self) -> dict[str, Any]:
        """The JSON the scan run keeps as selftest_detail."""
        return {
            "differences": [{"level": d.level, "source": d.source_id, "message": d.message} for d in self.differences],
            "not_read": list(self.not_read),
        }


def _operation(extract: dict[str, Any], path: str) -> dict[str, Any] | None:
    for op in extract.get("operations", []):
        if op.get("method") == "get" and op.get("path") == path:
            return op
    return None


def _success_schemas(op: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Every 2xx response schema of the operation, by status code."""
    return {
        str(r["status"]): r["schema"]
        for r in op.get("responses", [])
        if str(r.get("status", "")).startswith("2") and isinstance(r.get("schema"), dict)
    }


def _bodyless_successes(op: dict[str, Any]) -> set[str]:
    """Status codes of 2xx responses the description gives no schema for (a 204, or a bare 200)."""
    return {
        str(r["status"])
        for r in op.get("responses", [])
        if str(r.get("status", "")).startswith("2") and not isinstance(r.get("schema"), dict)
    }


def _required_parameters(op: dict[str, Any]) -> set[tuple[str, str]]:
    return {(str(p.get("name")), str(p.get("in"))) for p in op.get("parameters", []) if p.get("required")}


def compare(committed: dict[str, Any], fresh: dict[str, Any], sources: tuple[Source, ...]) -> SelfTestResult:
    """Compare the instance's extract with the committed one, over the manifest's sources only."""
    found: list[Difference] = []
    not_read: list[str] = []

    old_version = (committed.get("source") or {}).get("version")
    new_version = (fresh.get("source") or {}).get("version")
    if old_version != new_version:
        found.append(Difference(WARN, "*", f"the instance describes API version {new_version!r}; the committed extract is {old_version!r}"))

    for source in sources:
        loss = ERROR if source.required else WARN
        old_op, new_op = _operation(committed, source.path), _operation(fresh, source.path)
        if old_op is None:
            found.append(Difference(ERROR, source.id, f"GET {source.path} is not in the committed extract"))
            continue
        if new_op is None:
            found.append(Difference(loss, source.id, f"GET {source.path} is not offered by the instance"))
            if not source.required:
                not_read.append(source.id)
            continue
        added = sorted(_required_parameters(new_op) - _required_parameters(old_op))
        if added:
            found.append(Difference(ERROR, source.id, f"GET {source.path} now requires {', '.join(f'{n} ({w})' for n, w in added)}"))
        old_schemas, new_schemas = _success_schemas(old_op), _success_schemas(new_op)
        if not new_schemas:
            found.append(Difference(loss, source.id, f"GET {source.path} has no 2xx response schema on the instance"))
            if not source.required:
                not_read.append(source.id)
            continue
        if not old_schemas:
            continue
        # A successful response with no schema carries none of the fields the parser needs, so one the
        # instance describes and the committed extract does not is a loss at the source's severity.
        for status in sorted(_bodyless_successes(new_op) - _bodyless_successes(old_op)):
            found.append(Difference(loss, source.id, f"GET {source.path} can now succeed with {status} and no described body"))
        baseline = next(iter(old_schemas.values()))
        # Every successful response the instance describes is a shape the client may receive, so each
        # is held to the committed schema of the same status (or the committed first one when the
        # status is new), not just the first.
        for status, new_schema in new_schemas.items():
            old_schema = old_schemas.get(status, baseline)
            where = f"GET {source.path}" + (f" ({status})" if len(new_schemas) > 1 or status not in old_schemas else "")
            if status not in old_schemas:
                found.append(Difference(WARN, source.id, f"{where} is a successful response the committed extract does not have"))
            for field, level in [(f, ERROR) for f in source.required_fields] + [(f, WARN) for f in source.optional_fields]:
                old_chain, new_chain = resolve_chain(old_schema, field), resolve_chain(new_schema, field)
                if old_chain is None:
                    continue
                if new_chain is None:
                    found.append(Difference(level, source.id, f"field {field} is gone from {where}"))
                    continue
                for depth, (old_node, new_node) in enumerate(zip(old_chain, new_chain, strict=True)):
                    if type_of(old_node) != type_of(new_node):
                        part = field if depth == len(old_chain) - 1 else f"{field} (a container on the way)"
                        found.append(Difference(level, source.id, f"field {part} changed type from {'/'.join(type_of(old_node)) or 'untyped'} to {'/'.join(type_of(new_node)) or 'untyped'}"))
                old_req, new_req = required_along(old_schema, field), required_along(new_schema, field)
                if old_req is not None and new_req is not None and any(o and not n for o, n in zip(old_req, new_req, strict=True)):
                    found.append(Difference(level, source.id, f"field {field} (or a container on the way) is no longer guaranteed present in {where}"))
                old_enum, new_enum = enum_of(old_chain[-1]), enum_of(new_chain[-1])
                if old_enum is not None and new_enum is None:
                    found.append(Difference(WARN, source.id, f"field {field} no longer lists its allowed values, so any value may now arrive"))
                elif old_enum is not None and new_enum is not None and new_enum - old_enum:
                    values = ", ".join(sorted(str(v) for v in new_enum - old_enum))
                    found.append(Difference(WARN, source.id, f"field {field} has new values the collector does not know: {values}"))

    verdict = ERROR if any(d.level == ERROR for d in found) else WARN if found else PASS
    return SelfTestResult(verdict=verdict, differences=tuple(found), not_read=tuple(not_read))
