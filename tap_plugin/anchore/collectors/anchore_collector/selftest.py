"""The per-run schema self-test: compare an instance's own API description with the committed extract
(req-anchore-selftest).

Pure comparison, no I/O and no Django. The caller fetches the instance's OpenAPI file, reduces it
with the same reducer that built the committed extract (``req-anchore-selftest-5``) and passes both
extracts here, with the manifest's sources, so only what the collector reads is compared:

- error: a required source is gone or has no 2xx response; a field the parser requires is removed
  or changed type; a required parameter appears that the committed extract did not have.
- warn: an optional source is gone (listed as not read), an optional field is gone or changed type,
  a new enum value appears on a field the collector reads (or its enum is removed), or the instance's version differs.
- pass: nothing above (additive change the collector does not read is not looked at).

A result is a verdict plus every difference behind it, so a verdict can be audited from the scan run.
"""

from dataclasses import dataclass
from typing import Any

from tap_plugin.anchore.collectors.anchore_collector.manifest import Source
from tap_plugin.anchore.collectors.anchore_collector.paths import enum_of, resolve_field, type_of

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


def _success_schema(op: dict[str, Any]) -> dict[str, Any] | None:
    for response in op.get("responses", []):
        if str(response.get("status", "")).startswith("2") and isinstance(response.get("schema"), dict):
            return response["schema"]
    return None


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
        old_schema, new_schema = _success_schema(old_op), _success_schema(new_op)
        if new_schema is None:
            found.append(Difference(loss, source.id, f"GET {source.path} has no 2xx response schema on the instance"))
            if not source.required:
                not_read.append(source.id)
            continue
        if old_schema is None:
            continue
        for field, level in [(f, ERROR) for f in source.required_fields] + [(f, WARN) for f in source.optional_fields]:
            old_node, new_node = resolve_field(old_schema, field), resolve_field(new_schema, field)
            if old_node is None:
                continue
            if new_node is None:
                found.append(Difference(level, source.id, f"field {field} is gone from GET {source.path}"))
                continue
            if type_of(old_node) != type_of(new_node):
                found.append(Difference(level, source.id, f"field {field} changed type from {'/'.join(type_of(old_node)) or 'untyped'} to {'/'.join(type_of(new_node)) or 'untyped'}"))
            old_enum, new_enum = enum_of(old_node), enum_of(new_node)
            if old_enum is not None and new_enum is None:
                found.append(Difference(WARN, source.id, f"field {field} no longer lists its allowed values, so any value may now arrive"))
            elif old_enum is not None and new_enum is not None and new_enum - old_enum:
                values = ", ".join(sorted(str(v) for v in new_enum - old_enum))
                found.append(Difference(WARN, source.id, f"field {field} has new values the collector does not know: {values}"))

    verdict = ERROR if any(d.level == ERROR for d in found) else WARN if found else PASS
    return SelfTestResult(verdict=verdict, differences=tuple(found), not_read=tuple(not_read))
