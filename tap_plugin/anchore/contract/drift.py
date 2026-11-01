"""Compare Anchore's published OpenAPI file with the committed extract (req-anchore-drift-ci).

    python -m tap_plugin.anchore.contract.drift < upstream.json | tee -a "$GITHUB_STEP_SUMMARY"

Standard input is the vendor's file already converted to JSON; the markdown summary goes to
standard output. No path comes from an argument. Exit 1 when anything the plugin consumes
changed; other changes are listed and do not fail. Exit 2 when the input cannot be read. No
network, no credential.
"""

import json
import sys

from tap_plugin.anchore.contract.build import CONSUMED, EXTRACT, SOURCE
from tap_plugin.anchore.contract.diff import diff_extracts, other_changes
from tap_plugin.anchore.contract.reduce import MAX_DOCUMENT_BYTES, ReducerError, load_document, reduce_document


def compare(fresh_doc: dict, consumed: dict, committed_extract: dict, baseline_doc: dict) -> tuple[list[str], list[str]]:
    """Return (consumed differences, other changes)."""
    fresh_extract = reduce_document(fresh_doc, consumed)
    drift = diff_extracts(committed_extract, fresh_extract)
    consumed_keys = {(e["method"], e["path"]) for e in consumed["operations"]}
    return drift, other_changes(baseline_doc, fresh_doc, consumed_keys)


def _clean(text: str) -> str:
    """Make a string from the upstream file safe to print inside a markdown code span."""
    kept = "".join(ch if ch.isprintable() and ch != "`" else " " for ch in str(text))
    return kept[:300]


def render_summary(drift: list[str], other: list[str]) -> str:
    lines = ["## Anchore API drift", ""]
    if drift:
        lines += ["### Changed in what the plugin consumes (this fails the run)", ""]
        lines += [f"- `{_clean(d)}`" for d in drift]
    else:
        lines += ["Nothing the plugin consumes has changed.", ""]
    if other:
        lines += ["", "### Changed outside what the plugin consumes (listed, does not fail)", ""]
        lines += [f"- `{_clean(o)}`" for o in other]
    return "\n".join(lines) + "\n"


def main(stdin=None, stdout=None) -> int:
    stdin = stdin if stdin is not None else sys.stdin.buffer
    stdout = stdout if stdout is not None else sys.stdout
    try:
        fresh_doc = load_document(stdin.read(MAX_DOCUMENT_BYTES + 1))
        baseline_doc = load_document(SOURCE.read_bytes())
        consumed = json.loads(CONSUMED.read_text(encoding="utf-8"))
        committed = json.loads(EXTRACT.read_text(encoding="utf-8"))
        drift, other = compare(fresh_doc, consumed, committed, baseline_doc)
    except ReducerError as exc:
        print(f"cannot read the upstream file: {exc}", file=sys.stderr)
        return 2
    stdout.write(render_summary(drift, other))
    return 1 if drift else 0


if __name__ == "__main__":
    raise SystemExit(main())
