"""Compare Anchore's published OpenAPI file with the committed extract (req-anchore-drift-ci).

    python -m tap_plugin.anchore.contract.drift --fresh upstream.json [--summary FILE]

``upstream.json`` is the vendor's file already converted to JSON. Exit 1 when anything the
plugin consumes changed; other changes are listed and do not fail. No network, no credential.
"""

import argparse
import json
import sys
from pathlib import Path

from tap_plugin.anchore.contract.build import CONSUMED, EXTRACT, SOURCE
from tap_plugin.anchore.contract.diff import diff_extracts, other_changes
from tap_plugin.anchore.contract.reduce import ReducerError, load_document, reduce_document


def compare(fresh_doc: dict, consumed: dict, committed_extract: dict, baseline_doc: dict) -> tuple[list[str], list[str]]:
    """Return (consumed differences, other changes)."""
    fresh_extract = reduce_document(fresh_doc, consumed)
    drift = diff_extracts(committed_extract, fresh_extract)
    consumed_keys = {(e["method"], e["path"]) for e in consumed["operations"]}
    return drift, other_changes(baseline_doc, fresh_doc, consumed_keys)


def render_summary(drift: list[str], other: list[str]) -> str:
    lines = ["## Anchore API drift", ""]
    if drift:
        lines += ["### Changed in what the plugin consumes (this fails the run)", ""]
        lines += [f"- `{d}`" for d in drift]
    else:
        lines += ["Nothing the plugin consumes has changed.", ""]
    if other:
        lines += ["", "### Changed outside what the plugin consumes (listed, does not fail)", ""]
        lines += [f"- `{o}`" for o in other]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fresh", required=True, type=Path, help="the vendor's file, converted to JSON")
    parser.add_argument("--summary", type=Path, help="append a markdown summary to this file")
    args = parser.parse_args(argv)
    try:
        fresh_doc = load_document(args.fresh.read_bytes())
        baseline_doc = load_document(SOURCE.read_bytes())
        consumed = json.loads(CONSUMED.read_text(encoding="utf-8"))
        committed = json.loads(EXTRACT.read_text(encoding="utf-8"))
        drift, other = compare(fresh_doc, consumed, committed, baseline_doc)
    except ReducerError as exc:
        print(f"cannot read the upstream file: {exc}", file=sys.stderr)
        return 2
    summary = render_summary(drift, other)
    print(summary)
    if args.summary:
        with args.summary.open("a", encoding="utf-8") as handle:
            handle.write(summary)
    return 1 if drift else 0


if __name__ == "__main__":
    raise SystemExit(main())
