"""Regenerate (or check) the committed extract from the committed source copy.

    python -m tap_plugin.anchore.contract.build           # rewrite extract.json
    python -m tap_plugin.anchore.contract.build --check   # exit 1 when extract.json is stale

Reads only the three committed files beside this module (req-anchore-contract-extract-1).
"""

import argparse
import json
import sys
from pathlib import Path

from tap_plugin.anchore.contract.reduce import load_document, reduce_document

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "openapi-2.20.0.json"
CONSUMED = HERE / "consumed.json"
EXTRACT = HERE / "extract.json"


def render(extract: dict) -> str:
    return json.dumps(extract, indent=1, sort_keys=False, ensure_ascii=False) + "\n"


def build() -> str:
    doc = load_document(SOURCE.read_bytes())
    consumed = json.loads(CONSUMED.read_text(encoding="utf-8"))
    return render(reduce_document(doc, consumed))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when extract.json is not what the reducer produces")
    args = parser.parse_args(argv)
    fresh = build()
    if args.check:
        if EXTRACT.read_text(encoding="utf-8") != fresh:
            print("extract.json is stale: run python -m tap_plugin.anchore.contract.build", file=sys.stderr)
            return 1
        return 0
    EXTRACT.write_text(fresh, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
