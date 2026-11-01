"""The contract extract, its reducer and the drift comparison (req-anchore-contract-extract,
req-anchore-drift-ci). Pure Python: no database, no network.
"""

import copy
import hashlib
import io
import json
import socket
from pathlib import Path

import jsonschema
import pytest

from tap_plugin.anchore.contract import build, diff, drift, reduce

CONTRACT = Path(build.__file__).resolve().parent
VENDOR = Path(__file__).resolve().parent / "vendor"

# Endpoints ruled out of v0 (secret-bearing, credential, admin or bulk-file). No consumed
# operation may start with, or contain, any of these.
EXCLUDED = (
    "/artifacts/",
    "/content/files",
    "/downloads",
    "/jobs",
    "/accounts",
    "/user",
    "/my-user-groups",
    "/rbac-manager",
    "/registries",
    "/notifications",
    "/events",
    "/alerts",
    "/stig",
    "/query/",
    "/imports",
    "/archives",
    "/reporting",
    "/subscriptions",
    "/actions",
    "/corrections",
)


@pytest.fixture(autouse=True)
def no_sockets(monkeypatch):
    """req-anchore-contract-extract-2: nothing in this module opens a connection."""

    def refuse(*args, **kwargs):
        raise AssertionError("the contract tests must not open a socket")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def _json(name):
    return json.loads((CONTRACT / name).read_text(encoding="utf-8"))


def _source():
    return reduce.load_document((VENDOR / "openapi-2.20.0.json").read_bytes())


class TestGenerated:
    def test_extract_is_what_the_reducer_produces(self):
        """req-anchore-contract-extract-1."""
        assert (CONTRACT / "extract.json").read_text(encoding="utf-8") == build.build()

    def test_every_consumed_operation_is_present_in_the_source(self):
        extract = _json("extract.json")
        missing = [o["path"] for o in extract["operations"] if not o["present"]]
        assert missing == []

    def test_finding_fields_reach_the_extract(self):
        extract = _json("extract.json")
        op = next(o for o in extract["operations"] if o["path"] == "/images/{image_digest}/vuln/{vuln_type}")
        members = op["responses"][0]["schema"]["properties"]["vulnerabilities"]["items"]["allOf"]
        fields = {name for member in members for name in member.get("properties", {})}
        assert {"severity", "fix", "suggested_fix_version", "fix_observed_at", "will_not_fix", "is_kev", "epss", "nvd_data", "vendor_data"} <= fields


class TestDescribed:
    def test_extract_matches_its_schema(self):
        """req-anchore-contract-extract-3."""
        jsonschema.validate(_json("extract.json"), _json("extract.schema.json"))

    def test_consumed_list_is_described(self):
        consumed = _json("consumed.json")
        assert consumed["description"]
        assert all(entry["description"] for entry in consumed["operations"])


class TestConsumedSet:
    def test_only_get_operations(self):
        """req-anchore-nongoals-1: the plugin never consumes a write operation."""
        assert {e["method"] for e in _json("consumed.json")["operations"]} == {"get"}

    def test_no_excluded_endpoint(self):
        """req-anchore-nongoals-2."""
        bad = [e["path"] for e in _json("consumed.json")["operations"] if any(x in e["path"] for x in EXCLUDED)]
        assert bad == []

    def test_no_duplicates(self):
        keys = [(e["method"], e["path"]) for e in _json("consumed.json")["operations"]]
        assert len(keys) == len(set(keys))


class TestReducerIsBounded:
    """req-anchore-contract-extract-4."""

    CONSUMED = {"operations": [{"description": "t", "method": "get", "path": "/x"}]}

    def _doc(self, schema):
        return {
            "openapi": "3.0.1",
            "info": {"title": "t", "version": "1"},
            "paths": {"/x": {"get": {"responses": {"200": {"content": {"application/json": {"schema": schema}}}}}}},
            "components": {"schemas": {}},
        }

    @pytest.mark.parametrize("ref", ["https://evil.example/s.json#/A", "file:///etc/passwd", "other.json#/A", "/etc/passwd"])
    def test_remote_or_file_reference_is_rejected(self, ref):
        with pytest.raises(reduce.ReducerError):
            reduce.reduce_document(self._doc({"$ref": ref}), self.CONSUMED)

    def test_cycle_becomes_a_marker(self):
        doc = self._doc({"$ref": "#/components/schemas/Node"})
        doc["components"]["schemas"]["Node"] = {"type": "object", "properties": {"next": {"$ref": "#/components/schemas/Node"}}}
        extract = reduce.reduce_document(doc, self.CONSUMED)
        schema = extract["operations"][0]["responses"][0]["schema"]
        assert schema["properties"]["next"] == {"$recursive": "#/components/schemas/Node"}

    def test_oversized_document_is_refused(self):
        with pytest.raises(reduce.ReducerError):
            reduce.load_document(b" " * (reduce.MAX_DOCUMENT_BYTES + 1))

    def test_deeply_nested_document_is_refused(self):
        raw = ("[" * 500 + "]" * 500).encode()
        with pytest.raises(reduce.ReducerError):
            reduce.load_document(b'{"a":' + raw + b"}")

    def test_expansion_past_the_node_budget_is_refused(self, monkeypatch):
        monkeypatch.setattr(reduce, "MAX_NODES", 50)
        doc = self._doc({"type": "object", "properties": {f"p{i}": {"type": "string"} for i in range(200)}})
        with pytest.raises(reduce.ReducerError):
            reduce.reduce_document(doc, self.CONSUMED)

    def test_reducer_does_no_io(self, monkeypatch):
        def refuse(*a, **k):
            raise AssertionError("the reducer opened a file")

        monkeypatch.setattr("builtins.open", refuse)
        reduce.reduce_document(self._doc({"type": "string"}), self.CONSUMED)


class TestDrift:
    def _args(self):
        return _json("consumed.json"), _json("extract.json"), _source()

    def test_identical_upstream_is_clean(self):
        """req-anchore-drift-ci-1, the quiet case."""
        consumed, committed, baseline = self._args()
        assert drift.compare(copy.deepcopy(baseline), consumed, committed, baseline) == ([], [])

    def test_changed_consumed_field_fails(self):
        consumed, committed, baseline = self._args()
        fresh = copy.deepcopy(baseline)
        item = fresh["paths"]["/images/{image_digest}/vuln/{vuln_type}"]["get"]
        item["parameters"] = [p for p in item.get("parameters", []) if p.get("name") != "vendor_only"] or item.get("parameters", [])
        schemas = fresh["components"]["schemas"]
        target = next(n for n, s in schemas.items() if "suggested_fix_version" in s.get("properties", {}))
        schemas[target]["properties"]["suggested_fix_version"] = {"type": "integer"}
        found, _ = drift.compare(fresh, consumed, committed, baseline)
        assert any("suggested_fix_version" in line for line in found)

    def test_removed_consumed_path_fails(self):
        consumed, committed, baseline = self._args()
        fresh = copy.deepcopy(baseline)
        del fresh["paths"]["/status"]
        found, _ = drift.compare(fresh, consumed, committed, baseline)
        assert any(line.startswith("GET /status") for line in found)

    def test_change_outside_the_extract_is_listed_not_failed(self):
        """req-anchore-drift-ci-2."""
        consumed, committed, baseline = self._args()
        fresh = copy.deepcopy(baseline)
        fresh["paths"]["/brand-new"] = {"get": {"responses": {"200": {"description": "ok"}}}}
        fresh["info"]["version"] = "9.9.9"
        found, other = drift.compare(fresh, consumed, committed, baseline)
        assert found == []
        assert any("/brand-new" in line for line in other) and any("9.9.9" in line for line in other)

    def test_documentation_only_change_is_not_drift(self):
        consumed, committed, baseline = self._args()
        fresh = copy.deepcopy(baseline)
        fresh["paths"]["/status"]["get"]["summary"] = "A reworded sentence"
        fresh["paths"]["/status"]["get"]["description"] = "Another"
        assert drift.compare(fresh, consumed, committed, baseline)[0] == []

    def test_summary_lists_both_kinds(self):
        text = drift.render_summary(["GET /x: changed"], ["GET /y: added upstream"])
        assert "fails the run" in text and "does not fail" in text

    def test_diff_is_bounded(self):
        a = {"operations": [{"method": "get", "path": "/p", "x": list(range(1000))}]}
        b = {"operations": [{"method": "get", "path": "/p", "x": [i + 1 for i in range(1000)]}]}
        assert len(diff.diff_extracts(a, b)) <= diff.MAX_REPORTED


class TestDriftCommand:
    """The command reads standard input and writes standard output; it takes no path."""

    def _run(self, doc_bytes):
        out = io.StringIO()
        code = drift.main(stdin=io.BytesIO(doc_bytes), stdout=out)
        return code, out.getvalue()

    def test_unchanged_upstream_exits_zero(self):
        code, text = self._run((VENDOR / "openapi-2.20.0.json").read_bytes())
        assert code == 0 and "Nothing the plugin consumes has changed" in text

    def test_drifted_upstream_exits_one_and_names_the_field(self):
        doc = _source()
        schemas = doc["components"]["schemas"]
        target = next(n for n, s in schemas.items() if "suggested_fix_version" in s.get("properties", {}))
        schemas[target]["properties"]["suggested_fix_version"] = {"type": "integer"}
        code, text = self._run(json.dumps(doc).encode())
        assert code == 1 and "suggested_fix_version" in text

    def test_unreadable_input_exits_two(self):
        code, text = self._run(b'{"a":')
        assert code == 2 and text == ""

    def test_command_accepts_no_path_argument(self):
        import inspect

        assert set(inspect.signature(drift.main).parameters) == {"stdin", "stdout"}


class TestOutsideTheExtract:
    def test_modified_unconsumed_operation_is_listed(self):
        """req-anchore-drift-ci-2: a change to an operation the plugin does not read is reported."""
        consumed = {(e["method"], e["path"]) for e in _json("consumed.json")["operations"]}
        baseline = _source()
        fresh = copy.deepcopy(baseline)
        path = next(p for p, item in fresh["paths"].items() if "get" in item and ("get", p) not in consumed)
        fresh["paths"][path]["get"].setdefault("parameters", []).append({"name": "zz", "in": "query", "schema": {"type": "string"}})
        other = diff.other_changes(baseline, fresh, consumed)
        assert f"GET {path}: changed outside the extract" in other

    def test_reworded_unconsumed_operation_is_not_listed(self):
        consumed = {(e["method"], e["path"]) for e in _json("consumed.json")["operations"]}
        baseline = _source()
        fresh = copy.deepcopy(baseline)
        path = next(p for p, item in fresh["paths"].items() if "get" in item and ("get", p) not in consumed)
        fresh["paths"][path]["get"]["summary"] = "A reworded sentence"
        assert diff.other_changes(baseline, fresh, consumed) == []

    def test_reporting_cap_holds_for_added_keys(self):
        out: list[str] = []
        diff._walk({}, {str(i): i for i in range(1000)}, "x", out)
        assert len(out) <= diff.MAX_REPORTED


class TestProvenance:
    def test_committed_copy_matches_its_recorded_hash(self):
        provenance = json.loads((VENDOR / "provenance.json").read_text(encoding="utf-8"))
        digest = hashlib.sha256((VENDOR / "openapi-2.20.0.json").read_bytes()).hexdigest()
        assert digest == provenance["json_sha256"]
        assert provenance["description"] and provenance["source_url"].startswith("https://")


class TestReviewFixes:
    CONSUMED = {
        "operations": [
            {"description": "t", "method": "get", "path": f"/x{i}"} for i in range(6)
        ]
    }

    def _shared_doc(self):
        schema = {"type": "object", "properties": {f"p{i}": {"type": "string"} for i in range(8)}}
        paths = {
            f"/x{i}": {"get": {"responses": {"200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Big"}}}}}}}
            for i in range(6)
        }
        return {"openapi": "3.0.1", "info": {"title": "t", "version": "1"}, "paths": paths, "components": {"schemas": {"Big": schema}}}

    def test_shared_schema_is_charged_each_time_it_is_used(self, monkeypatch):
        """A schema named by many operations expands in the output once per use, so the node budget counts every use."""
        doc = self._shared_doc()
        monkeypatch.setattr(reduce, "MAX_NODES", 55)
        with pytest.raises(reduce.ReducerError):
            reduce.reduce_document(doc, self.CONSUMED)
        monkeypatch.setattr(reduce, "MAX_NODES", 10_000)
        reduce.reduce_document(doc, self.CONSUMED)

    def test_parameter_default_change_is_drift(self):
        consumed, committed, baseline = _json("consumed.json"), _json("extract.json"), _source()
        fresh = copy.deepcopy(baseline)
        params = fresh["paths"]["/images/{image_digest}/vuln/{vuln_type}"]["get"]["parameters"]
        target = next(p for p in params if p.get("name") == "vendor_only")
        assert target["schema"].get("default") is not None
        target["schema"]["default"] = not target["schema"]["default"]
        found, _ = drift.compare(fresh, consumed, committed, baseline)
        assert any("vendor_only" in line or "default" in line for line in found)

    def test_files_content_type_is_never_requested(self):
        """The generic content routes allow a files value the plugin must never send; the extract says so."""
        extract = _json("extract.json")
        generic = [o for o in extract["operations"] if o["path"].endswith("/content/{content_type}")]
        assert len(generic) == 2
        for op in generic:
            assert op["never_request"] == [{"parameter": "content_type", "values": ["files"]}]

    def test_summary_text_from_upstream_cannot_forge_markdown(self):
        text = drift.render_summary([], ["version: x`\n## Forged status"])
        assert "\n## Forged" not in text and "`## " not in text
        assert text.count("`") % 2 == 0

    def test_large_kept_values_are_charged_by_what_they_hold(self, monkeypatch):
        """A big enum named by several operations costs its length each time, not one node."""
        doc = self._shared_doc()
        doc["components"]["schemas"]["Big"] = {"enum": list(range(1000))}
        monkeypatch.setattr(reduce, "MAX_NODES", 3000)
        with pytest.raises(reduce.ReducerError):
            reduce.reduce_document(doc, self.CONSUMED)
        monkeypatch.setattr(reduce, "MAX_NODES", 100_000)
        reduce.reduce_document(doc, self.CONSUMED)
