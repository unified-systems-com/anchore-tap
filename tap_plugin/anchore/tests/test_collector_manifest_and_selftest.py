"""The collector manifest and the per-run self-test (req-anchore-selftest, req-anchore-scope-walk-3).

Offline and Django-free: the committed extract is the baseline and each test changes a copy the
way an instance that differs from it would. Spec-derived, not observed on a real instance.
"""

import copy
import json
from pathlib import Path

import pytest

from tap_plugin.anchore.collectors.anchore_collector.manifest import ManifestError, load_manifest, shipped_manifest
from tap_plugin.anchore.collectors.anchore_collector.paths import resolve_field
from tap_plugin.anchore.collectors.anchore_collector.selftest import ERROR, PASS, WARN, compare

CONTRACT = Path(__file__).resolve().parents[1] / "contract"
EXTRACT = json.loads((CONTRACT / "extract.json").read_text(encoding="utf-8"))
CONSUMED_PATHS = {op["path"] for op in json.loads((CONTRACT / "consumed.json").read_text(encoding="utf-8"))["operations"]}
SOURCES = shipped_manifest()
VULN = "/images/{image_digest}/vuln/{vuln_type}"


def _fresh() -> dict:
    return copy.deepcopy(EXTRACT)


def _op(extract: dict, path: str) -> dict:
    return next(o for o in extract["operations"] if o["path"] == path and o["method"] == "get")


def _vuln_item(extract: dict) -> dict:
    schema = _op(extract, VULN)["responses"][0]["schema"]
    item = schema["properties"]["vulnerabilities"]["items"]
    return item


def _vuln_props(extract: dict) -> dict:
    members = _vuln_item(extract).get("allOf") or [_vuln_item(extract)]
    return next(m["properties"] for m in members if "properties" in m and "vuln" in m["properties"])


class TestManifest:
    def test_every_path_is_one_the_collector_may_call(self):
        assert {s.path for s in SOURCES} <= CONSUMED_PATHS

    def test_every_listed_field_is_in_the_extract(self):
        for source in SOURCES:
            op = _op(EXTRACT, source.path)
            schema = next(r["schema"] for r in op["responses"] if str(r["status"]).startswith("2"))
            for field in (*source.required_fields, *source.optional_fields):
                assert resolve_field(schema, field) is not None, (source.id, field)

    def test_the_probe_reads_come_first_and_account_is_required(self):
        assert [s.id for s in SOURCES][:4] == ["account", "status", "system", "feeds"]
        assert next(s for s in SOURCES if s.id == "account").required is True

    def test_a_path_the_extract_lacks_is_refused(self):
        bad = {"description": "x", "sources": [{"id": "ghost", "path": "/nowhere", "scope": "probe", "required": False, "required_fields": [], "optional_fields": []}]}
        with pytest.raises(ManifestError, match="no 2xx response"):
            load_manifest(bad)

    def test_a_field_the_extract_lacks_is_refused(self):
        bad = {"description": "x", "sources": [{"id": "account", "path": "/account", "scope": "probe", "required": True, "required_fields": ["no_such_field"], "optional_fields": []}]}
        with pytest.raises(ManifestError, match="no_such_field"):
            load_manifest(bad)

    def test_a_manifest_that_breaks_its_schema_is_refused(self):
        with pytest.raises(ManifestError, match="schema"):
            load_manifest({"description": "x", "sources": [{"id": "Bad Id", "path": "/account"}]})

    def test_a_repeated_id_is_refused(self):
        entry = {"id": "account", "path": "/account", "scope": "probe", "required": True, "required_fields": ["name"], "optional_fields": []}
        with pytest.raises(ManifestError, match="twice"):
            load_manifest({"description": "x", "sources": [entry, entry]})


class TestSelfTest:
    def test_an_identical_description_passes(self):
        result = compare(EXTRACT, _fresh(), SOURCES)
        assert result.verdict == PASS and result.differences == () and result.not_read == ()

    def test_an_additive_change_the_collector_does_not_read_passes(self):
        fresh = _fresh()
        _vuln_props(fresh)["a_brand_new_field"] = {"type": "string"}
        _op(fresh, "/account")["responses"][0]["schema"]["properties"]["another"] = {"type": "string"}
        assert compare(EXTRACT, fresh, SOURCES).verdict == PASS

    def test_a_required_source_gone_is_an_error(self):
        fresh = _fresh()
        fresh["operations"] = [o for o in fresh["operations"] if o["path"] != VULN]
        result = compare(EXTRACT, fresh, SOURCES)
        assert result.verdict == ERROR
        assert any(d.source_id == "image_vulnerabilities" and d.level == ERROR for d in result.differences)

    def test_an_optional_source_gone_is_a_warning_and_is_listed_as_not_read(self):
        fresh = _fresh()
        fresh["operations"] = [o for o in fresh["operations"] if o["path"] != "/system/feeds"]
        result = compare(EXTRACT, fresh, SOURCES)
        assert result.verdict == WARN and result.not_read == ("feeds",)

    def test_a_required_field_removed_is_an_error(self):
        fresh = _fresh()
        del _vuln_props(fresh)["vuln"]
        result = compare(EXTRACT, fresh, SOURCES)
        assert result.verdict == ERROR
        assert any("vulnerabilities[].vuln is gone" in d.message for d in result.differences)

    def test_a_required_field_changing_type_is_an_error(self):
        fresh = _fresh()
        _vuln_props(fresh)["vuln"] = {"type": "integer"}
        result = compare(EXTRACT, fresh, SOURCES)
        assert result.verdict == ERROR
        assert any("changed type from string to integer" in d.message for d in result.differences)

    def test_an_optional_field_removed_is_a_warning(self):
        fresh = _fresh()
        del _vuln_props(fresh)["severity"]
        result = compare(EXTRACT, fresh, SOURCES)
        assert result.verdict == WARN and result.not_read == ()
        assert any("vulnerabilities[].severity is gone" in d.message for d in result.differences)

    def test_a_new_required_parameter_is_an_error(self):
        fresh = _fresh()
        _op(fresh, "/images")["parameters"].append({"name": "tenant", "in": "query", "required": True})
        result = compare(EXTRACT, fresh, SOURCES)
        assert result.verdict == ERROR
        assert any("now requires tenant (query)" in d.message for d in result.differences)

    def test_a_new_optional_parameter_passes(self):
        fresh = _fresh()
        _op(fresh, "/images")["parameters"].append({"name": "page_hint", "in": "query", "required": False})
        assert compare(EXTRACT, fresh, SOURCES).verdict == PASS

    def test_a_new_enum_value_on_a_field_the_collector_reads_is_a_warning(self):
        fresh = _fresh()
        item = _op(fresh, "/images")["responses"][0]["schema"]["properties"]["items"]["items"]
        item["properties"]["analysis_status"]["enum"].append("quarantined")
        result = compare(EXTRACT, fresh, SOURCES)
        assert result.verdict == WARN
        assert any("quarantined" in d.message for d in result.differences)

    def test_a_removed_enum_on_a_field_the_collector_reads_is_a_warning(self):
        fresh = _fresh()
        item = _op(fresh, "/images")["responses"][0]["schema"]["properties"]["items"]["items"]
        del item["properties"]["analysis_status"]["enum"]
        result = compare(EXTRACT, fresh, SOURCES)
        assert result.verdict == WARN
        assert any("no longer lists its allowed values" in d.message for d in result.differences)

    def test_a_container_on_the_way_becoming_nullable_is_an_error(self):
        """A reader of items[].image_digest breaks when items may now be null, though the leaf is unchanged."""
        fresh = _fresh()
        _op(fresh, "/images")["responses"][0]["schema"]["properties"]["items"]["type"] = ["array", "null"]
        result = compare(EXTRACT, fresh, SOURCES)
        assert result.verdict == ERROR
        assert any("a container on the way" in d.message for d in result.differences)

    def test_a_second_successful_response_is_held_to_the_same_fields(self):
        fresh = _fresh()
        response = _op(fresh, "/images")["responses"][0]
        broken = copy.deepcopy(response["schema"])
        del broken["properties"]["items"]["items"]["properties"]["image_digest"]
        _op(fresh, "/images")["responses"].append({**response, "status": "206", "schema": broken})
        result = compare(EXTRACT, fresh, SOURCES)
        assert result.verdict == ERROR
        assert any("items[].image_digest is gone from GET /images (206)" in d.message for d in result.differences)

    def test_a_changed_second_successful_response_is_not_hidden_behind_an_unchanged_first(self):
        fresh = _fresh()
        response = _op(fresh, "/images")["responses"][0]
        changed = copy.deepcopy(response["schema"])
        changed["properties"]["items"]["items"]["properties"]["analysis_status"]["type"] = "integer"
        _op(fresh, "/images")["responses"].append({**response, "status": "203", "schema": changed})
        assert compare(EXTRACT, fresh, SOURCES).verdict == ERROR

    def test_a_different_version_is_a_warning(self):
        fresh = _fresh()
        fresh["source"] = {**fresh["source"], "version": "9.9.9"}
        result = compare(EXTRACT, fresh, SOURCES)
        assert result.verdict == WARN
        assert any("9.9.9" in d.message for d in result.differences)

    def test_an_error_outranks_a_warning(self):
        fresh = _fresh()
        fresh["source"] = {**fresh["source"], "version": "9.9.9"}
        del _vuln_props(fresh)["vuln"]
        assert compare(EXTRACT, fresh, SOURCES).verdict == ERROR

    def test_the_detail_is_json_the_scan_run_can_keep(self):
        fresh = _fresh()
        fresh["operations"] = [o for o in fresh["operations"] if o["path"] != "/system"]
        detail = compare(EXTRACT, fresh, SOURCES).as_detail()
        assert json.loads(json.dumps(detail)) == detail
        assert detail["not_read"] == ["system"]
