"""The self-test run against an instance's own description, and the per-response check
(req-anchore-selftest-1 to -6). No socket is opened; every description and body is canned,
the description being Anchore's published 2.20.0 file as vendored for the contract tests.
"""

import copy
import json
import socket
from pathlib import Path

import pytest
import requests

from tap_plugin.anchore import client as cl
from tap_plugin.anchore import credential as cred
from tap_plugin.anchore.collectors.anchore_collector.gate import SPEC_PATH, fetch_instance_extract, previous_spec_served, run_selftest
from tap_plugin.anchore.collectors.anchore_collector.manifest import shipped_manifest
from tap_plugin.anchore.collectors.anchore_collector.selftest import ERROR, PASS, WARN
from tap_plugin.anchore.collectors.anchore_collector.validate import validate_body
from tap_plugin.anchore.tests.fakes import FakeTransport, response
from tap_plugin.anchore.tests.test_anchore_credential import envelope

CONTRACT = Path(__file__).resolve().parents[1] / "contract"
VENDOR = Path(__file__).resolve().parent / "vendor" / "openapi-2.20.0.json"
EXTRACT = json.loads((CONTRACT / "extract.json").read_text(encoding="utf-8"))
SOURCES = {s.id: s for s in shipped_manifest()}
VULN_PATH = "/images/{image_digest}/vuln/{vuln_type}"


@pytest.fixture(autouse=True)
def no_sockets(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("these tests must not open a socket")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture(scope="module")
def spec() -> dict:
    return json.loads(VENDOR.read_text(encoding="utf-8"))


def client_for(spec_response) -> tuple[cl.ReadOnlyClient, FakeTransport]:
    transport = FakeTransport({SPEC_PATH: spec_response})
    credential = cred.credential_from_envelope(envelope())
    return cl.ReadOnlyClient(credential, transport=transport, sleep=lambda s: None), transport


def serving(doc: dict):
    return response(200, json.dumps(doc).encode())


class TestTheDescriptionIsFetchedAndCompared:
    def test_the_published_file_passes_against_the_extract_built_from_it(self, spec):
        client, transport = client_for(serving(spec))
        result = run_selftest(client, previous_spec_served=None)
        assert result.verdict == PASS and result.ran and result.spec_served
        assert [str(c.url).split("/v2")[-1] for c in transport.calls] == [SPEC_PATH]
        assert {c.method for c in transport.calls} == {"GET"}

    def test_a_dropped_required_operation_is_an_error_that_stops_the_run(self, spec):
        doc = copy.deepcopy(spec)
        del doc["paths"][VULN_PATH]
        result = run_selftest(client_for(serving(doc))[0], previous_spec_served=True)
        assert result.verdict == ERROR and result.stops_the_run
        assert any("is not offered by the instance" in d["message"] for d in result.detail["differences"]), "the reducer marks it present: false, which must read as not offered"

    def test_a_dropped_optional_operation_is_a_warning_and_the_source_is_listed_as_not_read(self, spec):
        doc = copy.deepcopy(spec)
        del doc["paths"]["/system/feeds"]
        result = run_selftest(client_for(serving(doc))[0], previous_spec_served=True)
        assert result.verdict == WARN and not result.stops_the_run
        assert result.not_read == ("feeds",)
        fields = result.scan_run_fields()
        assert fields["scopes_not_read"] == [{"scope": "source:feeds", "reason": "not offered by the instance"}]
        assert fields["selftest_verdict"] == "warn"

    def test_a_different_version_is_a_warning(self, spec):
        doc = copy.deepcopy(spec)
        doc["info"]["version"] = "9.9.9"
        result = run_selftest(client_for(serving(doc))[0], previous_spec_served=None)
        assert result.verdict == WARN and result.detail["instance_version"] == "9.9.9"

    def test_the_detail_is_json_and_records_that_it_ran(self, spec):
        result = run_selftest(client_for(serving(spec))[0], previous_spec_served=None)
        assert json.loads(json.dumps(result.detail)) == result.detail
        assert result.detail["ran"] is True and result.detail["spec_served"] is True


class TestADescriptionThatIsNotServed:
    @pytest.mark.parametrize("answer", [response(404, {}), response(403, {}), response(200, b"<html>not json"), response(500, {})])
    def test_with_no_previous_record_it_warns_and_is_never_a_pass(self, answer):
        result = run_selftest(client_for(answer)[0], previous_spec_served=None)
        assert result.verdict == WARN and not result.ran and not result.spec_served
        assert not result.stops_the_run

    @pytest.mark.parametrize("previous", [None, False])
    def test_a_scanner_that_never_served_it_continues_with_a_warning(self, previous):
        assert run_selftest(client_for(response(404, {}))[0], previous_spec_served=previous).verdict == WARN

    def test_a_scanner_that_served_it_before_stops_when_it_stops_answering(self):
        result = run_selftest(client_for(response(404, {}))[0], previous_spec_served=True)
        assert result.verdict == ERROR and result.stops_the_run
        assert "not a gate" in result.detail["differences"][0]["message"]

    def test_a_transport_error_is_not_served_not_an_exception(self):
        fetched = fetch_instance_extract(client_for(requests.ConnectionError("reset"))[0])
        assert not fetched.served and fetched.reason

    def test_a_description_the_reducer_refuses_is_not_served(self):
        fetched = fetch_instance_extract(client_for(response(200, b"[1, 2, 3]"))[0])
        assert not fetched.served and fetched.reason == "the description was served but could not be read"

    def test_the_messages_carry_no_response_text(self):
        result = run_selftest(client_for(response(200, b"SECRET-TOKEN-in-a-bad-body"))[0], previous_spec_served=None)
        assert "SECRET-TOKEN" not in json.dumps(result.detail)


class TestThePreviousRunsFact:
    def test_it_is_read_from_the_recorded_detail(self):
        assert previous_spec_served({"spec_served": True}) is True
        assert previous_spec_served({"spec_served": False}) is False

    @pytest.mark.parametrize("detail", [None, {}, {"spec_served": "yes"}, "x", []])
    def test_anything_else_is_unknown_not_false(self, detail):
        assert previous_spec_served(detail) is None


class TestResponsesAreValidatedAgainstTheCommittedShapes:
    def test_a_conforming_account_body_passes(self):
        assert validate_body(EXTRACT, SOURCES["account"], 200, {"name": "acct", "type": "user", "state": "enabled"}).ok

    def test_a_missing_required_field_is_refused_naming_the_rule_and_not_the_value(self):
        outcome = validate_body(EXTRACT, SOURCES["account"], 200, {"email": "someone@example.org"})
        assert not outcome.ok and "required" in (outcome.reason or "")
        assert "someone@example.org" not in (outcome.reason or "")

    def test_a_wrong_type_is_refused_with_its_path(self):
        outcome = validate_body(EXTRACT, SOURCES["images"], 200, {"items": "not a list"})
        assert not outcome.ok and "/items" in (outcome.reason or "") and "type" in (outcome.reason or "")

    def test_a_nullable_field_may_be_null(self):
        item = {"image_digest": "sha256:" + "ab" * 32, "analysis_status": "analyzed", "analysis_status_detail": None}
        assert validate_body(EXTRACT, SOURCES["images"], 200, {"items": [item]}).ok

    def test_a_value_outside_an_enum_is_refused(self):
        item = {"image_digest": "sha256:" + "ab" * 32, "analysis_status": "quarantined"}
        outcome = validate_body(EXTRACT, SOURCES["images"], 200, {"items": [item]})
        assert not outcome.ok and "enum" in (outcome.reason or "")

    def test_a_status_the_extract_has_no_schema_for_is_refused(self):
        outcome = validate_body(EXTRACT, SOURCES["account"], 204, {})
        assert not outcome.ok and "HTTP 204" in (outcome.reason or "")

    def test_an_operation_marked_absent_has_no_schema(self):
        gone = copy.deepcopy(EXTRACT)
        next(o for o in gone["operations"] if o["path"] == "/account")["present"] = False
        assert not validate_body(gone, SOURCES["account"], 200, {"name": "x"}).ok

    def test_an_empty_vulnerability_list_is_a_valid_observation_of_none(self):
        assert validate_body(EXTRACT, SOURCES["image_vulnerabilities"], 200, {"image_digest": "sha256:" + "ab" * 32, "vulnerabilities": []}).ok
