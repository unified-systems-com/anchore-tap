"""The observation command (the trial session instrument). No socket is opened and nothing is written to a repository."""

import base64
import io
import json
import re
import socket
import stat
from pathlib import Path

import pytest

from tap_plugin.anchore import credential as cred
from tap_plugin.anchore import observe
from tap_plugin.anchore.contract.build import CONSUMED
import requests

from tap_plugin.anchore.tests.fakes import DIGEST, FakeTransport, anchore_routes, response
from tap_plugin.anchore.tests.test_anchore_credential import SECRET, data, envelope, write


@pytest.fixture(autouse=True)
def no_sockets(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("the observation tests must not open a socket")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


def credential(scheme="basic"):
    return cred.credential_from_envelope(envelope(scheme=scheme))


def observe_run(tmp_path, scheme="basic", routes=None, **kw):
    transport = FakeTransport(routes if routes is not None else anchore_routes())
    out = io.StringIO()
    ctx = observe.run(credential(scheme), out_root=tmp_path / "rec", transport=transport, sleep=lambda s: None, stdout=out, **kw)
    return ctx, transport, out.getvalue()


def templates_regex():
    ops = json.loads(CONSUMED.read_text(encoding="utf-8"))["operations"]
    return [re.compile("^" + re.sub(r"\{[^}]+\}", "[^/]+", o["path"]) + "$") for o in ops]


class TestRequests:
    def test_only_get_over_https_and_only_listed_paths(self, tmp_path):
        _, transport, _ = observe_run(tmp_path)
        patterns = templates_regex() + [re.compile("^/openapi.json$")]
        assert transport.calls
        for request in transport.calls:
            assert request.method == "GET" and str(request.url).startswith("https://")
            path = str(request.url).split("/v2", 1)[1].split("?", 1)[0]
            assert any(p.match(path) for p in patterns), path

    def test_a_path_outside_the_consumed_list_is_refused(self, tmp_path):
        ctx, transport, _ = observe_run(tmp_path)
        before = len(transport.calls)
        with pytest.raises(observe.ClientError):
            observe.fetch(ctx, "x", "/accounts")
        assert len(transport.calls) == before

    def test_excluded_endpoints_are_never_requested(self, tmp_path):
        _, transport, _ = observe_run(tmp_path)
        for request in transport.calls:
            url = str(request.url)
            assert "secret-search" not in url and "retrieved-files" not in url and "file-content-search" not in url
            assert "/content/files" not in url and "/downloads" not in url and "/jobs" not in url

    def test_the_sampled_image_is_read_in_the_fixed_order(self, tmp_path):
        ctx, _, _ = observe_run(tmp_path)
        steps = [line.step for line in ctx.lines]
        assert steps[:2] == ["account", "account"] and steps.index("probe") < steps.index("spec") < steps.index("images") < steps.index("sources")

    def test_account_header_is_tried_with_and_without_then_follows_the_flag(self, tmp_path):
        _, transport, _ = observe_run(tmp_path, account_header=False)
        account_calls = [c for c in transport.calls if str(c.url).endswith("/account")]
        assert len(account_calls) == 2
        assert "x-anchore-account" in account_calls[0].headers and "x-anchore-account" not in account_calls[1].headers
        assert all("x-anchore-account" not in c.headers for c in transport.calls[2:])


class TestThreeStates:
    def test_an_operation_needing_a_parameter_it_cannot_know_is_not_read_not_empty(self, tmp_path):
        ctx, transport, _ = observe_run(tmp_path)
        by_template = {line.template: line for line in ctx.lines}
        assert not any(str(c.url).split("?")[0].endswith("/packages-by-vulnerability") for c in transport.calls)
        for template in ("/ecs-containers", "/kubernetes-pods"):
            assert by_template[template].status in {"404", "200"}  # page was supplied, so it was asked
        ctx2 = observe.Context(credential(), None, tmp_path, {"/apps/{app_id}/versions/{version_id}/packages-by-vulnerability"}, {"/apps/{app_id}/versions/{version_id}/packages-by-vulnerability": {"vulnerability_id": True}}, True)
        assert observe.fetch(ctx2, "t", "/apps/{app_id}/versions/{version_id}/packages-by-vulnerability", values={"app_id": "a", "version_id": "v"}) is None
        assert ctx2.lines[0].status == "not read" and "vulnerability_id" in ctx2.lines[0].note

    def test_check_is_requested_with_the_tag_found_in_the_image_record(self, tmp_path):
        _, transport, _ = observe_run(tmp_path)
        checks = [c for c in transport.calls if str(c.url).split("?")[0].endswith("/check")]
        assert len(checks) == 1 and "tag=registry.example%2Fapp%3A1" in str(checks[0].url)

    def test_check_without_a_tag_is_not_read(self, tmp_path):
        routes = anchore_routes()
        routes["/images"] = response(200, {"images": [{"imageDigest": DIGEST}]})
        ctx, _, _ = observe_run(tmp_path, routes=routes)
        assert any(line.template.endswith("/check") and line.status == "not read" for line in ctx.lines)

    def test_a_failing_read_is_recorded_and_the_rest_continue(self, tmp_path):
        routes = anchore_routes()
        routes["/system"] = requests.ConnectionError("down")
        ctx, _, text = observe_run(tmp_path, routes=routes)
        assert any(line.template == "/system" and line.status == "failed" for line in ctx.lines)
        assert "/images" in text

    def test_no_image_means_the_per_image_reads_are_not_read(self, tmp_path):
        routes = anchore_routes()
        routes["/images"] = response(200, {"images": []})
        ctx, _, text = observe_run(tmp_path, routes=routes)
        assert not any("/vuln/" in line.template and line.step == "image" for line in ctx.lines)
        assert "not read" in text


class TestAnswers:
    def test_the_report_names_wrapper_digest_kind_and_severities(self, tmp_path):
        _, _, text = observe_run(tmp_path)
        assert "sha256, 64 hex" in text and "'images'" in text
        assert "'High': 1" in text and "'Low': 1" in text
        assert "difference(s) in what the plugin consumes" in text and "0 difference(s)" in text

    def test_a_drifted_instance_spec_is_reported(self, tmp_path):
        routes = anchore_routes()
        spec = json.loads(routes["/openapi.json"].content)
        del spec["paths"]["/status"]
        routes["/openapi.json"] = response(200, json.dumps(spec))
        _, _, text = observe_run(tmp_path, routes=routes)
        assert "consumed difference: GET /status" in text


class TestSecrecy:
    @pytest.mark.parametrize("scheme", ["basic", "api_key", "bearer"])
    def test_no_secret_in_the_report_or_in_any_recording(self, tmp_path, scheme):
        ctx, _, text = observe_run(tmp_path, scheme=scheme)
        assert SECRET not in text
        files = list(ctx.out_dir.glob("*.json"))
        assert files
        forms = [SECRET, base64.b64encode(f"reader:{SECRET}".encode()).decode(), base64.b64encode(f"_api_key:{SECRET}".encode()).decode(), f"Bearer {SECRET}"]
        for path in files:
            body = path.read_text(encoding="utf-8")
            assert not any(form in body for form in forms)
            # Header NAMES are recorded; header VALUES that can carry a credential are not.
            recorded = json.loads(body)
            assert "authorization" not in recorded.get("headers", {}) and "set-cookie" not in recorded.get("headers", {})

    def test_recordings_are_private_and_outside_the_repository(self, tmp_path):
        ctx, _, _ = observe_run(tmp_path)
        assert stat.S_IMODE(ctx.out_dir.stat().st_mode) == 0o700
        assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in ctx.out_dir.glob("*.json"))
        repo = Path(observe.__file__).resolve().parents[2]
        assert repo not in ctx.out_dir.resolve().parents

    def test_the_report_does_not_print_bodies_or_names(self, tmp_path):
        _, _, text = observe_run(tmp_path)
        assert "demo-account" not in text and "registry.example" not in text and DIGEST not in text


class TestCommand:
    def _setup(self, tmp_path, monkeypatch):
        root = tmp_path / "secrets"
        root.mkdir()
        write(root, "demo", data(account="acct"))
        write(root, "broken", data(scheme="api_key", username="x"))
        monkeypatch.setenv("TAP_SECRETS_ROOT", str(root))
        return root

    def test_list_shows_usable_and_unusable_without_a_request(self, tmp_path, monkeypatch):
        self._setup(tmp_path, monkeypatch)
        out = io.StringIO()
        transport = FakeTransport(anchore_routes())
        assert observe.main(["--list"], stdout=out, transport=transport) == 0
        text = out.getvalue()
        assert "anchore:demo: scheme basic" in text and "anchore:broken: NOT USABLE" in text and SECRET not in text
        assert transport.calls == []

    def test_dry_run_sends_nothing(self, tmp_path, monkeypatch):
        self._setup(tmp_path, monkeypatch)
        out = io.StringIO()
        transport = FakeTransport(anchore_routes())
        assert observe.main(["--key", "demo", "--dry-run"], stdout=out, transport=transport) == 0
        assert transport.calls == [] and "nothing is sent" in out.getvalue()

    def test_an_unknown_or_unusable_key_is_refused(self, tmp_path, monkeypatch):
        self._setup(tmp_path, monkeypatch)
        out = io.StringIO()
        assert observe.main(["--key", "missing"], stdout=out, transport=FakeTransport()) == 2
        assert observe.main(["--key", "broken"], stdout=out, transport=FakeTransport()) == 2
        assert "NOT USABLE" in out.getvalue()

    def test_a_real_run_through_the_command(self, tmp_path, monkeypatch):
        self._setup(tmp_path, monkeypatch)
        out = io.StringIO()
        assert observe.main(["--key", "demo"], stdout=out, out_root=tmp_path / "rec", transport=FakeTransport(anchore_routes()), sleep=lambda s: None) == 0
        assert "Answers to the open questions" in out.getvalue()

    def test_no_secrets_root_is_a_clear_error(self, monkeypatch):
        monkeypatch.delenv("TAP_SECRETS_ROOT", raising=False)
        monkeypatch.setattr(observe.secrets_root, "resolve", lambda: None)
        out = io.StringIO()
        assert observe.main(["--list"], stdout=out) == 2 and "TAP_SECRETS_ROOT" in out.getvalue()


class TestAccept:
    def test_the_xml_vex_document_is_asked_for_as_xml(self, tmp_path):
        _, transport, _ = observe_run(tmp_path)
        xml = [c for c in transport.calls if str(c.url).endswith("/vex/cyclonedx-xml")]
        assert len(xml) == 1 and xml[0].headers["Accept"] == "application/xml"
