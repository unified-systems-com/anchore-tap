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
        assert "acct" not in text  # the account name is not printed
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


class TestHostileInstance:
    def test_control_characters_from_an_instance_never_reach_the_terminal(self, tmp_path):
        routes = anchore_routes()
        routes["/system"] = response(200, {"version\x1b[31m": "5\x07", "ok": True})
        routes["/images"] = response(200, {"images\x1b]0;pwned\x07": [{"imageDigest": DIGEST, "analysis_status": "analyzed", "x\x1b[2J": 1}]})
        spec = json.loads(routes["/openapi.json"].content)
        spec["info"]["version"] = "9\x1b[31m.0\x07"
        spec["paths"]["/new\x1b[2Jpath"] = {"get": {"responses": {"200": {"description": "ok"}}}}
        del spec["paths"]["/status"]
        routes["/openapi.json"] = response(200, json.dumps(spec))
        _, _, text = observe_run(tmp_path, routes=routes)
        assert "version 9?[31m.0?" in text  # the instance's version string, cleaned
        assert "\x1b" not in text and "\x07" not in text

    def test_safe_bounds_and_cleans(self):
        assert observe.safe("a\x1b[0mb") == "a?[0mb"
        assert len(observe.safe("x" * 1000)) == 240


class TestEchoedCredential:
    """An instance that echoes the credential must not get it written into a recording."""

    def _echo_routes(self, scheme):
        forms = {
            "basic": [SECRET, base64.b64encode(f"reader:{SECRET}".encode()).decode()],
            "api_key": [SECRET, base64.b64encode(f"_api_key:{SECRET}".encode()).decode()],
            "bearer": [SECRET, f"Bearer {SECRET}"],
        }[scheme]
        routes = anchore_routes()
        routes["/account"] = response(200, {"name": "demo", "echo": forms[0], "auth": forms[1]}, {"X-Echo-Authorization": forms[1]})
        return routes

    @pytest.mark.parametrize("scheme", ["basic", "api_key", "bearer"])
    def test_every_form_is_redacted_from_body_and_headers(self, tmp_path, scheme):
        ctx, _, text = observe_run(tmp_path, scheme=scheme, routes=self._echo_routes(scheme))
        recordings = "".join(p.read_text(encoding="utf-8") for p in ctx.out_dir.glob("*.json"))
        assert SECRET not in recordings and SECRET not in text
        assert "[REDACTED:credential]" in recordings and ctx.redactions >= 4
        assert "occurrence(s) of the credential" in text
        assert "demo" in recordings  # the rest of the body is kept

    def test_a_clean_run_reports_no_redactions(self, tmp_path):
        ctx, _, text = observe_run(tmp_path)
        assert ctx.redactions == 0 and "occurrence(s) of the credential" not in text


class TestPrivateRoot:
    def test_the_recordings_root_is_owner_only_too(self, tmp_path):
        ctx, _, _ = observe_run(tmp_path)
        root = ctx.out_dir.parent
        assert stat.S_IMODE(root.stat().st_mode) == 0o700 and stat.S_IMODE(ctx.out_dir.stat().st_mode) == 0o700

    def test_an_existing_listable_root_is_tightened(self, tmp_path):
        root = tmp_path / "rec"
        root.mkdir(mode=0o755)
        root.chmod(0o755)
        observe_run(tmp_path)
        assert stat.S_IMODE(root.stat().st_mode) == 0o700


class TestFailureNotes:
    def test_a_failed_read_prints_the_class_of_failure_not_the_identifier(self, tmp_path):
        routes = anchore_routes()
        routes[f"/images/{DIGEST}/vuln/all"] = requests.ConnectionError("down")
        ctx, _, text = observe_run(tmp_path, routes=routes)
        failed = [line for line in ctx.lines if line.status == "failed"]
        assert failed and DIGEST not in text and "RequestFailed" in text
        recordings = "".join(p.read_text(encoding="utf-8") for p in ctx.out_dir.glob("*.json"))
        assert DIGEST in recordings  # the full message is kept in the private recording


class TestAtomicPrivateWrites:
    def test_a_recording_is_never_readable_by_others_even_for_an_instant(self, tmp_path, monkeypatch):
        """The file is created owner-only from the first byte, so a permissive umask cannot expose it."""
        seen = []
        real_open = observe.os.open

        def spy(path, flags, mode=0o777, *a, **k):
            seen.append(mode)
            return real_open(path, flags, mode, *a, **k)

        monkeypatch.setattr(observe.os, "open", spy)
        old = observe.os.umask(0o000)
        try:
            ctx, _, _ = observe_run(tmp_path)
        finally:
            observe.os.umask(old)
        assert seen and set(seen) == {0o600}
        assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in ctx.out_dir.glob("*.json"))

    def test_write_private_refuses_to_overwrite(self, tmp_path):
        target = tmp_path / "x.json"
        observe.write_private(target, "a")
        with pytest.raises(FileExistsError):
            observe.write_private(target, "b")


class TestHostileEchoEverywhere:
    """An instance can put the credential in any field it controls; none of it may reach a recording or the terminal."""

    def test_the_credential_in_every_instance_controlled_place_is_redacted(self, tmp_path):
        routes = anchore_routes()
        routes["/account"] = response(200, {"name": "x"}, {"Content-Type": f"application/json; note={SECRET}"})
        routes["/system"] = response(200, {SECRET: 1, "ok": SECRET})
        routes["/system/feeds"] = response(200, [{"name": SECRET}])
        spec = json.loads(routes["/openapi.json"].content)
        spec["info"]["version"] = f"v{SECRET}"
        spec["paths"][f"/{SECRET}"] = {"get": {"responses": {"200": {"description": "ok"}}}}
        routes["/openapi.json"] = response(200, json.dumps(spec))
        # An image whose tag and digest are the credential: the paths and params built from them are recorded.
        routes["/images"] = response(200, {SECRET: [{"imageDigest": "sha256:" + "cd" * 32, "analysis_status": "analyzed", "image_detail": [{"fulltag": SECRET}]}]})
        ctx, transport, text = observe_run(tmp_path, routes=routes)
        recordings = "".join(p.read_text(encoding="utf-8") for p in ctx.out_dir.glob("*.json"))
        for form in (SECRET, base64.b64encode(f"reader:{SECRET}".encode()).decode()):
            assert form not in text and form not in recordings
        assert ctx.redactions >= 5 and "[REDACTED:credential]" in recordings
        # The credential is never put in a URL, even one built from a value the instance supplied.
        assert not any(SECRET in str(c.url) for c in transport.calls)
        assert any(line.status == "not read" and "matched the credential" in line.note for line in ctx.lines)

    def test_redact_tree_covers_keys_values_and_nesting(self):
        c = credential()
        cleaned, n = observe.redact_tree({SECRET: [SECRET, {"a": f"x{SECRET}y"}], "n": 1}, c.redact)
        assert SECRET not in json.dumps(cleaned) and n == 3 and cleaned["n"] == 1


class TestRecordingsStayOutOfRepositories:
    def test_a_symlinked_root_is_refused(self, tmp_path):
        real = tmp_path / "elsewhere"
        real.mkdir()
        link = tmp_path / "rec"
        link.symlink_to(real, target_is_directory=True)
        with pytest.raises(observe.ClientError, match="symbolic link"):
            observe.run(credential(), out_root=link, transport=FakeTransport(anchore_routes()), sleep=lambda s: None, stdout=io.StringIO())
        assert list(real.iterdir()) == []

    def test_a_root_inside_a_git_work_tree_is_refused(self, tmp_path):
        repo = tmp_path / "checkout"
        (repo / ".git").mkdir(parents=True)
        with pytest.raises(observe.ClientError, match="git work tree"):
            observe.run(credential(), out_root=repo / "recordings", transport=FakeTransport(anchore_routes()), sleep=lambda s: None, stdout=io.StringIO())
        assert not list((repo / "recordings").glob("*/*.json"))

    def test_a_pre_made_run_directory_is_not_written_through(self, tmp_path, monkeypatch):
        fixed = observe.datetime.now(observe.UTC).replace(microsecond=0)

        class Frozen(observe.datetime):
            @classmethod
            def now(cls, tz=None):
                return fixed

        monkeypatch.setattr(observe, "datetime", Frozen)
        root = tmp_path / "rec"
        root.mkdir(mode=0o700)
        name = f"{fixed.strftime('%Y%m%dT%H%M%SZ')}-{observe.hashlib.sha256(b'anchore:a').hexdigest()[:8]}"
        victim = tmp_path / "victim"
        victim.mkdir()
        (root / name).symlink_to(victim, target_is_directory=True)
        with pytest.raises(FileExistsError):
            observe.run(credential(), out_root=root, transport=FakeTransport(anchore_routes()), sleep=lambda s: None, stdout=io.StringIO())
        assert list(victim.iterdir()) == []


class TestFailureContainment:
    def test_a_broken_stream_is_recorded_and_the_observation_goes_on(self, tmp_path):
        from tap_plugin.anchore.tests.fakes import BrokenStream

        routes = anchore_routes()
        routes["/system"] = BrokenStream(requests.exceptions.ChunkedEncodingError("bad chunk"))
        ctx, _, text = observe_run(tmp_path, routes=routes)
        broken = [line for line in ctx.lines if line.template == "/system"]
        assert broken and broken[0].status == "failed" and "RequestFailed" in broken[0].note
        assert any(line.template == "/images" and line.status == "200" for line in ctx.lines)
        assert "Answers to the open questions" in text

    def test_an_unexpected_error_in_a_read_is_recorded_not_raised(self, tmp_path, monkeypatch):
        real = observe.ReadOnlyClient.get
        calls = {"n": 0}

        def flaky(self, path, **kw):
            calls["n"] += 1
            if path == "/status":
                raise RuntimeError("surprise")
            return real(self, path, **kw)

        monkeypatch.setattr(observe.ReadOnlyClient, "get", flaky)
        ctx, _, _ = observe_run(tmp_path)
        line = next(line for line in ctx.lines if line.template == "/status")
        assert line.status == "failed" and "unexpected RuntimeError" in line.note


class TestCoverageIsAccounted:
    def test_every_consumed_operation_appears_as_read_or_not_read(self, tmp_path):
        ctx, _, text = observe_run(tmp_path)
        consumed = {o["path"] for o in json.loads(CONSUMED.read_text(encoding="utf-8"))["operations"]}
        listed = {line.template for line in ctx.lines}
        assert consumed <= listed
        assert any(line.step == "coverage" and line.status == "not read" and "not requested" in line.note for line in ctx.lines)
        assert "/apps/{app_id}/versions/{version_id}/packages-by-vulnerability" in text

    def test_an_operation_added_to_the_consumed_list_is_reported_not_silently_skipped(self, tmp_path, monkeypatch):
        extra = "/brand-new-consumed"
        original = observe._context

        def with_extra(*a, **k):
            ctx = original(*a, **k)
            ctx.consumed = ctx.consumed | {extra}
            return ctx

        monkeypatch.setattr(observe, "_context", with_extra)
        ctx, _, _ = observe_run(tmp_path)
        assert any(line.template == extra and line.status == "not read" for line in ctx.lines)
