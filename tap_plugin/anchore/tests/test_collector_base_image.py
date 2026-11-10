"""Base-image attribution of findings and the ancestor links (req-anchore-base-image-*).

The payloads are spec-derived from Anchore's OpenAPI file (2.20.0), not recorded from an instance.
"""

import pytest
import tap_plugin.anchore.models as anchore  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models as compliance  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration
from tap_plugin.computing_core.models.host import Host

from tap_grid.models import Edge
from tap_plugin.anchore.models.scan_run import AnchoreScanRun
from tap_plugin.anchore.tests.test_collector_run import DIGEST, Instance, findings, no_sockets, run_against, secrets, vuln  # noqa: F401 — fixtures
from tap_plugin.anchore.tests.test_collector_scope import configure

BASE = "sha256:" + "b" * 64
ROOT = "sha256:" + "c" * 64


def run() -> AnchoreScanRun:
    return AnchoreScanRun.objects.order_by("-finished_at").first()


def not_read() -> dict[str, str]:
    return {entry["scope"]: entry["reason"] for entry in run().scopes_not_read}


def built_on() -> set[tuple[str, str]]:
    return {(Host.objects.get(entity_id=e.from_entity_id).stable_id, Host.objects.get(entity_id=e.to_entity_id).stable_id) for e in Edge.objects.filter(edge_type="BUILT_ON_IMAGE__anchore")}


def instance(**flags) -> Instance:
    return Instance(vulns=[vuln("CVE-2024-0001", inherited_from_base=True), vuln("CVE-2024-0002", inherited_from_base=False), vuln("CVE-2024-0003")], **flags)


@pytest.mark.django_db
class TestAttribution:
    def test_the_read_asks_for_the_base_and_each_finding_says_which_and_whether(self, secrets, monkeypatch):
        server = instance()
        server.base[DIGEST] = BASE
        run_against(monkeypatch, server)
        asked = [str(call.url) for call in server.transport.calls if "/vuln/all" in str(call.url)]
        assert asked and all("base_digest=auto" in url for url in asked)
        got = {vuln_id: (f.inherited_from_base, f.base_digest) for (vuln_id, _), f in findings().items()}
        assert got == {"CVE-2024-0001": (True, BASE), "CVE-2024-0002": (False, BASE), "CVE-2024-0003": (None, BASE)}

    def test_without_a_named_base_not_inherited_is_unobserved(self, secrets, monkeypatch):
        """False with no base to compare against is not an observation; true still says a base held it."""
        run_against(monkeypatch, instance())
        got = {vuln_id: (f.inherited_from_base, f.base_digest) for (vuln_id, _), f in findings().items()}
        assert got == {"CVE-2024-0001": (True, None), "CVE-2024-0002": (None, None), "CVE-2024-0003": (None, None)}

    @pytest.mark.parametrize("base", ["latest", "sha256:XYZ", DIGEST])
    def test_a_base_that_is_not_another_image_digest_is_no_base(self, secrets, monkeypatch, base):
        server = instance()
        server.base[DIGEST] = base
        run_against(monkeypatch, server)
        assert {f.base_digest for f in findings().values()} == {None}

    @pytest.mark.parametrize("status", [400, 422])
    def test_an_instance_that_refuses_the_parameter_is_read_without_it_and_says_so(self, secrets, monkeypatch, status):
        server = instance()
        server.refuse_base = status
        run_against(monkeypatch, server)
        assert len(findings()) == 3
        assert f"refused base_digest=auto (HTTP {status})" in not_read()[f"base:{DIGEST}"]
        assert f"image:{DIGEST}" in run().scopes_read

    @pytest.mark.parametrize("status", [404, 408, 429])
    def test_a_status_that_is_not_about_the_request_is_not_taken_for_a_refusal(self, secrets, monkeypatch, status):
        """Throttling is about now: reading again without the parameter would add load and lose the attribution."""
        server = instance()
        server.refuse_base = status
        run_against(monkeypatch, server)
        asked = [str(call.url) for call in server.transport.calls if "/vuln/all" in str(call.url)]
        assert all("base_digest=auto" in url for url in asked)
        assert f"base:{DIGEST}" not in not_read() and f"image:{DIGEST}" in not_read() and not findings()

    def test_a_failure_that_is_not_about_the_parameter_is_not_retried_without_it(self, secrets, monkeypatch):
        server = instance()
        server.failing.add(DIGEST)
        run_against(monkeypatch, server)
        asked = [str(call.url) for call in server.transport.calls if "/vuln/all" in str(call.url)]
        assert all("base_digest=auto" in url for url in asked)
        assert f"base:{DIGEST}" not in not_read() and f"image:{DIGEST}" in not_read()


@pytest.mark.django_db
class TestAncestors:
    def test_each_ancestor_is_an_edge_to_its_image_host(self, secrets, monkeypatch):
        server = instance()
        server.ancestors[DIGEST] = [{"image_digest": ROOT, "layers": ["sha256:1"]}, {"image_digest": BASE, "layers": ["sha256:1", "sha256:2"], "chosen_base_image": True}]
        run_against(monkeypatch, server)
        assert built_on() == {(DIGEST, ROOT), (DIGEST, BASE)}
        # An ancestor's host is a stub: the digest and nothing Anchore did not say.
        assert Host.objects.get(stable_id=BASE).realm == "oci-digest"
        assert f"ancestors:{DIGEST}" in run().scopes_read

    def test_a_second_run_writes_no_second_edge(self, secrets, monkeypatch):
        server = instance()
        server.ancestors[DIGEST] = [{"image_digest": BASE}]
        run_against(monkeypatch, server)
        run_against(monkeypatch, server)
        assert Edge.objects.filter(edge_type="BUILT_ON_IMAGE__anchore").count() == 1

    def test_an_entry_that_names_no_other_image_is_left_out(self, secrets, monkeypatch):
        server = instance()
        server.ancestors[DIGEST] = [{"image_digest": DIGEST}, {"image_digest": "node:latest"}, {"tags": ["x"]}, {"image_digest": BASE}]
        run_against(monkeypatch, server)
        assert built_on() == {(DIGEST, BASE)}

    def test_no_ancestor_is_observed_empty_and_writes_nothing(self, secrets, monkeypatch):
        run_against(monkeypatch, instance())
        assert built_on() == set() and f"ancestors:{DIGEST}" in run().scopes_read

    @pytest.mark.parametrize("answer", [404, 500, {"detail": "not a list"}, ["not an object"]])
    def test_a_list_that_cannot_be_read_is_recorded_and_the_image_is_still_read(self, secrets, monkeypatch, answer):
        server = instance()
        server.ancestors[DIGEST] = answer
        run_against(monkeypatch, server)
        assert f"ancestors:{DIGEST}" in not_read()
        assert len(findings()) == 3 and built_on() == set()


@pytest.mark.django_db
class TestAncestorsObeyTheScope:
    def test_an_ancestor_outside_the_repository_prefixes_is_not_written_and_the_base_still_is(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": False, "repository_prefixes": ["registry.example/"]})
        server = Instance(vulns=[vuln("CVE-2024-0001", inherited_from_base=True)], images=[{"image_digest": DIGEST, "analysis_status": "analyzed", "image_detail": [{"registry": "registry.example", "repo": "app", "tag": "1"}]}])
        server.base[DIGEST] = BASE
        server.ancestors[DIGEST] = [{"image_digest": BASE, "tags": ["docker.io/library/node:20"]}, {"image_digest": ROOT, "tags": ["registry.example/base/os:9"]}, {"image_digest": "sha256:" + "d" * 64}]
        run_against(monkeypatch, server)
        assert built_on() == {(DIGEST, ROOT)}
        assert not Host.objects.filter(stable_id=BASE).exists()
        assert findings()[("CVE-2024-0001", DIGEST)].base_digest == BASE
