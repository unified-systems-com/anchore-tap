"""The collector end to end against a canned instance: probe, self-test, image walk, one GRIFT batch.

No socket is opened. The instance is a path table served through the read-only client's transport,
the import is the real GRIFT importer, and the nodes are read back through the models. The payloads
are spec-derived from Anchore's OpenAPI file (2.20.0), not recorded from an instance.
"""

import socket
import types
import uuid

import pytest
import tap_plugin.anchore.models as anchore  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models as compliance  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration
from django.db.models import Count

from tap_cares.collectors import CollectorConfig
from tap_cares.registry import get_collector
from tap_grid.models import Edge
from tap_plugin.anchore.client import ReadOnlyClient
from tap_plugin.anchore.collectors.anchore_collector import collector as collector_module
from tap_plugin.anchore.collectors.anchore_collector import decompose
from tap_plugin.anchore.collectors.anchore_collector.collector import AnchoreCollector, AnchoreCollectorError
from tap_plugin.anchore.credential import scanner_key
from tap_plugin.anchore.models.finding import AnchoreFinding, package_key_for
from tap_plugin.anchore.models.scan_run import AnchoreScanRun
from tap_plugin.anchore.models.scanner import AnchoreScanner
from tap_plugin.anchore.tests.fakes import VENDOR, FakeTransport, response
from tap_plugin.anchore.tests.test_anchore_credential import data, write

DIGEST = "sha256:" + "ab" * 32
OTHER = "sha256:" + "cd" * 32
KEY = scanner_key("https://anchore.example:8228/v2", "acct")
SPEC = (VENDOR / "openapi-2.20.0.json").read_bytes()


def vuln(vuln_id="CVE-2024-0001", package="libx-1.0", path="/usr/lib/libx.so", omit=(), **over):
    entry = {"vuln": vuln_id, "severity": "High", "fix": "1.2.3", "package": package, "package_path": path, "package_name": "libx", **over}
    return {k: v for k, v in entry.items() if k not in omit}


class Instance:
    """A canned instance whose answers a test can change between runs."""

    def __init__(self, vulns=None, images=None, account="acct"):
        self.vulns = {DIGEST: vulns if vulns is not None else [vuln(), vuln("CVE-2024-0002", severity="Low", omit=("fix",))]}
        self.images = images if images is not None else [{"image_digest": DIGEST, "analysis_status": "analyzed"}]
        self.account = account
        self.failing: set[str] = set()
        self.transport = FakeTransport(default=None)
        self.transport.routes = {
            "/account": lambda r: response(200, {"name": self.account, "type": "user"}),
            "/status": lambda r: response(200, {"version": "5.1.0", "up": True}),
            "/system": lambda r: response(200, {"service_states": []}),
            "/system/feeds": lambda r: response(200, [{"dataset_name": "vulnerabilities", "enabled": True, "groups": [{"name": "debian:11", "last_sync": "2026-11-03T00:00:00Z"}]}]),
            "/openapi.json": lambda r: response(200, SPEC),
            "/images": lambda r: response(200, {"items": self.images}),
        }
        for digest in (DIGEST, OTHER):
            self.transport.routes[f"/images/{digest}/vuln/all"] = self._vulns(digest)

    def _vulns(self, digest):
        def answer(request):
            if digest in self.failing:
                return response(500, {"detail": "boom"})
            return response(200, {"image_digest": digest, "vulnerabilities": self.vulns.get(digest, [])})

        return answer


@pytest.fixture(autouse=True)
def no_sockets(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("these tests must not open a socket")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


@pytest.fixture
def secrets(tmp_path, monkeypatch):
    write(tmp_path, "demo", data("basic"))
    monkeypatch.setattr(collector_module, "secrets_root", types.SimpleNamespace(resolve=lambda: tmp_path))
    return tmp_path


def run_against(monkeypatch, instance: Instance) -> AnchoreCollector:
    monkeypatch.setattr(collector_module, "ReadOnlyClient", lambda credential: ReadOnlyClient(credential, transport=instance.transport, sleep=lambda s: None))
    collector = AnchoreCollector(CollectorConfig(collector_entity_id=uuid.uuid4(), collection_job_entity_id=uuid.uuid4()))
    collector.run()
    return collector


def findings():
    return {(f.vulnerability_id, f.target_key): f for f in AnchoreFinding.objects.all()}


@pytest.mark.django_db
class TestFirstRun:
    def test_writes_the_scanner_the_run_and_the_findings_as_returned(self, secrets, monkeypatch):
        run_against(monkeypatch, Instance())
        scanner = AnchoreScanner.objects.get()
        assert scanner.scanner_key == KEY and scanner.reported_version == "5.1.0"
        run = AnchoreScanRun.objects.get()
        assert run.scanner_key == KEY and run.selftest_verdict == "pass"
        assert run.scopes_read == ["source:images", f"image:{DIGEST}"] and run.scopes_not_read == []
        assert run.status == {"version": "5.1.0", "up": True} and isinstance(run.feeds, list)
        found = findings()
        assert set(found) == {("CVE-2024-0001", DIGEST), ("CVE-2024-0002", DIGEST)}
        high, low = found[("CVE-2024-0001", DIGEST)], found[("CVE-2024-0002", DIGEST)]
        assert (high.severity, high.fix, high.state, high.last_seen_run_id) == ("High", "1.2.3", "current", run.run_id)
        assert high.package_key == package_key_for("libx-1.0", "/usr/lib/libx.so")
        # A key the response did not carry is unobserved: null, never "None" or "".
        assert low.fix is None and high.is_kev is None and high.will_not_fix is None and high.epss is None

    def test_the_run_is_linked_to_its_scanner(self, secrets, monkeypatch):
        run_against(monkeypatch, Instance())
        edge = Edge.objects.get(edge_type="RUN_OF_SCANNER__anchore")
        assert edge.from_entity.entity_type == "anchore__anchore_scan_run" and edge.to_entity.entity_type == "anchore__anchore_scanner"

    def test_only_get_requests_are_made(self, secrets, monkeypatch):
        instance = Instance()
        run_against(monkeypatch, instance)
        assert instance.transport.calls and {c.method for c in instance.transport.calls} == {"GET"}

    def test_an_image_still_being_analyzed_is_not_read_and_is_listed(self, secrets, monkeypatch):
        instance = Instance(images=[{"image_digest": DIGEST, "analysis_status": "analyzed"}, {"image_digest": OTHER, "analysis_status": "analyzing"}])
        run_against(monkeypatch, instance)
        run = AnchoreScanRun.objects.get()
        assert [n["scope"] for n in run.scopes_not_read] == [f"image:{OTHER}"]
        assert not any(c.url.endswith(f"{OTHER}/vuln/all") for c in instance.transport.calls)


@pytest.mark.django_db
class TestLaterRuns:
    def test_the_same_data_twice_is_one_set_of_nodes(self, secrets, monkeypatch):
        instance = Instance()
        run_against(monkeypatch, instance)
        run_against(monkeypatch, instance)
        assert AnchoreFinding.objects.count() == 2 and AnchoreScanner.objects.count() == 1 and AnchoreScanRun.objects.count() == 2
        keys = ("scanner_key", "vulnerability_id", "target_kind", "target_key", "package_key")
        assert AnchoreFinding.objects.values(*keys).annotate(n=Count("id")).filter(n__gt=1).count() == 0
        latest = AnchoreScanRun.objects.order_by("-finished_at").first()
        assert {f.last_seen_run_id for f in AnchoreFinding.objects.all()} == {latest.run_id}

    def test_a_finding_a_successful_read_no_longer_reports_is_resolved_not_deleted(self, secrets, monkeypatch):
        instance = Instance()
        run_against(monkeypatch, instance)
        first_run = AnchoreScanRun.objects.get().run_id
        instance.vulns[DIGEST] = [vuln()]
        run_against(monkeypatch, instance)
        found = findings()
        assert found[("CVE-2024-0002", DIGEST)].state == "resolved"
        assert found[("CVE-2024-0002", DIGEST)].severity == "Low" and found[("CVE-2024-0002", DIGEST)].last_seen_run_id == first_run
        assert found[("CVE-2024-0001", DIGEST)].state == "current"

    def test_a_read_that_failed_leaves_the_findings_untouched_and_says_so(self, secrets, monkeypatch):
        instance = Instance()
        run_against(monkeypatch, instance)
        instance.failing.add(DIGEST)
        instance.vulns[DIGEST] = []
        collector = run_against(monkeypatch, instance)
        assert {f.state for f in AnchoreFinding.objects.all()} == {"current"}
        latest = AnchoreScanRun.objects.order_by("-finished_at").first()
        assert [n["scope"] for n in latest.scopes_not_read] == [f"image:{DIGEST}"] and latest.scopes_read == ["source:images"]
        assert any(w["message_code"] == "IMAGE_NOT_READ" for w in collector.results["warn"])

    def test_an_image_that_leaves_the_list_is_not_treated_as_cleared(self, secrets, monkeypatch):
        instance = Instance()
        run_against(monkeypatch, instance)
        instance.images = []
        run_against(monkeypatch, instance)
        assert {f.state for f in AnchoreFinding.objects.all()} == {"current"}

    def test_an_image_with_no_vulnerabilities_is_observed_empty_and_resolves_its_findings(self, secrets, monkeypatch):
        instance = Instance()
        run_against(monkeypatch, instance)
        instance.vulns[DIGEST] = []
        run_against(monkeypatch, instance)
        assert {f.state for f in AnchoreFinding.objects.all()} == {"resolved"}


@pytest.mark.django_db
class TestWhatIsRefused:
    def test_a_different_account_stops_the_scanner_and_writes_nothing(self, secrets, monkeypatch):
        with pytest.raises(AnchoreCollectorError):
            run_against(monkeypatch, Instance(account="someone-else"))
        assert AnchoreScanner.objects.count() == AnchoreScanRun.objects.count() == AnchoreFinding.objects.count() == 0

    def test_no_credential_is_an_error_not_an_empty_success(self, tmp_path, monkeypatch):
        monkeypatch.setattr(collector_module, "secrets_root", types.SimpleNamespace(resolve=lambda: tmp_path))
        with pytest.raises(AnchoreCollectorError):
            run_against(monkeypatch, Instance())

    def test_an_image_list_that_cannot_be_read_or_has_the_wrong_shape_writes_nothing(self, secrets, monkeypatch):
        for answer in (response(500, {"detail": "boom"}), response(200, {"items": "not-a-list"}), response(200, b"not json")):
            instance = Instance()
            instance.transport.routes["/images"] = lambda r, a=answer: a
            with pytest.raises(AnchoreCollectorError):
                run_against(monkeypatch, instance)
        assert AnchoreScanner.objects.count() == AnchoreScanRun.objects.count() == AnchoreFinding.objects.count() == 0

    def test_a_vulnerability_response_in_the_wrong_shape_stops_the_scanner_and_writes_nothing(self, secrets, monkeypatch):
        instance = Instance()
        instance.transport.routes[f"/images/{DIGEST}/vuln/all"] = lambda r: response(200, {"vulnerabilities": "nope"})
        with pytest.raises(AnchoreCollectorError):
            run_against(monkeypatch, instance)
        assert AnchoreScanner.objects.count() == AnchoreScanRun.objects.count() == AnchoreFinding.objects.count() == 0

    def test_one_failing_scanner_does_not_stop_another(self, tmp_path, monkeypatch):
        write(tmp_path, "good", data("basic"))
        write(tmp_path, "bad", data("basic", base_url="https://other.example:8228/v2"))
        monkeypatch.setattr(collector_module, "secrets_root", types.SimpleNamespace(resolve=lambda: tmp_path))
        good = Instance()
        bad = Instance(account="not-the-account")
        monkeypatch.setattr(collector_module, "ReadOnlyClient", lambda c: ReadOnlyClient(c, transport=(good if "anchore.example" in c.base_url else bad).transport, sleep=lambda s: None))
        collector = AnchoreCollector(CollectorConfig(collector_entity_id=uuid.uuid4(), collection_job_entity_id=uuid.uuid4()))
        collector.run()
        assert AnchoreScanner.objects.get().scanner_key == KEY
        assert len(collector.results["error"]) == 1

    def test_a_value_the_model_cannot_hold_is_stored_unobserved_and_listed(self, secrets, monkeypatch):
        collector = run_against(monkeypatch, Instance(vulns=[vuln(fix="x" * 600)]))
        assert AnchoreFinding.objects.get().fix is None
        dropped = next(w for w in collector.results["warn"] if w["message_code"] == "FIELDS_DROPPED")
        assert dropped["message_data"]["values"] == [{"vulnerability": "CVE-2024-0001", "field": "fix", "reason": "longer than 512 characters", "effect": "stored as unobserved"}]

    def test_an_assertion_repeated_in_one_response_is_one_finding(self, secrets, monkeypatch):
        collector = run_against(monkeypatch, Instance(vulns=[vuln(), vuln()]))
        assert AnchoreFinding.objects.count() == 1
        assert any(w["message_data"].get("duplicates") == 1 for w in collector.results["warn"] if w["message_code"] == "ENTRIES_NOT_STORED")

    def test_an_entry_without_an_identifier_is_counted_not_stored(self, secrets, monkeypatch):
        collector = run_against(monkeypatch, Instance(vulns=[{"severity": "High"}, vuln()]))
        assert AnchoreFinding.objects.count() == 1
        assert any(w["message_data"].get("skipped") == 1 for w in collector.results["warn"] if w["message_code"] == "ENTRIES_NOT_STORED")


@pytest.mark.django_db
class TestIdentityIsNeverGuessed:
    def test_an_entry_whose_package_cannot_be_held_is_not_stored_rather_than_stored_under_a_null_identity(self):
        # The response check already refuses a wrong-typed package, so this is the second line: a value the model
        # cannot hold must never become a null that makes two different packages one assertion.
        dropped: list = []
        assert decompose.finding_fields(vuln(package_path=7), KEY, DIGEST, "run", dropped) is None
        assert dropped == [{"vulnerability": "CVE-2024-0001", "field": "package_path", "reason": "not the form the model holds", "effect": "entry not stored"}]

    def test_a_read_with_an_entry_that_could_not_be_stored_resolves_nothing(self, secrets, monkeypatch):
        instance = Instance()
        run_against(monkeypatch, instance)
        instance.vulns[DIGEST] = [{"severity": "High"}]
        run_against(monkeypatch, instance)
        # The earlier findings are still current: an entry that could not be stored proves nothing about absence.
        assert {f.state for f in AnchoreFinding.objects.all()} == {"current"} and AnchoreFinding.objects.count() == 2
        latest = AnchoreScanRun.objects.order_by("-finished_at").first()
        assert [n["scope"] for n in latest.scopes_not_read] == [f"resolution:{DIGEST}"]

    def test_image_list_entries_without_a_usable_digest_are_listed_not_skipped_silently(self, secrets, monkeypatch):
        instance = Instance(images=[{"image_digest": DIGEST, "analysis_status": "analyzed"}, {"analysis_status": "analyzed"}, {"image_digest": "", "analysis_status": "analyzed"}])
        collector = run_against(monkeypatch, instance)
        latest = AnchoreScanRun.objects.get()
        assert [n["scope"] for n in latest.scopes_not_read] == ["source:images:entries"] and "2 entry(ies)" in latest.scopes_not_read[0]["reason"]
        assert any(w["message_code"] == "IMAGES_NOT_READ" for w in collector.results["warn"])


@pytest.mark.django_db
def test_the_collector_is_registered_and_its_self_test_reports_a_credential(secrets):
    assert get_collector("anchore:anchore") is AnchoreCollector
    result = AnchoreCollector.self_test()
    assert result.to_dict()["checks"][0]["code"] == "CREDENTIAL_PRESENT"
