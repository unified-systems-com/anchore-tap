"""The scanner, scan-run and finding node types and their three edges (req-anchore-findings).

Creation through the service layer, required fields, the declared natural keys (found again by
the generated search), the three states (null is unobserved), values stored as Anchore returned
them, and the endpoint rules of the edges. The payloads are spec-derived from Anchore's OpenAPI
file (version 2.20.0), not recorded from an instance.
"""

import pytest
import tap_plugin.anchore.models as anchore  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models as compliance  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration

from tap_grid.constraints import InvalidEdgeError
from tap_grid.models import Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_edge, create_node
from tap_plugin.anchore.credential import canonical_root, scanner_key
from tap_plugin.anchore.models.finding import package_key_for
from tap_plugin.anchore.tests.conftest import dimension_view, vulnerability_dimensions_declared

SCANNER_KEY = scanner_key("https://anchore.example:8228/v2", "demo")
OTHER_ACCOUNT_KEY = scanner_key("https://anchore.example:8228/v2", "other")
DIGEST = "sha256:" + "ab" * 32

API_ROOT = canonical_root("https://Anchore.Example:8228/v2")
SCANNER = {"scanner_key": SCANNER_KEY, "api_root": API_ROOT, "account": "demo"}
RUN = {"scanner_key": SCANNER_KEY, "run_id": "run-1"}
FINDING = {
    "scanner_key": SCANNER_KEY,
    "vulnerability_id": "CVE-2024-0001",
    "target_kind": "image",
    "target_key": DIGEST,
    "package": "openssl-1.1.1",
    "package_path": "/usr/lib/libssl.so",
    "package_key": package_key_for("openssl-1.1.1", "/usr/lib/libssl.so"),
}


FINDING_KEY = {k: FINDING[k] for k in get_model_class("anchore__anchore_finding").NATURAL_KEY}


def _create(type_slug: str, payload: dict):
    result = create_node(type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    return get_model_class(type_slug).objects.get(entity=Entity.objects.get(pk=result.entity_id))


@pytest.mark.django_db
class TestScanner:
    def test_create_and_display(self):
        node = _create("anchore__anchore_scanner", SCANNER)
        node.entity.refresh_from_db()
        assert node.entity.name == "https://anchore.example:8228/v2 · demo"
        assert dimension_view(node.entity).get("anchore.area") == "run"

    def test_unread_version_is_null_not_empty(self):
        assert _create("anchore__anchore_scanner", SCANNER).reported_version is None

    @pytest.mark.parametrize("missing", ["scanner_key", "api_root", "account"])
    def test_identity_fields_required(self, missing):
        payload = {k: v for k, v in SCANNER.items() if k != missing}
        assert not create_node("anchore__anchore_scanner", payload).success

    def test_a_key_that_disagrees_with_its_columns_is_refused(self):
        """A key naming one account over columns naming another would misattribute every finding under it."""
        assert not create_node("anchore__anchore_scanner", {**SCANNER, "account": "other"}).success
        assert not create_node("anchore__anchore_scanner", {**SCANNER, "scanner_key": OTHER_ACCOUNT_KEY}).success
        assert not create_node("anchore__anchore_scanner", {**SCANNER, "scanner_key": "not json"}).success

    def test_found_again_by_scanner_key_and_accounts_stay_apart(self):
        node = _create("anchore__anchore_scanner", SCANNER)
        model = get_model_class("anchore__anchore_scanner")
        assert model.find_existing(scanner_key=SCANNER_KEY).pk == node.pk
        assert model.find_existing(scanner_key=OTHER_ACCOUNT_KEY) is None


@pytest.mark.django_db
class TestScanRun:
    def test_create_and_display(self):
        node = _create("anchore__anchore_scan_run", RUN)
        node.entity.refresh_from_db()
        assert node.entity.name == "run run-1"
        assert dimension_view(node.entity).get("anchore.area") == "run"

    def test_everything_unread_is_null(self):
        node = _create("anchore__anchore_scan_run", RUN)
        for name in ("started_at", "reported_version", "status", "feeds", "selftest_verdict", "selftest_detail", "scopes_read", "scopes_not_read"):
            assert getattr(node, name) is None, name

    def test_observed_empty_is_kept_apart_from_unobserved(self):
        node = _create("anchore__anchore_scan_run", {**RUN, "scopes_read": [], "scopes_not_read": []})
        assert node.scopes_read == [] and node.scopes_not_read == []

    def test_a_scope_not_read_names_its_reason(self):
        ok = {**RUN, "scopes_not_read": [{"scope": DIGEST, "reason": "analysis not complete"}]}
        assert create_node("anchore__anchore_scan_run", ok).success
        assert not create_node("anchore__anchore_scan_run", {**RUN, "run_id": "run-2", "scopes_not_read": [{"scope": DIGEST}]}).success

    def test_selftest_verdict_is_closed(self):
        assert not create_node("anchore__anchore_scan_run", {**RUN, "selftest_verdict": "ok"}).success
        assert create_node("anchore__anchore_scan_run", {**RUN, "run_id": "run-3", "selftest_verdict": "warn"}).success

    def test_found_again_by_scanner_and_run(self):
        node = _create("anchore__anchore_scan_run", RUN)
        model = get_model_class("anchore__anchore_scan_run")
        assert model.find_existing(scanner_key=SCANNER_KEY, run_id="run-1").pk == node.pk

    def test_run_of_scanner_edge(self):
        run = _create("anchore__anchore_scan_run", RUN)
        scanner = _create("anchore__anchore_scanner", SCANNER)
        edge = create_edge(run.entity, scanner.entity, "RUN_OF_SCANNER__anchore")
        assert dimension_view(edge.entity).get("anchore.area") == "run"

    def test_run_of_scanner_refuses_the_wrong_direction(self):
        run = _create("anchore__anchore_scan_run", RUN)
        scanner = _create("anchore__anchore_scanner", SCANNER)
        with pytest.raises(InvalidEdgeError):
            create_edge(scanner.entity, run.entity, "RUN_OF_SCANNER__anchore")


@pytest.mark.django_db
class TestFinding:
    def test_create_and_display(self):
        node = _create("anchore__anchore_finding", {**FINDING, "package_name": "openssl"})
        node.entity.refresh_from_db()
        assert node.entity.name == "CVE-2024-0001 · openssl"
        assert dimension_view(node.entity).get("anchore.area") == "finding"

    def test_fields_nothing_observed_are_null(self):
        node = _create("anchore__anchore_finding", FINDING)
        for name in ("severity", "fix", "suggested_fix_version", "fix_observed_at", "will_not_fix", "is_kev", "epss", "nvd_data", "vendor_data", "state"):
            assert getattr(node, name) is None, name

    def test_values_are_kept_as_anchore_returned_them(self):
        node = _create(
            "anchore__anchore_finding",
            {
                **FINDING,
                "severity": "Critical",
                "fix": "None",
                "suggested_fix_version": "1.1.1k-1",
                "will_not_fix": False,
                "epss": [{"epss": 0.0123, "percentile": 0.77}],
                "nvd_data": [{"id": "CVE-2024-0001", "cvss_v3": {"base_score": 9.8}}, {"id": "CVE-2024-0001", "cvss_v3": {"base_score": 7.5}}],
            },
        )
        assert node.severity == "Critical"
        assert node.fix == "None"
        assert node.will_not_fix is False
        assert len(node.nvd_data) == 2

    def test_an_observed_empty_list_is_not_null(self):
        assert _create("anchore__anchore_finding", {**FINDING, "vendor_data": []}).vendor_data == []

    @pytest.mark.parametrize("missing", ["scanner_key", "vulnerability_id", "target_kind", "target_key", "package_key"])
    def test_key_fields_required(self, missing):
        payload = {k: v for k, v in FINDING.items() if k != missing}
        assert not create_node("anchore__anchore_finding", payload).success

    def test_a_package_key_is_derived_from_its_two_columns(self):
        """Two stored copies of one identity cannot disagree: a key that is not the digest of its parts is refused."""
        assert not create_node("anchore__anchore_finding", {**FINDING, "package_key": package_key_for("other", "/x")}).success
        assert not create_node("anchore__anchore_finding", {**FINDING, "package_path": "/elsewhere"}).success

    def test_any_package_value_is_representable(self):
        """Quotes, backslashes and very long values escape to a far longer JSON text; the digest stays 64 characters."""
        package, path = '"' * 600, "\\" * 3000 + "é"
        key = package_key_for(package, path)
        assert len(key) == 64
        node = _create("anchore__anchore_finding", {**FINDING, "package": package, "package_path": path, "package_key": key})
        assert node.package == package and node.package_path == path

    def test_an_unobserved_package_part_stays_null_in_the_key(self):
        """A null package_path is unobserved, not an empty path: the two derive different keys."""
        assert package_key_for("p", None) != package_key_for("p", "")
        payload = {k: v for k, v in FINDING.items() if k != "package_path"}
        assert create_node("anchore__anchore_finding", {**payload, "package_key": package_key_for("openssl-1.1.1", None)}).success

    def test_target_kind_is_image_or_source(self):
        assert not create_node("anchore__anchore_finding", {**FINDING, "target_kind": "host"}).success
        assert create_node("anchore__anchore_finding", {**FINDING, "target_kind": "source", "target_key": "src-1"}).success

    def test_state_is_current_or_resolved(self):
        assert not create_node("anchore__anchore_finding", {**FINDING, "state": "closed"}).success

    def test_the_key_names_the_assertion_never_the_run(self):
        assert "last_seen_run_id" not in get_model_class("anchore__anchore_finding").NATURAL_KEY
        node = _create("anchore__anchore_finding", {**FINDING, "last_seen_run_id": "run-1"})
        model = get_model_class("anchore__anchore_finding")
        assert model.find_existing(**FINDING_KEY).pk == node.pk

    def test_the_scanner_is_in_the_key(self):
        _create("anchore__anchore_finding", FINDING)
        model = get_model_class("anchore__anchore_finding")
        assert model.find_existing(**{**FINDING_KEY, "scanner_key": OTHER_ACCOUNT_KEY}) is None

    def test_edges_to_the_image_and_package(self):
        finding = _create("anchore__anchore_finding", FINDING)
        host = _create("computing_core__host", {"realm": "assert", "stable_id": "image-under-test", "kind": "container"})
        package = _create("computing_core__package", {"ecosystem": "deb", "name": "openssl", "version": "1.1.1"})
        for target, slug in ((host, "FOUND_ON_IMAGE__anchore"), (package, "FOUND_IN_PACKAGE__anchore")):
            edge = create_edge(finding.entity, target.entity, slug)
            assert dimension_view(edge.entity).get("anchore.area") == "finding", slug

    def test_a_source_finding_is_found_in_the_sbom_document_it_was_read_from(self):
        """computing_core no longer blocks every edge into a document, so the edge needs no change there."""
        finding = _create("anchore__anchore_finding", {**FINDING, "target_kind": "source", "target_key": "src-1"})
        document = _create("computing_core__sbom_document", {"content_digest": "cd" * 32})
        edge = create_edge(finding.entity, document.entity, "FOUND_IN_SBOM__anchore")
        assert dimension_view(edge.entity).get("anchore.area") == "finding"

    def test_a_finding_is_about_the_shared_vulnerability(self):
        """The edge a finding draws to compliance_core's vulnerability; this plugin never creates that node."""
        vulnerability_dimensions_declared()
        finding = _create("anchore__anchore_finding", FINDING)
        vulnerability = _create("compliance_core__compliance_vulnerability", {"vuln_id": "CVE-2024-0001"})
        edge = create_edge(finding.entity, vulnerability.entity, "ABOUT_VULNERABILITY__anchore")
        assert dimension_view(edge.entity).get("anchore.area") == "finding"

    def test_an_edge_to_the_wrong_type_is_refused(self):
        finding = _create("anchore__anchore_finding", FINDING)
        package = _create("computing_core__package", {"ecosystem": "deb", "name": "openssl", "version": "1.1.1"})
        with pytest.raises(InvalidEdgeError):
            create_edge(finding.entity, package.entity, "FOUND_ON_IMAGE__anchore")


def test_no_anchore_node_declares_containment():
    """A finding is reached by traversal and never owned; retiring a run or scanner retires no finding."""
    for slug in ("anchore__anchore_scanner", "anchore__anchore_scan_run", "anchore__anchore_finding"):
        assert get_model_class(slug).CONTAINMENT_EDGES == ()
