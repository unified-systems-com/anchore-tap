"""Differences a real instance was seen to have from the vendor's file (req-anchore-contract-extract-5).

The extract is still generated: the differences are listed in consumed.json and applied by the
reducer, so the committed schema, the drift check and the per-run self-test all carry them.
"""

import copy
import json
from pathlib import Path

import pytest
import tap_plugin.anchore.models as anchore  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models as compliance  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration
from tap_grid.registry import get_model_class

from tap_plugin.anchore.collectors.anchore_collector.manifest import shipped_manifest
from tap_plugin.anchore.collectors.anchore_collector.validate import validate_body
from tap_plugin.anchore.contract import build, reduce
from tap_plugin.anchore.models.scan_run import AnchoreScanRun
from tap_plugin.anchore.tests.test_collector_kubernetes import cluster, container, node, pod
from tap_plugin.anchore.tests.test_collector_run import DIGEST, findings, no_sockets, run_against, secrets, vuln, Instance  # noqa: F401 — fixtures
from tap_plugin.anchore.tests.test_collector_scope import configure

EXTRACT = json.loads(build.EXTRACT.read_text(encoding="utf-8"))
SOURCES = {source.id: source for source in shipped_manifest()}
SYSTEM_UID = "5f4c1c9e-0b0a-4e1f-9c7d-1a2b3c4d5e6f"

ITEM = {"type": "object", "required": ["uid", "name"], "properties": {"uid": {"type": "string"}, "name": {"type": "string"}, "size": {"type": "integer"}}}
LIST = {"type": "object", "properties": {"rows": {"type": "array", "items": ITEM}}}


def valid(source_id: str, body) -> bool:
    return validate_body(EXTRACT, SOURCES[source_id], 200, body).ok


class TestReducer:
    def test_a_nullable_path_marks_only_that_field(self):
        out = reduce.apply_observed(LIST, {"nullable": ["rows[].size"]}, "test")
        item = out["properties"]["rows"]["items"]
        assert item["properties"]["size"] == {"type": "integer", "nullable": True}
        assert "nullable" not in item["properties"]["name"]

    def test_either_requires_one_of_the_two_names(self):
        out = reduce.apply_observed(LIST, {"either": [["rows[].uid", "id"]]}, "test")
        item = out["properties"]["rows"]["items"]
        assert item["required"] == ["name"] and item["properties"]["id"] == {"type": "string"}
        assert item["anyOf"] == [{"required": ["uid"]}, {"required": ["id"]}]

    def test_the_schema_passed_in_is_not_changed(self):
        """Resolved schemas are shared between operations; an override on one must not leak into another."""
        before = copy.deepcopy(LIST)
        reduce.apply_observed(LIST, {"nullable": ["rows[].size"], "either": [["rows[].uid", "id"]]}, "test")
        assert LIST == before

    @pytest.mark.parametrize("observed", [{"nullable": ["rows[].gone"]}, {"nullable": ["nowhere[].size"]}, {"either": [["rows[].gone", "id"]]}, {"nullable": ["rows[]"]}])
    def test_a_path_that_does_not_resolve_is_an_error(self, observed):
        with pytest.raises(reduce.ReducerError):
            reduce.apply_observed(LIST, observed, "test")

    def test_a_field_inside_an_allof_is_found(self):
        schema = {"type": "object", "properties": {"rows": {"type": "array", "items": {"allOf": [{"type": "object", "properties": {"fix": {"type": "string"}}}, {"type": "object"}]}}}}
        out = reduce.apply_observed(schema, {"nullable": ["rows[].fix"]}, "test")
        assert out["properties"]["rows"]["items"]["allOf"][0]["properties"]["fix"]["nullable"] is True

    def test_the_committed_extract_is_what_the_reducer_makes_with_the_overrides(self):
        assert build.build() == build.EXTRACT.read_text(encoding="utf-8")
        observed = {op["path"]: op["observed"] for op in EXTRACT["operations"] if "observed" in op}
        assert set(observed) == {"/images", "/images/{image_digest}", "/images/{image_digest}/vuln/{vuln_type}", "/sources/{source_id}/vuln/{vuln_type}", "/kubernetes-namespaces", "/kubernetes-nodes", "/kubernetes-pods"}
        assert sum(len(o.get("nullable", [])) for o in observed.values()) == 24


class TestTheCommittedShape:
    def test_a_vulnerability_with_null_annotation_and_fix_fields_is_valid(self):
        body = {"image_digest": DIGEST, "vulnerabilities": [{"vuln": "CVE-2024-0001", "annotation_status": None, "annotation_uuid": None, "suggested_fix_version": None}]}
        assert valid("image_vulnerabilities", body)

    def test_a_null_the_instance_was_not_seen_to_send_is_still_refused(self):
        body = {"image_digest": DIGEST, "vulnerabilities": [{"vuln": "CVE-2024-0001", "severity": None}]}
        assert not valid("image_vulnerabilities", body)

    def test_an_image_list_with_null_metadata_is_valid(self):
        image = {
            "image_digest": DIGEST,
            "analysis_status": "analyzed",
            "analysis_status_detail": [{"from_status": "not_analyzed", "to_status": "analyzed", "timestamp": "2026-11-03T10:00:00Z", "source": {"enterprise_version": None, "host_id": None, "service_name": None}}],
            "image_content": {"metadata": {"arch": None, "distro": None, "distro_version": None, "extended_support": None, "image_size": None, "layer_count": None}},
        }
        assert valid("images", {"items": [image]})

    @pytest.mark.parametrize("source_id", ["kubernetes_namespaces", "kubernetes_nodes"])
    def test_a_record_identified_by_id_is_valid_and_one_with_neither_name_is_not(self, source_id):
        record = {"name": "default", "labels": {}, "annotations": {}}
        assert valid(source_id, {"namespaces": [{**record, "id": "x", "cluster_name": "prod", "account_name": "acct"}]})
        assert valid(source_id, {"namespaces": [{**record, "uid": "x"}]})
        assert not valid(source_id, {"namespaces": [record]})


    def test_the_node_list_is_checked_under_the_key_the_instance_uses(self):
        """The file wraps the node list in ``namespaces``; a real instance sends ``nodes``. Its records are
        checked under either key, so the real key is not a way round the check."""
        record = {"name": "ip-10-0-1-2", "labels": {}, "annotations": {}}
        assert valid("kubernetes_nodes", {"nodes": [{**record, "id": "x"}]})
        assert not valid("kubernetes_nodes", {"nodes": [record]})
        assert not valid("kubernetes_nodes", {"nodes": [{**record, "id": 7}]})

    def test_the_pod_list_is_checked_under_the_key_the_instance_uses(self):
        record = {"id": "p1", "name": "p1", "account_name": "acct", "labels": {}, "annotations": {}}
        assert valid("kubernetes_pods", {"pods": [record]})
        assert not valid("kubernetes_pods", {"pods": [{**record, "labels": "not-a-map"}]})
        assert not valid("kubernetes_pods", {"pods": [{key: value for key, value in record.items() if key != "id"}]})

    def test_a_container_record_with_an_undeclared_last_seen_is_valid(self):
        record = {"id": "containerd://x", "name": "web", "pod_id": "p1", "account_name": "acct", "context": "prod/default", "image_tag": "registry.example/app:1", "image_digest": DIGEST, "last_seen": "2026-11-10T00:00:00Z"}
        assert valid("kubernetes_containers", {"containers": [record]})


@pytest.mark.django_db
class TestARun:
    def test_null_fields_no_longer_stop_the_scanner(self, secrets, monkeypatch):
        server = Instance(vulns=[vuln("CVE-2024-0001", annotation_status=None, annotation_uuid=None, suggested_fix_version=None)])
        server.images = [{"image_digest": DIGEST, "analysis_status": "analyzed", "image_content": {"metadata": {"arch": None, "distro": None, "distro_version": None, "extended_support": None, "image_size": None, "layer_count": None}}}]
        run_against(monkeypatch, server)
        (finding,) = findings().values()
        assert (finding.suggested_fix_version, finding.annotation_status, finding.annotation_uuid) == (None, None, None)
        assert AnchoreScanRun.objects.get().selftest_verdict == "pass"

    def test_namespaces_and_nodes_identified_by_id_are_written(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        server = cluster(with_kube_system=False)
        by_id = lambda record: {("id" if key == "uid" else key): value for key, value in record.items()}  # noqa: E731
        server.kubernetes["namespaces"] = ("namespaces", [by_id({"uid": "ns-default", "name": "default", "labels": {}, "annotations": {}}), by_id({"uid": SYSTEM_UID, "name": "kube-system", "labels": {}, "annotations": {}})])
        # The wrapper keys a real instance uses: nodes and pods, where the vendor's file says namespaces.
        server.kubernetes["nodes"] = ("nodes", [by_id(node())])
        server.kubernetes["pods"] = ("pods", [pod("p1"), pod("p-dns", namespace_uid=SYSTEM_UID)])
        server.kubernetes["containers"] = ("containers", [container("p1"), container("p-dns", "coredns", "prod/kube-system")])
        run_against(monkeypatch, server)
        namespace_type = get_model_class("computing_core__kubernetes_namespace")
        assert {(n.uid, n.name) for n in namespace_type.objects.all()} == {("ns-default", "default"), (SYSTEM_UID, "kube-system")}
        assert [n.uid for n in get_model_class("computing_core__kubernetes_node").objects.all()] == ["node-1"]
        (made,) = get_model_class("computing_core__kubernetes_cluster").objects.all()
        assert (made.realm, made.stable_id) == ("kube-system-uid", SYSTEM_UID)
