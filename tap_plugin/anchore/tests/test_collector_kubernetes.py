"""The Kubernetes objects end to end against a canned instance (req-anchore-inventory-kubernetes-*).

Written into computing_core's Kubernetes types through the real GRIFT importer. The payloads are
spec-derived from Anchore's OpenAPI file (2.20.0), not recorded from an instance.
"""

import json

import pytest
import tap_plugin.anchore.models as anchore  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models as compliance  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration
from tap_plugin.computing_core.models.host import Host

from tap_grid.models import Edge
from tap_grid.registry import get_model_class
from tap_plugin.anchore.tests.fakes import response
from tap_plugin.anchore.tests.test_collector_run import DIGEST, KEY, OTHER, no_sockets, run_against  # noqa: F401 — no_sockets is autouse
from tap_plugin.anchore.tests.test_collector_scope import configure, latest_run, not_read, seen, two_images

TYPES = {kind: f"computing_core__kubernetes_{kind}" for kind in ("cluster", "namespace", "node", "pod", "container")}


def namespace(uid: str, name: str) -> dict:
    return {"uid": uid, "name": name, "labels": {"team": "platform"}, "annotations": {"secret-ish": "do-not-store"}}


def node(uid: str = "node-1", name: str = "ip-10-0-1-2") -> dict:
    return {"uid": uid, "name": name, "labels": {"zone": "a"}, "annotations": {}}


def pod(uid: str, namespace_uid: str = "ns-default", node_uid: str | None = "node-1", hours_ago: float = 1) -> dict:
    record = {"id": uid, "name": f"{uid}-name", "account_name": "acct", "labels": {"app": "web"}, "annotations": {}, "namespace_id": namespace_uid, "last_seen": seen(hours_ago)}
    if node_uid is not None:
        record["node_id"] = node_uid
    return record


def container(pod_uid: str, name: str = "web", context: str = "prod/default", digest: str = DIGEST, runtime_id: str | None = None) -> dict:
    return {"id": runtime_id if runtime_id is not None else f"containerd://{pod_uid}-{name}", "name": name, "pod_id": pod_uid, "account_name": "acct", "context": context, "image_tag": "registry.example/app:1", "image_digest": digest}


def cluster(with_kube_system: bool = True):
    instance = two_images()
    namespaces, pods, containers = [namespace("ns-default", "default")], [pod("p1")], [container("p1")]
    if with_kube_system:
        namespaces.append(namespace("5f4c1c9e-0b0a-4e1f-9c7d-1a2b3c4d5e6f", "kube-system"))
        pods.append(pod("p-dns", namespace_uid="5f4c1c9e-0b0a-4e1f-9c7d-1a2b3c4d5e6f"))
        containers.append(container("p-dns", "coredns", "prod/kube-system", digest=OTHER))
    instance.kubernetes = {"namespaces": ("namespaces", namespaces), "nodes": ("namespaces", [node()]), "pods": ("namespaces", pods), "containers": ("containers", containers)}
    return instance


def all_of(kind: str):
    return list(get_model_class(TYPES[kind]).objects.all())


def edge_pairs(slug: str) -> set[tuple[str, str]]:
    return {(e.from_entity.name, e.to_entity.name) for e in Edge.objects.filter(edge_type=slug)}


@pytest.mark.django_db
class TestKubernetes:
    def test_the_chain_is_written(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        run_against(monkeypatch, cluster())
        (made_cluster,) = all_of("cluster")
        assert (made_cluster.realm, made_cluster.stable_id, made_cluster.name) == ("kube-system-uid", "5f4c1c9e-0b0a-4e1f-9c7d-1a2b3c4d5e6f", "prod")
        assert {(n.uid, n.name) for n in all_of("namespace")} == {("ns-default", "default"), ("5f4c1c9e-0b0a-4e1f-9c7d-1a2b3c4d5e6f", "kube-system")}
        assert {(p.uid, p.name, json.dumps(p.labels)) for p in all_of("pod")} == {("p1", "p1-name", '{"app": "web"}'), ("p-dns", "p-dns-name", '{"app": "web"}')}
        (made_node,) = all_of("node")
        assert (made_node.uid, made_node.name, made_node.labels) == ("node-1", "ip-10-0-1-2", {"zone": "a"})
        # Anchore's node record carries no kubelet version field, so they stay unobserved.
        assert made_node.kernel_version is None and made_node.kubelet_version is None and made_node.architecture is None
        web = get_model_class(TYPES["container"]).objects.get(pod_uid="p1", name="web")
        assert (web.container_id, web.image_reference) == ("containerd://p1-web", "registry.example/app:1")
        assert "create:kubernetes" in latest_run().scopes_read

    def test_every_edge_of_the_chain_and_the_node_host(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        run_against(monkeypatch, cluster())
        assert edge_pairs("CONTAINS_NAMESPACE__computing_core") == {("prod", "default"), ("prod", "kube-system")}
        assert edge_pairs("CONTAINS_POD__computing_core") == {("default", "p1-name"), ("kube-system", "p-dns-name")}
        assert edge_pairs("RUNS_CONTAINER__computing_core") == {("p1-name", "web"), ("p-dns-name", "coredns")}
        assert edge_pairs("REGISTERS_NODE__computing_core") == {("prod", "ip-10-0-1-2")}
        assert edge_pairs("SCHEDULED_ON_NODE__computing_core") == {("p1-name", "ip-10-0-1-2"), ("p-dns-name", "ip-10-0-1-2")}
        machine = Host.objects.get(realm="kubernetes-node-uid", stable_id="node-1")
        assert (machine.name, machine.kind) == ("ip-10-0-1-2", None)
        assert edge_pairs("BACKED_BY_HOST__computing_core") == {("ip-10-0-1-2", "ip-10-0-1-2")}
        runs = {(e.from_entity.name, e.to_entity_id) for e in Edge.objects.filter(edge_type="RUNS_IMAGE__computing_core")}
        assert runs == {("web", Host.objects.get(realm="oci-digest", stable_id=DIGEST).entity_id), ("coredns", Host.objects.get(realm="oci-digest", stable_id=OTHER).entity_id)}

    def test_no_annotation_is_stored_anywhere(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        run_against(monkeypatch, cluster())
        for kind in TYPES:
            model = get_model_class(TYPES[kind])
            assert "annotations" not in model.FIELD_CRUD_SCHEMA
        assert all(n.labels == {"team": "platform"} for n in all_of("namespace"))

    def test_without_kube_system_the_cluster_is_keyed_to_the_scanner(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        run_against(monkeypatch, cluster(with_kube_system=False))
        (made,) = all_of("cluster")
        assert made.realm == "anchore-inventory"
        assert json.loads(made.stable_id) == [KEY, "prod"]
        assert made.name == "prod"

    def test_create_kubernetes_false_writes_nothing(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True}, create={"kubernetes": False})
        instance = cluster()
        run_against(monkeypatch, instance)
        assert [len(all_of(kind)) for kind in TYPES] == [0, 0, 0, 0, 0]
        assert not [c for c in instance.transport.calls if "/kubernetes-" in str(c.url)]

    def test_a_second_run_writes_no_second_object_and_follows_a_restart(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        instance = cluster()
        run_against(monkeypatch, instance)
        wrapper, rows = instance.kubernetes["containers"]
        instance.kubernetes["containers"] = (wrapper, [container("p1", runtime_id="containerd://restarted"), *rows[1:]])
        run_against(monkeypatch, instance)
        assert [len(all_of(kind)) for kind in TYPES] == [1, 2, 1, 2, 2]
        assert get_model_class(TYPES["container"]).objects.get(pod_uid="p1", name="web").container_id == "containerd://restarted"
        assert Host.objects.filter(realm="kubernetes-node-uid").count() == 1
        assert Edge.objects.filter(edge_type="RUNS_CONTAINER__computing_core").count() == 2

    def test_a_context_prefix_limits_what_is_written_and_not_who_the_cluster_is(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True, "context_prefixes": ["prod/default"]})
        run_against(monkeypatch, cluster())
        assert [c.name for c in all_of("container")] == ["web"]
        assert [n.name for n in all_of("namespace")] == ["default"]
        assert [(c.realm, c.stable_id) for c in all_of("cluster")] == [("kube-system-uid", "5f4c1c9e-0b0a-4e1f-9c7d-1a2b3c4d5e6f")]

    def test_a_pod_not_seen_recently_is_not_written(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True}, inventory_max_age_hours=6)
        instance = cluster(with_kube_system=False)
        instance.kubernetes["pods"] = ("namespaces", [pod("p1", hours_ago=30)])
        run_against(monkeypatch, instance)
        assert [len(all_of(kind)) for kind in TYPES] == [0, 0, 0, 0, 0]

    def test_the_natural_wrapper_keys_are_accepted_too(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        instance = cluster()
        instance.kubernetes["nodes"] = ("nodes", instance.kubernetes["nodes"][1])
        instance.kubernetes["pods"] = ("pods", instance.kubernetes["pods"][1])
        run_against(monkeypatch, instance)
        assert len(all_of("pod")) == 2 and len(all_of("node")) == 1

    def test_one_unreadable_list_writes_nothing(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        instance = cluster()
        instance.transport.routes["/kubernetes-pods"] = lambda r: response(500, {"detail": "boom"})
        run_against(monkeypatch, instance)
        assert [len(all_of(kind)) for kind in TYPES] == [0, 0, 0, 0, 0]
        assert "no Kubernetes object was written" in not_read(latest_run())["create:kubernetes"]

    def test_a_pod_not_yet_placed_is_written_without_a_node(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        instance = cluster(with_kube_system=False)
        instance.kubernetes["pods"] = ("namespaces", [pod("p1", node_uid=None)])
        run_against(monkeypatch, instance)
        assert len(all_of("pod")) == 1 and all_of("node") == []
        assert Edge.objects.filter(edge_type="SCHEDULED_ON_NODE__computing_core").count() == 0
