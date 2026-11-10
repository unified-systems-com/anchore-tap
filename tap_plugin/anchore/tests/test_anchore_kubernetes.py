"""The Kubernetes placement plan (req-anchore-inventory-kubernetes-*): pure, no grid and no request."""

from datetime import UTC, datetime, timedelta

from tap_plugin.anchore import kubernetes, scope

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
KEY = '["https://anchore.example:8228/v2","acct"]'
D1, D2 = ("sha256:" + c * 64 for c in "ab")


def ago(hours: float) -> str:
    return (NOW - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def container(pod: str, name: str = "web", context: str = "prod/default", digest: str = D1, **over) -> dict:
    return {"id": f"containerd://{pod}-{name}", "name": name, "pod_id": pod, "context": context, "image_tag": "registry.example/app:1", "image_digest": digest, **over}


def pod(uid: str, namespace: str = "ns-default", node: str | None = "node-1", hours: float = 1, **over) -> dict:
    record = {"id": uid, "name": f"{uid}-name", "labels": {"app": "web"}, "namespace_id": namespace, "last_seen": ago(hours), **over}
    if node is not None:
        record["node_id"] = node
    return record


NAMESPACES = [{"uid": "ns-default", "name": "default", "labels": {}}, {"uid": "5f4c1c9e-0b0a-4e1f-9c7d-1a2b3c4d5e6f", "name": "kube-system", "labels": {"k": "v"}}]
NODES = [{"uid": "node-1", "name": "ip-10-0-1-2", "labels": {"zone": "a"}}]
SYSTEM = [container("p-dns", "coredns", "prod/kube-system")]
SYSTEM_PODS = [pod("p-dns", namespace="5f4c1c9e-0b0a-4e1f-9c7d-1a2b3c4d5e6f")]


def settings(**over) -> scope.Settings:
    return scope.Settings(running_only=True, **over)


def planned(containers, pods, **over):
    return kubernetes.plan(containers, pods, NAMESPACES, NODES, settings(**over), NOW, KEY)


class TestChain:
    def test_a_container_leads_to_its_pod_namespace_node_and_cluster(self):
        got = planned([container("p1"), *SYSTEM], [pod("p1"), *SYSTEM_PODS])
        cluster = ("kube-system-uid", "5f4c1c9e-0b0a-4e1f-9c7d-1a2b3c4d5e6f")
        assert got.clusters == {cluster: {"realm": "kube-system-uid", "stable_id": "5f4c1c9e-0b0a-4e1f-9c7d-1a2b3c4d5e6f", "name": "prod"}}
        assert got.containers[("p1", "web")] == {"pod_uid": "p1", "name": "web", "container_id": "containerd://p1-web", "image_reference": "registry.example/app:1"}
        assert got.pods["p1"] == {"uid": "p1", "name": "p1-name", "labels": {"app": "web"}}
        assert got.namespaces["ns-default"] == {"uid": "ns-default", "name": "default", "labels": {}}
        assert got.nodes["node-1"] == {"uid": "node-1", "name": "ip-10-0-1-2", "labels": {"zone": "a"}}
        assert got.images[("p1", "web")] == D1
        assert ("RUNS_CONTAINER", "pod", "p1", "container", ("p1", "web")) in got.edges
        assert ("CONTAINS_POD", "namespace", "ns-default", "pod", "p1") in got.edges
        assert ("CONTAINS_NAMESPACE", "cluster", cluster, "namespace", "ns-default") in got.edges
        assert ("SCHEDULED_ON_NODE", "pod", "p1", "node", "node-1") in got.edges
        assert ("REGISTERS_NODE", "cluster", cluster, "node", "node-1") in got.edges

    def test_two_containers_in_one_pod_are_two_containers_and_one_pod(self):
        got = planned([container("p1", "web"), container("p1", "sidecar", digest=D2)], [pod("p1")])
        assert set(got.containers) == {("p1", "web"), ("p1", "sidecar")}
        assert list(got.pods) == ["p1"]

    def test_a_pod_not_yet_placed_has_no_node_edge(self):
        got = planned([container("p1")], [pod("p1", node=None)])
        assert got.nodes == {}
        assert not [e for e in got.edges if e[0] in ("SCHEDULED_ON_NODE", "REGISTERS_NODE")]

    def test_a_container_not_yet_started_has_no_runtime_id_and_one_without_a_digest_no_image(self):
        got = planned([container("p1", id="", image_digest="nginx:latest")], [pod("p1")])
        assert got.containers[("p1", "web")]["container_id"] is None
        assert got.images == {}

    def test_a_namespace_or_node_no_container_leads_to_is_not_written(self):
        got = planned([container("p1")], [pod("p1")])
        assert list(got.namespaces) == ["ns-default"]


class TestClusterIdentity:
    def test_without_kube_system_the_key_is_scoped_to_the_scanner(self):
        got = planned([container("p1")], [pod("p1")])
        ((realm, stable_id),) = got.clusters
        assert realm == "anchore-inventory"
        assert stable_id == '["[\\"https://anchore.example:8228/v2\\",\\"acct\\"]","prod"]'
        assert got.fallback_clusters == 1

    def test_two_scanners_with_a_cluster_of_one_name_get_two_keys(self):
        one = kubernetes.cluster_key("prod", None, KEY)
        two = kubernetes.cluster_key("prod", None, '["https://other.example/v2","acct"]')
        assert one != two and one[0] == two[0] == "anchore-inventory"

    def test_two_kube_system_uids_under_one_name_are_not_trusted(self):
        pods = [pod("p1"), pod("p-a", namespace="5f4c1c9e-0b0a-4e1f-9c7d-1a2b3c4d5e6f"), pod("p-b", namespace="ns-other-system")]
        got = planned([container("p1"), container("p-a", "dns", "prod/kube-system"), container("p-b", "dns", "prod/kube-system")], pods)
        assert {realm for realm, _ in got.clusters} == {"anchore-inventory"}

    def test_a_kube_system_context_over_another_namespace_does_not_key_the_cluster(self):
        """The context says kube-system; the pod's namespace is the one named default."""
        got = planned([container("p1", "dns", "prod/kube-system")], [pod("p1", namespace="ns-default")])
        assert {realm for realm, _ in got.clusters} == {"anchore-inventory"}

    def test_a_kube_system_namespace_anchore_does_not_list_does_not_key_the_cluster(self):
        got = planned([container("p1", "dns", "prod/kube-system")], [pod("p1", namespace="ns-unlisted")])
        assert {realm for realm, _ in got.clusters} == {"anchore-inventory"}

    def test_repository_prefixes_narrow_placement(self):
        """A container whose image is outside the repository prefixes is not written (req-anchore-scope-8)."""
        got = planned([container("p1", image_tag="other.example/app:1"), container("p2")], [pod("p1"), pod("p2")], repository_prefixes=("registry.example/",))
        assert set(got.containers) == {("p2", "web")} and set(got.pods) == {"p2"}
        assert got.out_of_scope == 1

    def test_a_container_with_no_image_reference_passes_no_repository_prefix(self):
        got = planned([container("p1", image_tag=None)], [pod("p1")], repository_prefixes=("registry.example/",))
        assert not got.containers and got.out_of_scope == 1

    def test_the_identity_does_not_depend_on_the_scope(self):
        got = planned([container("p1", context="prod/payments"), *SYSTEM], [pod("p1"), *SYSTEM_PODS], context_prefixes=("prod/payments",))
        assert list(got.clusters) == [("kube-system-uid", "5f4c1c9e-0b0a-4e1f-9c7d-1a2b3c4d5e6f")]
        assert set(got.containers) == {("p1", "web")}

    def test_a_key_too_long_for_the_column_writes_no_cluster(self):
        assert kubernetes.cluster_key("prod", None, "k" * 300) is None
        got = kubernetes.plan([container("p1")], [pod("p1")], NAMESPACES, NODES, settings(), NOW, "k" * 300)
        assert got.clusters == {} and list(got.namespaces) == ["ns-default"]
        assert not [e for e in got.edges if e[1] == "cluster"]


class TestScopeAndFreshness:
    def test_a_context_prefix_selects_and_an_account_selects_nothing(self):
        records = [container("p1", context="prod/default"), container("p2", context="dev/default")]
        pods = [pod("p1"), pod("p2")]
        chosen = planned(records, pods, context_prefixes=("prod/",))
        assert set(chosen.containers) == {("p1", "web")} and chosen.out_of_scope == 1
        assert planned(records, pods, aws_account_ids=("123456789012",)).containers == {}

    def test_a_pod_not_seen_recently_is_not_running(self):
        got = planned([container("p1"), container("p2")], [pod("p1", hours=30), pod("p2")])
        assert set(got.containers) == {("p2", "web")} and got.stale == 1

    def test_a_container_without_a_name_a_context_or_a_listed_pod_is_counted(self):
        records = [container("p1", name=""), container("p1", context=None), container("p-missing")]
        got = planned(records, [pod("p1")])
        assert got.containers == {} and got.unusable == 3

    def test_labels_that_are_not_a_string_map_are_unobserved(self):
        got = planned([container("p1")], [pod("p1", labels={"replicas": 3})])
        assert got.pods["p1"]["labels"] is None


SYSTEM_UID = "5f4c1c9e-0b0a-4e1f-9c7d-1a2b3c4d5e6f"


class TestIdentifierNames:
    """A real instance returns a namespace's identifier as ``id`` where the vendor's file says ``uid``
    (req-anchore-inventory-kubernetes-13). Every identifier is read under either name."""

    def test_namespaces_and_nodes_keyed_by_id_are_found(self):
        namespaces = [{"id": "ns-default", "name": "default", "labels": {}, "cluster_name": "prod", "account_name": "acct"}, {"id": SYSTEM_UID, "name": "kube-system", "labels": {}}]
        nodes = [{"id": "node-1", "name": "ip-10-0-1-2", "labels": {}}]
        got = kubernetes.plan([container("p1"), *SYSTEM], [pod("p1"), *SYSTEM_PODS], namespaces, nodes, settings(), NOW, KEY)
        assert set(got.namespaces) == {"ns-default", SYSTEM_UID} and set(got.nodes) == {"node-1"}
        assert list(got.clusters) == [("kube-system-uid", SYSTEM_UID)]

    def test_the_vendors_name_wins_where_a_record_carries_both(self):
        namespaces = [{"uid": "ns-default", "id": "17", "name": "default", "labels": {}}]
        got = kubernetes.plan([container("p1")], [pod("p1")], namespaces, NODES, settings(), NOW, KEY)
        assert set(got.namespaces) == {"ns-default"}

    def test_pod_and_reference_identifiers_are_read_under_either_name(self):
        pods = [{"uid": "p1", "name": "p1-name", "labels": {}, "namespace_uid": "ns-default", "node_uid": "node-1", "last_seen": ago(1)}]
        containers = [{"id": "containerd://x", "name": "web", "pod_uid": "p1", "context": "prod/default", "image_tag": "registry.example/app:1", "image_digest": D1}]
        got = planned(containers, pods)
        assert set(got.containers) == {("p1", "web")} and set(got.namespaces) == {"ns-default"} and set(got.nodes) == {"node-1"}

    def test_a_kube_system_identifier_that_is_not_a_kubernetes_uid_does_not_key_the_cluster(self):
        """An instance could return its own row id under ``id``; only a UUID is a namespace UID."""
        namespaces = [{"id": "ns-default", "name": "default", "labels": {}}, {"id": "42", "name": "kube-system", "labels": {}}]
        got = kubernetes.plan([container("p1"), container("p-dns", "coredns", "prod/kube-system")], [pod("p1"), pod("p-dns", namespace="42")], namespaces, NODES, settings(), NOW, KEY)
        assert {realm for realm, _ in got.clusters} == {"anchore-inventory"}
        assert "42" in got.namespaces
