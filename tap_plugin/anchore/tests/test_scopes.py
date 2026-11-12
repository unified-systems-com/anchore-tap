"""Scope dimensions on staged nodes, and end to end against the grid's own stored keys (req-anchore-dimensions-5, -6)."""

import pytest
import tap_plugin.anchore.models as anchore  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models as compliance  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration

from tap_plugin.anchore import scopes

D = "sha256:" + "a" * 64


def node(ref: str, entity_type: str, **fields) -> dict:
    return {"entity": {"ref": ref, "entity_type": entity_type, "name": ref, "dimensions": {}}, "node": fields}


def edge(slug: str, source: str, target: str) -> dict:
    return {"entity": {"ref": f"{source}>{target}", "entity_type": "edge", "name": slug, "dimensions": {}}, "edge": {"edge_type": slug, "from_ref": source, "to_ref": target, "properties": {}}}


def compose(entity_type: str, values) -> str | None:
    """A stand-in for the grid's composer: the fields a type is keyed by, joined."""
    keyed = {scopes.HOST_TYPE: ("realm", "stable_id"), scopes.CLUSTER_TYPE: ("realm", "stable_id"), scopes.NAMESPACE_TYPE: ("uid",)}[entity_type]
    parts = [values.get(name) for name in keyed]
    return None if any(part is None for part in parts) else "|".join(parts)


def host_key(digest: str) -> dict:
    return {"realm": "oci-digest", "stable_id": digest}


def staged():
    nodes = [
        node("c", scopes.CLUSTER_TYPE, realm="kube-system-uid", stable_id="cl-1", name="prod"),
        node("ns", scopes.NAMESPACE_TYPE, uid="ns-1", name="default"),
        node("p", scopes.POD_TYPE, uid="p-1"),
        node("k", scopes.CONTAINER_TYPE, pod_uid="p-1", name="web"),
        node("orphan", scopes.POD_TYPE, uid="p-2"),
        node("kn", "computing_core__kubernetes_node", uid="n-1"),
        node("f", "anchore__anchore_finding", target_kind="image", target_key=D),
        node("fs", "anchore__anchore_finding", target_kind="source", target_key="src-1"),
        node("x", "anchore__anchore_vex_annotation", scope_kind="image", scope_id=D),
        node("xv", "anchore__anchore_vex_annotation", scope_kind="app_version", scope_id="v-1"),
        node("i", "anchore__anchore_image", image_digest=D),
        node("e", "anchore__anchore_policy_evaluation", image_digest=D),
        node("r", "anchore__anchore_runtime_image", image_digest=D),
        node("s", "anchore__anchore_scanner", scanner_key="k"),
        node("h", scopes.HOST_TYPE, realm="oci-digest", stable_id=D),
    ]
    edges = [edge("CONTAINS_NAMESPACE__computing_core", "c", "ns"), edge("CONTAINS_POD__computing_core", "ns", "p"), edge("RUNS_CONTAINER__computing_core", "p", "k")]
    return nodes, edges


def dimensions(nodes) -> dict[str, dict]:
    return {n["entity"]["ref"]: n["entity"]["dimensions"] for n in nodes}


class TestStamp:
    def test_each_node_about_an_image_carries_the_image_hosts_key(self):
        nodes, edges = staged()
        counts = scopes.stamp(nodes, edges, scopes.ALL, compose, host_key)
        got = dimensions(nodes)
        for ref in ("f", "x", "i", "e", "r"):
            assert got[ref] == {scopes.HOST: f"oci-digest|{D}"}, ref
        assert counts[scopes.HOST] == 5

    def test_a_node_about_no_one_image_carries_no_host_scope(self):
        nodes, edges = staged()
        scopes.stamp(nodes, edges, scopes.ALL, compose, host_key)
        got = dimensions(nodes)
        assert got["fs"] == got["xv"] == got["s"] == {}
        # The host is the scope; it is not scoped to itself, and a shared node gets no image scope.
        assert got["h"] == {}

    def test_a_pod_and_its_container_carry_their_namespace_and_cluster(self):
        nodes, edges = staged()
        scopes.stamp(nodes, edges, scopes.ALL, compose, host_key)
        got = dimensions(nodes)
        both = {scopes.NAMESPACE: "ns-1", scopes.CLUSTER: "kube-system-uid|cl-1"}
        assert got["ns"] == got["p"] == got["k"] == both
        assert got["c"] == got["kn"] == {}

    def test_a_pod_whose_namespace_the_run_did_not_write_gets_neither(self):
        nodes, edges = staged()
        scopes.stamp(nodes, edges, scopes.ALL, compose, host_key)
        assert dimensions(nodes)["orphan"] == {}

    def test_a_namespace_with_no_cluster_edge_carries_only_itself(self):
        nodes, edges = staged()
        scopes.stamp(nodes, edges[1:], scopes.ALL, compose, host_key)
        got = dimensions(nodes)
        assert got["ns"] == got["p"] == got["k"] == {scopes.NAMESPACE: "ns-1"}

    def test_a_dimension_that_is_not_declared_is_not_stamped(self):
        nodes, edges = staged()
        counts = scopes.stamp(nodes, edges, {scopes.NAMESPACE}, compose, host_key)
        got = dimensions(nodes)
        assert got["f"] == {} and got["p"] == {scopes.NAMESPACE: "ns-1"}
        assert counts == {scopes.HOST: 0, scopes.CLUSTER: 0, scopes.NAMESPACE: 3}

    def test_a_key_that_cannot_be_composed_is_not_stamped(self):
        nodes, edges = staged()
        scopes.stamp(nodes, edges, scopes.ALL, lambda entity_type, values: None, host_key)
        assert all(d == {} for d in dimensions(nodes).values())

    def test_a_malformed_digest_names_no_image(self):
        assert scopes.image_digest_of(node("f", "anchore__anchore_finding", target_kind="image", target_key="latest")) is None


@pytest.mark.django_db
class TestAgainstTheGrid:
    """The stamped value is the scoping node's key exactly as the grid stored it."""

    def declare(self, *names):
        from tap_grid.services import create_node

        for name in names:
            assert create_node("dimension", {"name": name, "description": name}).success

    def spine(self, model):
        from tap_grid.models import Entity

        return Entity.objects.get(pk=model.entity_id).natural_key

    def test_the_image_scope_equals_the_image_hosts_stored_key(self, tmp_path, monkeypatch):
        from tap_plugin.computing_core.models.host import Host

        from tap_plugin.anchore.models.finding import AnchoreFinding
        from tap_plugin.anchore.models.image import AnchoreImage
        from tap_plugin.anchore.tests.test_collector_run import DIGEST, Instance, run_against
        from tap_plugin.anchore.tests.test_collector_scope import configure

        self.declare(*scopes.ALL)
        configure(tmp_path, monkeypatch, {"running_only": False})
        run_against(monkeypatch, Instance())
        stored = self.spine(Host.objects.get(stable_id=DIGEST))
        assert stored and "|" in stored
        for model in (AnchoreFinding, AnchoreImage):
            rows = list(model.objects.all())
            assert rows, model
            for row in rows:
                digest = getattr(row, "target_key", None) or row.image_digest
                assert row.entity.dimensions[scopes.HOST] == self.spine(Host.objects.get(stable_id=digest))

    def test_the_kubernetes_scopes_equal_the_stored_keys(self, tmp_path, monkeypatch):
        from tap_grid.registry import get_model_class
        from tap_plugin.anchore.tests.test_collector_kubernetes import cluster
        from tap_plugin.anchore.tests.test_collector_run import run_against
        from tap_plugin.anchore.tests.test_collector_scope import configure

        self.declare(*scopes.ALL)
        configure(tmp_path, monkeypatch, {"running_only": True})
        run_against(monkeypatch, cluster())
        (made,) = get_model_class(scopes.CLUSTER_TYPE).objects.all()
        namespaces = {n.uid: n for n in get_model_class(scopes.NAMESPACE_TYPE).objects.all()}
        pod = get_model_class(scopes.POD_TYPE).objects.get(uid="p1")
        container = get_model_class(scopes.CONTAINER_TYPE).objects.get(pod_uid="p1", name="web")
        expected = {scopes.CLUSTER: self.spine(made), scopes.NAMESPACE: self.spine(namespaces["ns-default"])}
        assert expected[scopes.NAMESPACE] == "ns-default"
        for row in (namespaces["ns-default"], pod, container):
            assert {k: v for k, v in row.entity.dimensions.items() if k in scopes.ALL} == expected, row

    def test_with_no_dimension_declared_nothing_is_stamped_and_the_run_says_so(self, tmp_path, monkeypatch):
        from tap_grid.models import Entity
        from tap_plugin.anchore.tests.test_collector_kubernetes import cluster
        from tap_plugin.anchore.tests.test_collector_run import run_against
        from tap_plugin.anchore.tests.test_collector_scope import configure

        configure(tmp_path, monkeypatch, {"running_only": True})
        collector = run_against(monkeypatch, cluster())
        assert not [e for e in Entity.objects.all() if scopes.ALL & set(e.dimensions)]
        (said,) = [m for m in collector.results["info"] if m["message_code"] == "SCOPE_DIMENSIONS"]
        assert said["message_data"]["not_declared"] == sorted(scopes.ALL)
