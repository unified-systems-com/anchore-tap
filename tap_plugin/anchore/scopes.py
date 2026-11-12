"""Scope dimensions: which image, cluster and namespace a node belongs to (req-anchore-dimensions-5, -6).

A popular base image is pointed at by every finding, annotation and verdict about it; a namespace
by every pod in it. Reaching "everything about this image" or "everything in this namespace" by
walking those edges is slow and makes the image or namespace a super-node. So the nodes also carry
the scope as a dimension, whose value is the scoping object's own natural key exactly as the grid
stores it. The edges stay.

Pure: this module takes the nodes and edges a run has staged, in place, and a function that
composes a natural key. It reads no grid and imports no Django. A dimension is stamped only when
it is declared on the grid, since a key with no Dimension node is refused; one that is not
declared is left off, which the grid reads as unasserted.
"""

from collections.abc import Callable, Iterable, Mapping
from typing import Any

HOST = "tap.computing.host"
CLUSTER = "tap.computing.kubernetes_cluster"
NAMESPACE = "tap.computing.kubernetes_namespace"
ALL = frozenset({HOST, CLUSTER, NAMESPACE})

HOST_TYPE = "computing_core__host"
CLUSTER_TYPE = "computing_core__kubernetes_cluster"
NAMESPACE_TYPE = "computing_core__kubernetes_namespace"
POD_TYPE = "computing_core__kubernetes_pod"
CONTAINER_TYPE = "computing_core__kubernetes_container"

OWN_TYPE_PREFIX = "anchore__"
IMAGE_SCHEME = "oci-digest"

#: Composes a type's natural key from field values, or None when it cannot (a hole, an older grid).
Compose = Callable[[str, Mapping[str, Any]], str | None]


def image_digest_of(node: Mapping[str, Any]) -> str | None:
    """The digest of the image an Anchore-owned node is about, or None when it is about no one image.

    A finding and a VEX annotation say what they are scoped to; only the image scope names an
    image. The image record, a policy evaluation and a running-image observation always do.
    """
    fields = node["node"]
    kind = node["entity"]["entity_type"].removeprefix(OWN_TYPE_PREFIX)
    if kind == "anchore_finding":
        digest = fields.get("target_key") if fields.get("target_kind") == "image" else None
    elif kind == "anchore_vex_annotation":
        digest = fields.get("scope_id") if fields.get("scope_kind") == "image" else None
    elif kind in ("anchore_image", "anchore_policy_evaluation", "anchore_runtime_image"):
        digest = fields.get("image_digest")
    else:
        digest = None
    return digest if isinstance(digest, str) and digest.startswith("sha256:") else None


def stamp(nodes: Iterable[dict[str, Any]], edges: Iterable[Mapping[str, Any]], declared: frozenset[str] | set[str], compose: Compose, host_key: Callable[[str], Mapping[str, Any]]) -> dict[str, int]:
    """Add the scope dimensions to the staged nodes, in place; returns how many nodes got each.

    ``host_key`` gives the image host's key fields for a digest. The Kubernetes scopes are read
    from the staged containment edges themselves, so a pod is scoped to the namespace the run
    says contains it and to no other; a pod whose namespace the run did not write gets neither.
    """
    nodes = list(nodes)
    counts = dict.fromkeys(sorted(ALL), 0)

    def put(node: dict[str, Any], key: str, value: str | None) -> None:
        if value and key in declared:
            node["entity"]["dimensions"][key] = value
            counts[key] += 1

    for node in nodes:
        if node["entity"]["entity_type"].startswith(OWN_TYPE_PREFIX):
            digest = image_digest_of(node)
            if digest is not None:
                put(node, HOST, compose(HOST_TYPE, host_key(digest)))

    by_ref = {node["entity"].get("ref"): node for node in nodes}
    parent: dict[str, dict[str, str]] = {"CONTAINS_NAMESPACE__computing_core": {}, "CONTAINS_POD__computing_core": {}, "RUNS_CONTAINER__computing_core": {}}
    for edge in edges:
        body = edge["edge"]
        if body.get("edge_type") in parent and body.get("from_ref") and body.get("to_ref"):
            parent[body["edge_type"]][body["to_ref"]] = body["from_ref"]

    def key_of(ref: str | None, entity_type: str) -> str | None:
        node = by_ref.get(ref)
        return compose(entity_type, node["node"]) if node is not None and node["entity"]["entity_type"] == entity_type else None

    for ref, node in by_ref.items():
        entity_type = node["entity"]["entity_type"]
        if entity_type == NAMESPACE_TYPE:
            namespace_ref = ref
        elif entity_type == POD_TYPE:
            namespace_ref = parent["CONTAINS_POD__computing_core"].get(ref)
        elif entity_type == CONTAINER_TYPE:
            namespace_ref = parent["CONTAINS_POD__computing_core"].get(parent["RUNS_CONTAINER__computing_core"].get(ref))
        else:
            continue
        put(node, NAMESPACE, key_of(namespace_ref, NAMESPACE_TYPE))
        put(node, CLUSTER, key_of(parent["CONTAINS_NAMESPACE__computing_core"].get(namespace_ref), CLUSTER_TYPE))
    return counts
