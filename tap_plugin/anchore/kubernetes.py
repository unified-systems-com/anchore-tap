"""Kubernetes placement from Anchore's runtime inventory: what a run writes (req-anchore-inventory-kubernetes).

Pure: given the four lists Anchore returned and the operator's settings, decide which cluster,
namespace, node, pod and container objects a run writes and which edges join them. This module
makes no request, reads no grid and imports no Django. Everything Anchore-shaped is taken from
the vendor's OpenAPI file (2.20.0) and not from a recorded response.

What that file says, and what follows from it:

- Only a container record carries a ``context`` (the cluster name, a slash, and the namespace).
  Namespace, node and pod records name no cluster. So the walk starts from containers: a
  container leads to its pod, the pod to its namespace and node, and the container's context
  names the cluster. A namespace or node no in-scope container leads to is not written.
- A container record carries no ``last_seen``; a pod does. A container counts as running when
  its pod was seen within the window.
- A node record carries a uid, a name and labels, and none of the kubelet's version fields.
"""

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from tap_plugin.anchore.scope import DIGEST, Settings, is_fresh

#: The cluster realms (req-computing-core-kubernetes, req-anchore-inventory-kubernetes-7).
REALM_KUBE_SYSTEM = "kube-system-uid"
REALM_FALLBACK = "anchore-inventory"
#: The realm of the host row behind a node.
REALM_NODE_HOST = "kubernetes-node-uid"
KUBE_SYSTEM = "kube-system"
#: Stands in a cluster's uid set for a kube-system claim the namespace list does not bear out.
UNCONFIRMED = ""

#: Column limits of the computing_core types; a value that does not fit cannot be written.
_MAX_UID = 64
_MAX_NAME = 255
_MAX_KEY = 255
_MAX_REFERENCE = 2048


def _text(value: Any, limit: int) -> str | None:
    """A non-empty string that fits its column, else None."""
    return value if isinstance(value, str) and 0 < len(value) <= limit else None


def _labels(value: Any) -> dict[str, str] | None:
    """A Kubernetes label map, string keys to string values; None when the record held no such map."""
    if isinstance(value, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
        return dict(value)
    return None


def cluster_of(context: Any) -> str | None:
    """The cluster name in a container's context: the text before its first slash."""
    if not isinstance(context, str):
        return None
    return _text(context.split("/", 1)[0], _MAX_NAME)


@dataclass
class Plan:
    """The Kubernetes objects a run writes, each keyed by its natural key, and the edges between them."""

    #: (realm, stable_id) -> fields
    clusters: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    #: uid -> fields
    namespaces: dict[str, dict[str, Any]] = field(default_factory=dict)
    nodes: dict[str, dict[str, Any]] = field(default_factory=dict)
    pods: dict[str, dict[str, Any]] = field(default_factory=dict)
    #: (pod_uid, name) -> fields
    containers: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    #: (pod_uid, name) -> image digest, for the containers whose digest can name an image host
    images: dict[tuple[str, str], str] = field(default_factory=dict)
    #: (edge slug, source kind, source key, target kind, target key)
    edges: list[tuple[str, str, Any, str, Any]] = field(default_factory=list)
    #: Containers whose pod was not seen within the window, or has no readable last_seen.
    stale: int = 0
    #: Containers the scope's context prefixes leave out.
    out_of_scope: int = 0
    #: Containers that cannot be written: no usable name, pod id or context, or a pod Anchore does not list.
    unusable: int = 0
    #: Clusters whose kube-system namespace was not reported, or was ambiguous, so the fallback realm was used.
    fallback_clusters: int = 0


def kube_system_uids(containers: Iterable[Mapping[str, Any]], pods: Mapping[str, Mapping[str, Any]], namespaces: Mapping[str, Mapping[str, Any]]) -> dict[str, set[str]]:
    """For each cluster name, the uids of the namespace its ``<cluster>/kube-system`` containers' pods are in.

    One uid is the cluster's identifier. None means the namespace was not inventoried; more than
    one means two clusters share a configured name, and neither uid can be trusted to name this one.
    A uid counts only when the namespace list holds it under the name ``kube-system``: a context
    that says kube-system over a pod in some other namespace, or in one Anchore does not list,
    must not key the cluster, and its presence leaves the cluster's other uids untrusted too.
    """
    found: dict[str, set[str]] = {}
    for container in containers:
        context = container.get("context")
        cluster = cluster_of(context)
        if cluster is None or context != f"{cluster}/{KUBE_SYSTEM}":
            continue
        pod = pods.get(container.get("pod_id"))  # type: ignore[arg-type]
        uid = _text(pod.get("namespace_id"), _MAX_UID) if pod is not None else None
        if uid is None:
            continue
        record = namespaces.get(uid)
        confirmed = record is not None and record.get("name") == KUBE_SYSTEM
        # An unconfirmed uid is evidence against the cluster's identity, not silence: it stands
        # as the empty marker, which is never a key.
        found.setdefault(cluster, set()).add(uid if confirmed else UNCONFIRMED)
    return found


def cluster_key(cluster: str, system_uids: set[str] | None, scanner_key: str) -> tuple[str, str] | None:
    """The cluster's ``(realm, stable_id)``, or None when neither form fits the key column.

    The kube-system uid where exactly one was reported. Otherwise the scanner key and the
    configured name together, as a compact JSON array, under this plugin's own realm: a bare
    name under a shared realm would merge two instances' clusters called ``prod``.
    """
    if system_uids is not None and len(system_uids) == 1 and UNCONFIRMED not in system_uids:
        return REALM_KUBE_SYSTEM, next(iter(system_uids))
    stable_id = json.dumps([scanner_key, cluster], separators=(",", ":"), ensure_ascii=False)
    return (REALM_FALLBACK, stable_id) if len(stable_id) <= _MAX_KEY else None


def plan(
    containers: Iterable[Mapping[str, Any]],
    pods: Iterable[Mapping[str, Any]],
    namespaces: Iterable[Mapping[str, Any]],
    nodes: Iterable[Mapping[str, Any]],
    settings: Settings,
    now: datetime,
    scanner_key: str,
) -> Plan:
    """The Kubernetes objects and edges to write for the containers that are in scope and running.

    In scope: every container when no running selector is set, else those whose context begins
    with a listed prefix (an AWS account selector selects no Kubernetes container). Running: the
    container's pod was seen within the window. ``repository_prefixes`` narrows which images'
    findings are read and plays no part here, as it plays none in the ECS placement.
    """
    out = Plan()
    containers = [c for c in containers if isinstance(c, Mapping)]
    pod_by_id = {p["id"]: p for p in pods if isinstance(p, Mapping) and isinstance(p.get("id"), str)}
    namespace_by_uid = {n["uid"]: n for n in namespaces if isinstance(n, Mapping) and isinstance(n.get("uid"), str)}
    node_by_uid = {n["uid"]: n for n in nodes if isinstance(n, Mapping) and isinstance(n.get("uid"), str)}
    system = kube_system_uids(containers, pod_by_id, namespace_by_uid)
    edges: set[tuple[str, str, Any, str, Any]] = set()
    fallback: set[str] = set()
    for container in containers:
        context = container.get("context")
        if settings.has_running_selector and not (isinstance(context, str) and any(context.startswith(p) for p in settings.context_prefixes)):
            out.out_of_scope += 1
            continue
        name, pod_uid, cluster = _text(container.get("name"), _MAX_NAME), _text(container.get("pod_id"), _MAX_UID), cluster_of(context)
        pod = pod_by_id.get(pod_uid) if pod_uid is not None else None
        if name is None or cluster is None or pod is None:
            out.unusable += 1
            continue
        if not is_fresh(pod.get("last_seen"), now, settings.inventory_max_age_hours):
            out.stale += 1
            continue
        key = (pod_uid, name)
        runtime_id = _text(container.get("id"), _MAX_NAME)
        out.containers[key] = {"pod_uid": pod_uid, "name": name, "container_id": runtime_id, "image_reference": _text(container.get("image_tag"), _MAX_REFERENCE)}
        digest = container.get("image_digest")
        if isinstance(digest, str) and DIGEST.fullmatch(digest):
            out.images[key] = digest
        out.pods[pod_uid] = {"uid": pod_uid, "name": _text(pod.get("name"), _MAX_NAME) or "", "labels": _labels(pod.get("labels"))}
        edges.add(("RUNS_CONTAINER", "pod", pod_uid, "container", key))
        cluster_id = cluster_key(cluster, system.get(cluster), scanner_key)
        if cluster_id is not None:
            out.clusters[cluster_id] = {"realm": cluster_id[0], "stable_id": cluster_id[1], "name": cluster}
            if cluster_id[0] == REALM_FALLBACK:
                fallback.add(cluster)
        namespace_uid = _text(pod.get("namespace_id"), _MAX_UID)
        if namespace_uid is not None and namespace_uid in namespace_by_uid:
            record = namespace_by_uid[namespace_uid]
            out.namespaces[namespace_uid] = {"uid": namespace_uid, "name": _text(record.get("name"), _MAX_NAME) or "", "labels": _labels(record.get("labels"))}
            edges.add(("CONTAINS_POD", "namespace", namespace_uid, "pod", pod_uid))
            if cluster_id is not None:
                edges.add(("CONTAINS_NAMESPACE", "cluster", cluster_id, "namespace", namespace_uid))
        node_uid = _text(pod.get("node_id"), _MAX_UID)
        if node_uid is not None and node_uid in node_by_uid:
            record = node_by_uid[node_uid]
            out.nodes[node_uid] = {"uid": node_uid, "name": _text(record.get("name"), _MAX_NAME) or "", "labels": _labels(record.get("labels"))}
            edges.add(("SCHEDULED_ON_NODE", "pod", pod_uid, "node", node_uid))
            if cluster_id is not None:
                edges.add(("REGISTERS_NODE", "cluster", cluster_id, "node", node_uid))
    out.fallback_clusters = len(fallback)
    out.edges = sorted(edges, key=repr)
    return out
