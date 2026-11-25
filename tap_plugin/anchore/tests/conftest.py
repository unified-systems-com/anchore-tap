"""Shared test scaffolding for the anchore plugin's suite."""

import pytest


def dimension_view(entity) -> dict:
    """An entity's dimensions as ``{name: value}``, whichever way the grid under test stores them.

    A grid from tap 0.3.4 or earlier stores that map directly. A later one keys it by Dimension
    node and wraps each value; its own ``view`` turns that back into names and values.
    """
    try:
        from tap_grid.dimension_names import view
    except ImportError:
        return dict(entity.dimensions or {})
    return view(entity.dimensions)


def needs_declared(*names: str) -> None:
    """Skip a test whose writes name a dimension the grid under test would refuse.

    A grid that requires declared dimensions takes its vocabulary from the installed plugins'
    seeds. A dependency pinned at a release older than its seed (aws_core before its account and
    region nodes, compliance_core before its own) cannot be written to on such a grid at all, so
    a test of that write has nothing to run against until the pin moves. On a grid that accepts
    any key this never skips.
    """
    from tap_plugin.anchore.collectors.anchore_collector import store

    missing = store.undeclared_dimensions(names)
    if missing:
        pytest.skip(f"the grid under test declares no Dimension node for {', '.join(missing)}; the pinned dependency ships no seed for it")


def vulnerability_dimensions_declared() -> None:
    """Skip unless the grid under test will accept a compliance_core vulnerability node."""
    from tap_grid.registry import get_model_class

    needs_declared(*get_model_class("compliance_core__compliance_vulnerability").DEFAULT_DIMENSIONS)


@pytest.fixture
def aws_dimensions_declared():
    """Skip unless the grid under test will accept the aws_core ECS nodes this plugin creates."""
    from tap_plugin.anchore.collectors.anchore_collector import store

    from tap_grid.registry import get_model_class

    names = set(store.aws_dimension_names().values())
    for entity_type in store.ECS_TYPES.values():
        names |= set(get_model_class(entity_type).DEFAULT_DIMENSIONS)
    needs_declared(*names)


#: The dimension that says whose numbering a host's or a cluster's stable_id comes from (computing_core 0.11).
HOST_TYPE = "tap.computing.host_type"
CLUSTER_TYPE = "tap.computing.kubernetes_cluster_type"


def hosts_of(host_type: str, stable_id: str | None = None):
    """The live hosts of one host type, and one identifier where given, found as core finds them."""
    from tap_plugin.computing_core.models.host import Host

    from tap_grid.natural_key import search

    if stable_id is not None:
        return search(Host.objects.all(), {f"dimension:{HOST_TYPE}": host_type, "stable_id": stable_id})
    return Host.objects.filter(entity__in=[h.entity for h in Host.objects.select_related("entity") if dimension_view(h.entity).get(HOST_TYPE) == host_type])


def host_of(host_type: str, stable_id: str):
    """The one live host of a host type and identifier."""
    return hosts_of(host_type, stable_id).get()


def type_of(row, dimension: str = HOST_TYPE):
    """A host's host type, or with ``CLUSTER_TYPE`` a cluster's cluster type, as its dimensions hold it."""
    row.entity.refresh_from_db()
    return dimension_view(row.entity).get(dimension)
