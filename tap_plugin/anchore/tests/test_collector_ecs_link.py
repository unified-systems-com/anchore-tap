"""The ECS link: an Anchore ECS container joined to the aws_core container with its ARN (req-anchore-shared-1 to -4, req-anchore-inventory-ecs-*).

These run against the real aws_core type, which the CI stack installs for this purpose. The
payloads are spec-derived from Anchore's OpenAPI file (2.20.0), not recorded from an instance.
"""

import pytest
import tap_plugin.anchore.models as anchore  # noqa: F401 — trigger model registration
import tap_plugin.aws_core.models as aws  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models as compliance  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration
from tap_plugin.computing_core.models.host import Host

from tap_grid.models import Edge, Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_node
from tap_plugin.anchore.collectors.anchore_collector import store
from tap_plugin.anchore.tests.test_collector_run import DIGEST, OTHER, no_sockets, run_against  # noqa: F401 — no_sockets is autouse
from tap_plugin.anchore.tests.test_collector_scope import configure, container, item, latest_run, not_read, two_images

ACCOUNT = "123456789012"
ECS = "aws_core__aws_ecs_container"


def on_grid(arn: str, name: str = "web"):
    result = create_node(ECS, {"name": name, "container_arn": arn, "image": "registry.example/app:1", "last_status": "RUNNING"})
    assert result.success, result.errors
    return get_model_class(ECS).objects.get(entity=Entity.objects.get(pk=result.entity_id))


def instance_with(*containers: dict):
    instance = two_images()
    instance.inventory = [item(c["context"], c["image_digest"], kind="ecs") for c in containers]
    instance.ecs = list(containers)
    return instance


def runs_image_edges():
    return list(Edge.objects.filter(edge_type="RUNS_IMAGE__computing_core"))


@pytest.mark.django_db
class TestEcsLink:
    def test_a_container_on_the_grid_is_joined_to_its_image_and_not_written(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        record = container(ACCOUNT, "ctx-a", DIGEST)
        node = on_grid(record["arn"])
        version = Entity.objects.get(pk=node.entity_id).version
        run_against(monkeypatch, instance_with(record))
        edge = runs_image_edges()[0]
        assert len(runs_image_edges()) == 1
        assert edge.from_entity_id == node.entity_id
        assert edge.to_entity_id == Host.objects.get(realm="oci-digest", stable_id=DIGEST).entity_id
        node.refresh_from_db()
        assert (node.name, node.image, node.last_status, node.image_digest) == ("web", "registry.example/app:1", "RUNNING", None)
        assert Entity.objects.get(pk=node.entity_id).version == version
        run = latest_run()
        assert "link:ecs-containers" in run.scopes_read
        assert "link:ecs-containers:unresolved" not in not_read(run)

    def test_a_container_the_grid_does_not_hold_is_counted_and_not_created(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        known, unknown = container(ACCOUNT, "ctx-a", DIGEST), container("999999999999", "ctx-b", OTHER)
        on_grid(known["arn"])
        run_against(monkeypatch, instance_with(known, unknown))
        assert len(runs_image_edges()) == 1
        assert get_model_class(ECS).objects.count() == 1
        assert not_read(latest_run())["link:ecs-containers:unresolved"].startswith("1 ECS container(s)")

    def test_create_ecs_true_changes_nothing_yet(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True}, create={"ecs": True})
        run_against(monkeypatch, instance_with(container(ACCOUNT, "ctx-a", DIGEST)))
        assert get_model_class(ECS).objects.count() == 0
        assert runs_image_edges() == []
        assert latest_run().settings["create"]["ecs"] is True

    def test_a_second_run_draws_no_second_edge(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        record = container(ACCOUNT, "ctx-a", DIGEST)
        on_grid(record["arn"])
        instance = instance_with(record)
        run_against(monkeypatch, instance)
        run_against(monkeypatch, instance)
        assert len(runs_image_edges()) == 1

    def test_only_containers_in_scope_are_linked(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True, "aws_account_ids": [ACCOUNT]})
        mine, theirs = container(ACCOUNT, "ctx-a", DIGEST), container("999999999999", "ctx-b", OTHER)
        mine_node, _ = on_grid(mine["arn"]), on_grid(theirs["arn"], name="other")
        run_against(monkeypatch, instance_with(mine, theirs))
        assert [edge.from_entity_id for edge in runs_image_edges()] == [mine_node.entity_id]

    def test_without_aws_core_the_join_is_not_read_and_the_run_goes_on(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        monkeypatch.setattr(store, "ECS_CONTAINER_TYPE", "aws_core__not_installed")
        run_against(monkeypatch, instance_with(container(ACCOUNT, "ctx-a", DIGEST)))
        run = latest_run()
        assert "aws_core is not installed" in not_read(run)["link:ecs-containers"]
        assert runs_image_edges() == []
        assert f"image:{DIGEST}" in run.scopes_read
