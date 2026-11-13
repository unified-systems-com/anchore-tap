"""Opt-in creation of aws_core ECS nodes the grid does not hold (req-anchore-shared-5 to -12).

Against the real aws_core types, which the CI stack installs. The payloads are spec-derived from
Anchore's OpenAPI file (2.20.0), not recorded from an instance.
"""

import types

import pytest
import tap_plugin.anchore.models as anchore  # noqa: F401 — trigger model registration
import tap_plugin.aws_core.models as aws  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models as compliance  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration
from tap_plugin.computing_core.models.host import Host

from tap_grid.models import Edge, Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_node
from tap_plugin.anchore import scope
from tap_plugin.anchore.collectors.anchore_collector import store
from tap_plugin.anchore.collectors.anchore_collector import collector as collector_module
from tap_plugin.anchore.tests.fakes import response
from tap_plugin.anchore.tests.test_anchore_credential import data, write
from tap_plugin.anchore.tests.test_collector_run import DIGEST, OTHER, no_sockets, run_against  # noqa: F401 — no_sockets is autouse
from tap_plugin.anchore.tests.test_collector_scope import configure, container, item, latest_run, not_read, two_images

ACCOUNT, REGION = "123456789012", "us-gov-west-1"
BASE = f"arn:aws-us-gov:ecs:{REGION}:{ACCOUNT}"
CLUSTER, SERVICE, TASK, CONTAINER = f"{BASE}:cluster/prod", f"{BASE}:service/prod/web", f"{BASE}:task/prod/t1", f"{BASE}:container/prod/t1/c1"
TYPES = dict(store.ECS_TYPES)
CREATE = {"create": {"ecs": True}}


def task(arn: str = TASK, service: str = SERVICE, cluster: str = CLUSTER, **over) -> dict:
    return {"arn": arn, "account_name": "acct", "cluster_arn": cluster, "service_arn": service, "task_definition_arn": f"{BASE}:task-definition/web:7", "tags": {"team": "platform"}, **over}


def service(arn: str = SERVICE, cluster: str = CLUSTER) -> dict:
    return {"arn": arn, "account_name": "acct", "cluster_arn": cluster, "tags": {"tier": "web"}}


def instance_with(containers: list, tasks: list, services: list):
    instance = two_images()
    instance.inventory = [item(c["context"], c["image_digest"], kind="ecs") for c in containers]
    instance.ecs = containers
    instance.transport.routes["/ecs-tasks"] = lambda r: response(200, {"tasks": tasks if "page=1" in str(r.url) else []})
    instance.transport.routes["/ecs-services"] = lambda r: response(200, {"services": services if "page=1" in str(r.url) else []})
    return instance


def standard():
    return instance_with([container(ACCOUNT, "ctx-a", DIGEST)], [task()], [service()])


def nodes(kind: str):
    return list(get_model_class(TYPES[kind]).objects.all())


def edges(slug: str) -> set[tuple[str, str]]:
    return {(e.from_entity.entity_type, e.to_entity.entity_type) for e in Edge.objects.filter(edge_type=slug)}


@pytest.mark.django_db
class TestCreate:
    def test_absent_nodes_are_created_from_what_anchore_reported(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True}, **CREATE)
        run_against(monkeypatch, standard())
        (made,) = nodes("container")
        assert (made.container_arn, made.image, made.image_digest) == (CONTAINER, "registry.example/app:1", DIGEST)
        # The placeholder name (rule 4), and nothing Anchore did not report.
        assert made.name == "c1"
        assert (made.runtime_id, made.last_status, made.tags, made.configuration) == (None, None, {}, {})
        (made_task,) = nodes("task")
        assert (made_task.task_arn, made_task.cluster_arn, made_task.tags) == (TASK, CLUSTER, {"team": "platform"})
        assert made_task.task_definition_arn == f"{BASE}:task-definition/web:7"
        assert made_task.last_status is None and made_task.configuration == {}
        (made_service,) = nodes("service")
        assert (made_service.service_arn, made_service.name, made_service.tags) == (SERVICE, "web", {"tier": "web"})
        (made_cluster,) = nodes("cluster")
        assert (made_cluster.cluster_arn, made_cluster.name) == (CLUSTER, "prod")
        assert "create:ecs" in latest_run().scopes_read

    def test_created_nodes_carry_the_providers_dimensions(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True}, **CREATE)
        run_against(monkeypatch, standard())
        for kind in TYPES:
            (made,) = nodes(kind)
            assert Entity.objects.get(pk=made.entity_id).dimensions == {"tap.cloud": "aws", "aws_account": ACCOUNT, "aws_region": REGION}, kind

    def test_the_account_and_region_go_under_the_names_the_installed_aws_core_uses(self, tmp_path, monkeypatch):
        """After aws_core's rename its seed declares the new names, and a created node carries those."""
        monkeypatch.setattr(store, "aws_dimension_names", lambda: {"account": "aws.account", "region": "aws.region"})
        configure(tmp_path, monkeypatch, {"running_only": True}, **CREATE)
        run_against(monkeypatch, standard())
        (made,) = nodes("task")
        held = Entity.objects.get(pk=made.entity_id).dimensions
        assert (held["aws.account"], held["aws.region"]) == (ACCOUNT, REGION)
        assert "aws_account" not in held and "aws_region" not in held and "cloud" not in held

    def test_the_owners_edges_and_the_image_edge_are_drawn(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True}, **CREATE)
        run_against(monkeypatch, standard())
        assert edges("RUNS_CONTAINER__aws_core") == {(TYPES["task"], TYPES["container"])}
        assert edges("RUNS_TASK__aws_core") == {(TYPES["cluster"], TYPES["task"]), (TYPES["service"], TYPES["task"])}
        assert edges("RUNS_SERVICE__aws_core") == {(TYPES["cluster"], TYPES["service"])}
        image_edge = Edge.objects.get(edge_type="RUNS_IMAGE__computing_core")
        assert image_edge.from_entity_id == nodes("container")[0].entity_id
        assert image_edge.to_entity_id == Host.objects.get(realm="oci-digest", stable_id=DIGEST).entity_id
        assert "link:ecs-containers:unresolved" not in not_read(latest_run())

    def test_off_by_default_nothing_is_created(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        run_against(monkeypatch, standard())
        assert [len(nodes(kind)) for kind in TYPES] == [0, 0, 0, 0]

    def test_a_node_the_grid_holds_is_not_written_and_its_absent_ancestors_are_created(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True}, **CREATE)
        held = create_node(TYPES["container"], {"name": "web", "container_arn": CONTAINER, "last_status": "RUNNING"})
        version = Entity.objects.get(pk=held.entity_id).version
        run_against(monkeypatch, standard())
        (kept,) = nodes("container")
        assert (kept.name, kept.last_status, kept.image_digest) == ("web", "RUNNING", None)
        assert Entity.objects.get(pk=held.entity_id).version == version
        assert [len(nodes(kind)) for kind in ("task", "service", "cluster")] == [1, 1, 1]
        assert edges("RUNS_CONTAINER__aws_core") == {(TYPES["task"], TYPES["container"])}

    def test_a_created_node_is_never_rewritten(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True}, **CREATE)
        instance = standard()
        run_against(monkeypatch, instance)
        versions = {kind: Entity.objects.get(pk=nodes(kind)[0].entity_id).version for kind in TYPES}
        instance.transport.routes["/ecs-tasks"] = lambda r: response(200, {"tasks": [task(tags={"team": "changed"})] if "page=1" in str(r.url) else []})
        run_against(monkeypatch, instance)
        assert {kind: Entity.objects.get(pk=nodes(kind)[0].entity_id).version for kind in TYPES} == versions
        assert nodes("task")[0].tags == {"team": "platform"}
        assert [len(nodes(kind)) for kind in TYPES] == [1, 1, 1, 1]

    def test_only_ancestors_of_selected_containers_are_created(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True}, **CREATE)
        stray_task = task(arn=f"{BASE}:task/prod/t9", service=f"{BASE}:service/prod/batch")
        stray_service = service(arn=f"{BASE}:service/prod/batch")
        run_against(monkeypatch, instance_with([container(ACCOUNT, "ctx-a", DIGEST)], [task(), stray_task], [service(), stray_service]))
        assert [n.task_arn for n in nodes("task")] == [TASK]
        assert [n.service_arn for n in nodes("service")] == [SERVICE]

    def test_a_task_outside_a_service_has_no_service(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True}, **CREATE)
        run_against(monkeypatch, instance_with([container(ACCOUNT, "ctx-a", DIGEST)], [task(service="")], []))
        assert nodes("service") == []
        assert edges("RUNS_TASK__aws_core") == {(TYPES["cluster"], TYPES["task"])}

    def test_an_inconsistent_ancestor_creates_nothing(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True}, **CREATE)
        elsewhere = "arn:aws-us-gov:ecs:us-gov-west-1:999999999999:cluster/prod"
        run_against(monkeypatch, instance_with([container(ACCOUNT, "ctx-a", DIGEST)], [task(cluster=elsewhere)], [service()]))
        assert [len(nodes(kind)) for kind in TYPES] == [0, 0, 0, 0]
        assert not_read(latest_run())["create:ecs:rejected"].startswith("1 selected ECS container(s)")

    def test_a_container_outside_the_listed_accounts_is_not_created(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True, "aws_account_ids": [ACCOUNT], "context_prefixes": ["ctx-"]}, **CREATE)
        other = container("999999999999", "ctx-b", OTHER)
        instance = instance_with([container(ACCOUNT, "ctx-a", DIGEST), other], [task()], [service()])
        run_against(monkeypatch, instance)
        assert [n.container_arn for n in nodes("container")] == [CONTAINER]
        assert "create:ecs:rejected" in not_read(latest_run())

    def test_without_the_task_list_nothing_is_created(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True}, **CREATE)
        instance = standard()
        instance.transport.routes["/ecs-tasks"] = lambda r: response(500, {"detail": "boom"})
        run_against(monkeypatch, instance)
        assert [len(nodes(kind)) for kind in TYPES] == [0, 0, 0, 0]
        assert "no ECS node was created" in not_read(latest_run())["create:ecs"]

    def test_the_lists_are_not_read_unless_creating(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        instance = standard()
        run_against(monkeypatch, instance)
        assert not [c for c in instance.transport.calls if "/ecs-tasks" in str(c.url) or "/ecs-services" in str(c.url)]


@pytest.mark.django_db
class TestTwoScanners:
    def test_a_second_scanner_joins_its_task_to_a_cluster_the_first_staged(self, tmp_path, monkeypatch):
        """Two Anchore instances report tasks under one cluster and service. The first scanner stages the
        cluster and service; the second must still draw its own task's edges to them."""
        write(tmp_path, "one", data("basic", base_url="https://one.example:8228/v2", scope={"running_only": True}, **CREATE))
        write(tmp_path, "two", data("basic", base_url="https://two.example:8228/v2", scope={"running_only": True}, **CREATE))
        monkeypatch.setattr(collector_module, "secrets_root", types.SimpleNamespace(resolve=lambda: tmp_path))
        other_task, other_container = f"{BASE}:task/prod/t2", f"{BASE}:container/prod/t2/c2"
        second = {**container(ACCOUNT, "ctx-a", OTHER), "arn": other_container, "task_arn": other_task}

        def per_host(first, later):
            return lambda r: response(200, (first if "one.example" in str(r.url) else later) if "page=1" in str(r.url) else {next(iter(first)): []})

        instance = two_images()
        instance.inventory = [item("ctx-a", DIGEST, kind="ecs"), item("ctx-a", OTHER, kind="ecs")]
        instance.transport.routes["/ecs-containers"] = per_host({"containers": [container(ACCOUNT, "ctx-a", DIGEST)]}, {"containers": [second]})
        instance.transport.routes["/ecs-tasks"] = per_host({"tasks": [task()]}, {"tasks": [task(arn=other_task)]})
        instance.transport.routes["/ecs-services"] = per_host({"services": [service()]}, {"services": [service()]})
        run_against(monkeypatch, instance)
        assert [len(nodes(kind)) for kind in ("container", "task", "service", "cluster")] == [2, 2, 1, 1]
        task_edges = {(e.from_entity.entity_type, e.to_entity.name) for e in Edge.objects.filter(edge_type="RUNS_TASK__aws_core")}
        assert task_edges == {(TYPES["cluster"], "t1"), (TYPES["service"], "t1"), (TYPES["cluster"], "t2"), (TYPES["service"], "t2")}
        assert Edge.objects.filter(edge_type="RUNS_SERVICE__aws_core").count() == 1

    def test_a_second_scanner_links_its_image_to_a_container_the_first_staged(self, tmp_path, monkeypatch):
        """Two Anchore instances report one container ARN with different digests. The first stages the
        container; the second must still draw its own image edge from it, or say it did not."""
        write(tmp_path, "one", data("basic", base_url="https://one.example:8228/v2", scope={"running_only": True}, **CREATE))
        write(tmp_path, "two", data("basic", base_url="https://two.example:8228/v2", scope={"running_only": True}, **CREATE))
        monkeypatch.setattr(collector_module, "secrets_root", types.SimpleNamespace(resolve=lambda: tmp_path))

        def per_host(first, later):
            return lambda r: response(200, (first if "one.example" in str(r.url) else later) if "page=1" in str(r.url) else {next(iter(first)): []})

        instance = two_images()
        instance.inventory = [item("ctx-a", DIGEST, kind="ecs"), item("ctx-a", OTHER, kind="ecs")]
        instance.transport.routes["/ecs-containers"] = per_host({"containers": [container(ACCOUNT, "ctx-a", DIGEST)]}, {"containers": [container(ACCOUNT, "ctx-a", OTHER)]})
        instance.transport.routes["/ecs-tasks"] = per_host({"tasks": [task()]}, {"tasks": [task()]})
        instance.transport.routes["/ecs-services"] = per_host({"services": [service()]}, {"services": [service()]})
        run_against(monkeypatch, instance)
        (node,) = nodes("container")
        runs = Edge.objects.filter(edge_type="RUNS_IMAGE__computing_core", from_entity_id=node.entity_id)
        assert {Host.objects.get(entity_id=e.to_entity_id).stable_id for e in runs} == {DIGEST, OTHER}


@pytest.mark.django_db
class TestTheRace:
    def test_a_node_the_provider_creates_after_the_lookup_is_replaced(self, tmp_path, monkeypatch):
        """The interleaving req-anchore-shared-5 requires to be stated (unified-systems-com/tap#1071).

        The provider's collector creates the container after this plugin has looked and before its
        batch is imported. The lookup is made to answer "absent" for a container that is in fact on
        the grid. This plugin's write then lands on the provider's node: the fields Anchore sends
        replace the provider's, the name included, and the fields it does not send are kept.
        """
        configure(tmp_path, monkeypatch, {"running_only": True}, **CREATE)
        theirs = create_node(TYPES["container"], {"name": "web", "container_arn": CONTAINER, "image": "their/image:9", "last_status": "RUNNING"})
        real = store.aws_nodes_on_grid
        monkeypatch.setattr(store, "aws_nodes_on_grid", lambda entity_type, key, arns: set() if entity_type == TYPES["container"] else real(entity_type, key, arns))
        run_against(monkeypatch, standard())
        (node,) = nodes("container")
        assert node.entity_id == theirs.entity_id
        assert (node.name, node.image) == ("c1", "registry.example/app:1")
        assert node.last_status == "RUNNING"


class TestPlan:
    def test_arns_are_checked_by_kind(self):
        assert scope.parse_ecs_arn(CONTAINER, "container").last == "c1"
        assert scope.parse_ecs_arn(CLUSTER, "cluster").last == "prod"
        assert scope.parse_ecs_arn(CONTAINER, "task") is None
        assert scope.parse_ecs_arn("arn:aws:s3:::bucket", "container") is None
        assert scope.parse_ecs_arn(f"arn:aws:ecs:{REGION}:12345:container/x", "container") is None
        assert scope.parse_ecs_arn(None, "container") is None

    @pytest.mark.parametrize(
        "arn",
        [
            f"{BASE}:cluster//",
            f"{BASE}:cluster/",
            f"{BASE}:task/prod//t1",
            f"{BASE}:service/prod/web ",
            f"{BASE}:cluster/pr od",
            f"{BASE}:cluster/prod/",
            f"{BASE}:cluster/prod\nx",
            f"arn:aws-:ecs:{REGION}:{ACCOUNT}:cluster/x",
            f"arn:aws:ecs:-:{ACCOUNT}:cluster/x",
            f"arn:aws:ecs:west:{ACCOUNT}:cluster/x",
            f"{BASE}:cluster/{'x' * 256}",
            f"{BASE}:task/{'x' * 255}/{'y' * 255}",
        ],
    )
    def test_a_malformed_resource_path_is_not_an_ecs_arn(self, arn):
        kind = arn.split(":")[5].split("/")[0]
        assert scope.parse_ecs_arn(arn, kind) is None

    def test_a_malformed_ancestor_rejects_the_container(self):
        records = [{"arn": CONTAINER, "task_arn": TASK, "image_digest": DIGEST}]
        plan = scope.plan_ecs_creation(records, [task(cluster=f"{BASE}:cluster//")], [service()], scope.Settings(running_only=True))
        assert plan.rejected == 1 and not plan.containers and not plan.clusters

    def test_a_task_and_service_that_name_different_clusters_are_rejected(self):
        other = f"{BASE}:cluster/staging"
        records = [{"arn": CONTAINER, "task_arn": TASK, "image_digest": DIGEST}]
        plan = scope.plan_ecs_creation(records, [task(cluster=CLUSTER)], [service(cluster=other)], scope.Settings(running_only=True))
        assert plan.rejected == 1
        assert not plan.containers and not plan.tasks and not plan.services and not plan.clusters and plan.edges == []

    def test_the_service_supplies_the_cluster_when_the_task_names_none(self):
        records = [{"arn": CONTAINER, "task_arn": TASK, "image_digest": DIGEST}]
        plan = scope.plan_ecs_creation(records, [task(cluster="")], [service()], scope.Settings(running_only=True))
        assert plan.rejected == 0 and list(plan.clusters) == [CLUSTER]

    def test_tags_that_are_not_a_flat_string_map_are_left_out(self):
        plan = scope.plan_ecs_creation([{"arn": CONTAINER, "task_arn": TASK, "image_digest": DIGEST}], [task(tags={"n": 3})], [service()], scope.Settings(running_only=True))
        assert plan.tasks[TASK]["tags"] is None
        assert plan.services[SERVICE]["tags"] == {"tier": "web"}


class TestAwsDimensionNames:
    """Which names the installed aws_core gives its account and region dimensions (req-anchore-shared-8)."""

    def seed(self, *names):
        return {"batches": [{"nodes": [{"entity": {"entity_type": "dimension"}, "node": {"name": name}} for name in names]}]}

    def test_before_the_rename(self):
        assert store.aws_dimension_names(self.seed("tap.cloud", "cloud", "aws_account", "aws_region")) == {"account": "aws_account", "region": "aws_region"}

    def test_after_the_rename(self):
        assert store.aws_dimension_names(self.seed("tap.computing.cloud", "cloud", "aws.account", "aws.region")) == {"account": "aws.account", "region": "aws.region"}

    def test_each_is_decided_on_its_own(self):
        assert store.aws_dimension_names(self.seed("aws.account", "aws_region")) == {"account": "aws.account", "region": "aws_region"}

    def test_the_new_name_wins_where_a_seed_declares_both(self):
        assert store.aws_dimension_names(self.seed("aws_account", "aws.account"))["account"] == "aws.account"

    @pytest.mark.parametrize("seed", [None, {}, {"batches": []}])
    def test_an_aws_core_with_no_seed_keeps_the_old_names(self, seed):
        assert store.aws_dimension_names(seed) == {"account": "aws_account", "region": "aws_region"}

    def test_a_non_dimension_node_of_that_name_does_not_count(self):
        seed = {"batches": [{"nodes": [{"entity": {"entity_type": "page"}, "node": {"name": "aws.account"}}]}]}
        assert store.aws_dimension_names(seed)["account"] == "aws_account"

    def test_the_installed_aws_core_ships_a_seed_this_reads_and_understands(self):
        """Against the real package: the path resolves and the file has the shape the name choice parses.

        A wrong path or a changed layout would otherwise fall back to the old names silently.
        """
        seed = store._aws_core_seed()
        assert isinstance(seed, dict), "the installed aws_core has no grift/dimension.grift.json where this plugin looks"
        declared = {n["node"]["name"] for batch in seed["batches"] for n in batch["nodes"] if n["entity"]["entity_type"] == "dimension"}
        assert declared, "aws_core's seed declares no dimension node in the shape this plugin reads"
        names = store.aws_dimension_names()
        # Whichever names it chose, each is the newest one that seed declares, or the oldest when it declares neither.
        for role, candidates in store._AWS_DIMENSION_NAMES.items():
            assert names[role] == next((name for name in candidates if name in declared), candidates[-1])


class TestSeedThatCannotBeRead:
    """A seed that is there but unreadable is not "no seed": nothing is created under guessed names."""

    def test_an_unreadable_or_malformed_seed_is_an_error_not_the_old_names(self, tmp_path, monkeypatch):
        from importlib import resources

        (tmp_path / "grift").mkdir()
        target = tmp_path / "grift" / "dimension.grift.json"
        monkeypatch.setattr(resources, "files", lambda package: tmp_path)
        for body in ("{not json", "[]", '{"batches": {}}'):
            target.write_text(body, encoding="utf-8")
            with pytest.raises(store.AwsSeedUnreadable):
                store.aws_dimension_names()

    def test_an_aws_core_that_ships_no_seed_file_is_no_seed(self, tmp_path, monkeypatch):
        from importlib import resources

        monkeypatch.setattr(resources, "files", lambda package: tmp_path)
        assert store._aws_core_seed() is None

    @pytest.mark.django_db
    def test_no_ecs_node_is_created_and_the_run_says_why(self, tmp_path, monkeypatch):
        def unreadable():
            raise store.AwsSeedUnreadable("aws_core's dimension seed could not be read (JSONDecodeError)")

        monkeypatch.setattr(store, "aws_dimension_names", unreadable)
        configure(tmp_path, monkeypatch, {"running_only": True}, **CREATE)
        run_against(monkeypatch, standard())
        assert all(not nodes(kind) for kind in TYPES)
        reasons = [entry["reason"] for entry in latest_run().scopes_not_read if entry["scope"] == "create:ecs"]
        assert reasons and "could not be read" in reasons[0] and "no ECS node was created" in reasons[0]
