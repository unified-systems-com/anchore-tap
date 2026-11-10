"""The collection scope end to end against a canned instance (req-anchore-scope-*, req-anchore-inventory-*).

Which images a run reads, what it writes for the running selection, and what it leaves alone.
The instance and the helpers are the collector run tests'; the payloads are spec-derived from
Anchore's OpenAPI file (2.20.0), not recorded from an instance.
"""

import types
from datetime import UTC, datetime, timedelta

import pytest
import tap_plugin.anchore.models as anchore  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models as compliance  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration
from tap_plugin.computing_core.models.host import Host

from tap_grid.models import Edge
from tap_plugin.anchore.collectors.anchore_collector import collector as collector_module
from tap_plugin.anchore.models.finding import AnchoreFinding
from tap_plugin.anchore.models.runtime_image import AnchoreRuntimeImage
from tap_plugin.anchore.models.scan_run import AnchoreScanRun
from tap_plugin.anchore.tests.fakes import response
from tap_plugin.anchore.tests.test_anchore_credential import data, write
from tap_plugin.anchore.tests.test_collector_run import DIGEST, OTHER, Instance, no_sockets, run_against, vuln  # noqa: F401 — no_sockets is autouse

ABSENT = "sha256:" + "ef" * 32
ECR = "123456789012.dkr.ecr.us-gov-west-1.amazonaws.com"


def seen(hours_ago: float = 1) -> str:
    return (datetime.now(UTC) - timedelta(hours=hours_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def item(context: str, digest: str, hours_ago: float = 1, kind: str = "kubernetes", **over) -> dict:
    return {"inventory_type": kind, "context": context, "image_digest": digest, "image_tag": "registry.example/app:1", "last_seen": seen(hours_ago), **over}


def container(account: str, context: str, digest: str) -> dict:
    return {
        "arn": f"arn:aws-us-gov:ecs:us-gov-west-1:{account}:container/prod/t1/c1",
        "task_arn": f"arn:aws-us-gov:ecs:us-gov-west-1:{account}:task/prod/t1",
        "account_name": "acct",
        "context": context,
        "image_tag": "registry.example/app:1",
        "image_digest": digest,
    }


def two_images() -> Instance:
    instance = Instance(images=[{"image_digest": DIGEST, "analysis_status": "analyzed"}, {"image_digest": OTHER, "analysis_status": "analyzed"}])
    instance.vulns[OTHER] = [vuln("CVE-2024-0009")]
    return instance


def configure(tmp_path, monkeypatch, scope: dict, **over) -> None:
    write(tmp_path, "demo", data("basic", scope=scope, **over))
    monkeypatch.setattr(collector_module, "secrets_root", types.SimpleNamespace(resolve=lambda: tmp_path))


def latest_run() -> AnchoreScanRun:
    return AnchoreScanRun.objects.order_by("-finished_at").first()


def read_images(run: AnchoreScanRun) -> set[str]:
    return {scope.removeprefix("image:") for scope in run.scopes_read if scope.startswith("image:")}


def not_read(run: AnchoreScanRun) -> dict[str, str]:
    return {entry["scope"]: entry["reason"] for entry in run.scopes_not_read}


@pytest.mark.django_db
class TestRunningOnly:
    def test_nothing_running_reads_no_image_and_says_so(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        run_against(monkeypatch, two_images())
        run = latest_run()
        assert read_images(run) == set()
        assert AnchoreFinding.objects.count() == 0
        assert (run.images_listed, run.images_selected, run.images_out_of_scope, run.images_not_in_anchore, run.inventory_stale) == (2, 0, 2, 0, 0)
        assert run.settings["scope"]["running_only"] is True
        assert "source:inventories" in run.scopes_read and "source:ecs-containers" in run.scopes_read

    def test_a_running_image_is_read_and_its_observation_written(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        instance = two_images()
        instance.inventory = [item("prod/default", DIGEST)]
        run_against(monkeypatch, instance)
        run = latest_run()
        assert read_images(run) == {DIGEST}
        assert {f.target_key for f in AnchoreFinding.objects.all()} == {DIGEST}
        assert (run.images_selected, run.images_out_of_scope) == (1, 1)
        observed = AnchoreRuntimeImage.objects.get()
        assert (observed.inventory_type, observed.context, observed.image_digest, observed.image_tag) == ("kubernetes", "prod/default", DIGEST, "registry.example/app:1")
        assert observed.last_seen is not None and observed.created_at is None
        edge = Edge.objects.get(edge_type="OBSERVES_IMAGE__anchore")
        assert edge.from_entity_id == observed.entity_id
        assert Host.objects.get(pk=Host.objects.get(realm="oci-digest", stable_id=DIGEST).pk).entity_id == edge.to_entity_id

    def test_a_record_not_seen_recently_is_not_running(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True}, inventory_max_age_hours=6)
        instance = two_images()
        unseen = item("old/default", DIGEST)
        del unseen["last_seen"]
        instance.inventory = [item("prod/default", DIGEST, hours_ago=7), item("prod/default", OTHER, hours_ago=5), unseen]
        run_against(monkeypatch, instance)
        run = latest_run()
        assert read_images(run) == {OTHER}
        assert run.inventory_stale == 2
        assert [o.image_digest for o in AnchoreRuntimeImage.objects.all()] == [OTHER]

    def test_a_running_digest_anchore_does_not_hold_is_counted_and_still_observed(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        instance = two_images()
        instance.inventory = [item("prod/default", ABSENT)]
        run_against(monkeypatch, instance)
        run = latest_run()
        assert read_images(run) == set()
        assert run.images_not_in_anchore == 1
        assert "scope:not-in-anchore" in not_read(run)[f"image:{ABSENT}"]
        assert AnchoreFinding.objects.count() == 0
        assert AnchoreRuntimeImage.objects.get().image_digest == ABSENT
        assert Host.objects.filter(realm="oci-digest", stable_id=ABSENT).count() == 1

    def test_out_of_scope_resolves_nothing(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        instance = two_images()
        instance.inventory = [item("prod/default", DIGEST)]
        run_against(monkeypatch, instance)
        assert {f.state for f in AnchoreFinding.objects.all()} == {"current"}
        # The image stops running: it leaves the scope, is not read, and its findings stay as they were.
        instance.inventory = []
        instance.vulns[DIGEST] = []
        run_against(monkeypatch, instance)
        assert AnchoreFinding.objects.count() == 2
        assert {f.state for f in AnchoreFinding.objects.all()} == {"current"}
        assert read_images(latest_run()) == set()

    def test_an_inventory_that_cannot_be_read_selects_nothing(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True})
        instance = two_images()
        instance.transport.routes["/inventories"] = lambda r: response(500, {"detail": "boom"})
        run_against(monkeypatch, instance)
        run = latest_run()
        assert read_images(run) == set()
        assert "no running image was selected" in not_read(run)["source:inventories"]
        assert (run.images_selected, run.images_out_of_scope, run.inventory_stale) == (0, 2, None)
        assert AnchoreRuntimeImage.objects.count() == 0


@pytest.mark.django_db
class TestSelectors:
    def test_a_context_prefix_selects_its_images_only(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True, "context_prefixes": ["prod/"]})
        instance = two_images()
        instance.inventory = [item("prod/default", DIGEST), item("dev/default", OTHER)]
        run_against(monkeypatch, instance)
        assert read_images(latest_run()) == {DIGEST}
        assert [o.context for o in AnchoreRuntimeImage.objects.all()] == ["prod/default"]

    def test_an_account_selects_by_the_container_arn(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True, "aws_account_ids": ["123456789012"]})
        instance = two_images()
        instance.inventory = [item("ctx-a", DIGEST, kind="ecs"), item("ctx-b", OTHER, kind="ecs")]
        instance.ecs = [container("123456789012", "ctx-a", DIGEST), container("999999999999", "ctx-b", OTHER)]
        run_against(monkeypatch, instance)
        assert read_images(latest_run()) == {DIGEST}

    def test_without_the_container_list_the_account_selects_nothing(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True, "aws_account_ids": ["123456789012"]})
        instance = two_images()
        instance.inventory = [item("ctx-a", DIGEST, kind="ecs")]
        instance.transport.routes["/ecs-containers"] = lambda r: response(503, {"detail": "down"})
        run_against(monkeypatch, instance)
        run = latest_run()
        assert read_images(run) == set()
        assert "no ECS container was selected" in not_read(run)["source:ecs-containers"]

    def test_a_container_list_that_ignores_paging_still_ends(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True, "aws_account_ids": ["123456789012"]})
        instance = two_images()
        instance.inventory = [item("ctx-a", DIGEST, kind="ecs")]
        instance.transport.routes["/ecs-containers"] = lambda r: response(200, {"containers": [container("123456789012", "ctx-a", DIGEST)]})
        run_against(monkeypatch, instance)
        assert read_images(latest_run()) == {DIGEST}
        pages = [str(call.url) for call in instance.transport.calls if "/ecs-containers" in str(call.url)]
        assert len(pages) == 2


@pytest.mark.django_db
class TestAllImages:
    def images(self) -> Instance:
        instance = two_images()
        instance.images = [
            {"image_digest": DIGEST, "analysis_status": "analyzed", "image_detail": [{"registry": ECR, "repo": "platform/api", "tag": "1"}]},
            {"image_digest": OTHER, "analysis_status": "analyzed", "image_detail": [{"registry": "docker.io", "repo": "library/nginx", "tag": "1"}]},
        ]
        return instance

    def test_everything_is_read_running_or_not(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": False})
        run_against(monkeypatch, self.images())
        run = latest_run()
        assert read_images(run) == {DIGEST, OTHER}
        assert (run.images_listed, run.images_selected, run.images_out_of_scope) == (2, 2, 0)

    def test_repository_prefixes_narrow_it(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": False, "repository_prefixes": [f"{ECR}/platform/"]})
        run_against(monkeypatch, self.images())
        run = latest_run()
        assert read_images(run) == {DIGEST}
        assert run.images_out_of_scope == 1

    def test_repository_prefixes_narrow_the_running_selection_too(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": True, "repository_prefixes": ["docker.io/"]})
        instance = self.images()
        instance.inventory = [item("prod/default", DIGEST), item("prod/default", OTHER, image_tag="docker.io/library/nginx:1")]
        run_against(monkeypatch, instance)
        assert read_images(latest_run()) == {OTHER}
        # What is outside the prefixes is not written: one observation, not two.
        assert [image.image_digest for image in AnchoreRuntimeImage.objects.all()] == [OTHER]

    def test_a_selector_that_cannot_narrow_is_recorded(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": False, "context_prefixes": ["prod/"]})
        instance = self.images()
        instance.inventory = [item("prod/default", DIGEST), item("dev/default", OTHER)]
        run_against(monkeypatch, instance)
        run = latest_run()
        assert read_images(run) == {DIGEST, OTHER}
        assert "did not narrow" in not_read(run)["scope:selectors-do-not-narrow-images"]
        assert [o.context for o in AnchoreRuntimeImage.objects.all()] == ["prod/default"]

    def test_a_failed_inventory_does_not_stop_the_images(self, tmp_path, monkeypatch):
        configure(tmp_path, monkeypatch, {"running_only": False})
        instance = self.images()
        instance.transport.routes["/inventories"] = lambda r: response(500, {"detail": "boom"})
        run_against(monkeypatch, instance)
        assert read_images(latest_run()) == {DIGEST, OTHER}
