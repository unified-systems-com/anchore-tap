"""Collection scope: settings, what counts as running, and which images are read (req-anchore-scope-*)."""

from datetime import UTC, datetime, timedelta

import pytest
from tap.runtime_secrets import SecretEnvelope

from tap_plugin.anchore import credential as cred
from tap_plugin.anchore import scope
from tap_plugin.anchore.tests.test_anchore_credential import data, envelope

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=UTC)
D1, D2, D3, D4 = ("sha256:" + c * 64 for c in "abcd")
ECR = "123456789012.dkr.ecr.us-gov-west-1.amazonaws.com"


def ago(hours: float) -> str:
    return (NOW - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")


def item(context: str, digest: str, hours: float = 1, kind: str = "kubernetes") -> dict:
    return {"inventory_type": kind, "context": context, "image_digest": digest, "last_seen": ago(hours)}


def container(account: str, context: str, digest: str, name: str = "c1") -> dict:
    return {
        "arn": f"arn:aws-us-gov:ecs:us-gov-west-1:{account}:container/prod/task1/{name}",
        "task_arn": f"arn:aws-us-gov:ecs:us-gov-west-1:{account}:task/prod/task1",
        "context": context,
        "image_digest": digest,
    }


def image(digest: str, registry: str = "docker.io", repo: str = "library/nginx") -> dict:
    return {"image_digest": digest, "image_detail": [{"registry": registry, "repo": repo, "tag": "1"}]}


def settings(running_only: bool = True, **over) -> scope.Settings:
    return scope.Settings(running_only=running_only, **over)


class TestSettings:
    def test_running_only_must_be_stated(self):
        for payload in ({}, {"scope": {}}, {"scope": {"context_prefixes": ["prod/"]}}):
            without = {k: v for k, v in data().items() if k != "scope"} | payload
            with pytest.raises(cred.CredentialError):
                cred.credential_from_envelope(envelope(payload=without))

    def test_true_and_false_are_both_accepted_and_kept(self):
        for choice in (True, False):
            got = cred.credential_from_envelope(envelope(payload=data(scope={"running_only": choice}))).settings
            assert got.running_only is choice

    def test_the_other_settings_default(self):
        got = cred.credential_from_envelope(envelope(payload=data(scope={"running_only": True}))).settings
        assert got == scope.Settings(running_only=True)
        assert got.create_kubernetes is True
        assert got.create_ecs is False
        assert got.inventory_max_age_hours == 24
        assert not got.has_running_selector

    def test_every_setting_is_read(self):
        payload = data(
            scope={
                "running_only": False,
                "aws_account_ids": ["123456789012"],
                "context_prefixes": ["prod-east/"],
                "repository_prefixes": [f"{ECR}/platform/"],
            },
            inventory_max_age_hours=6,
            create={"kubernetes": False, "ecs": True},
        )
        got = cred.credential_from_envelope(envelope(payload=payload)).settings
        assert got == scope.Settings(False, ("123456789012",), ("prod-east/",), (f"{ECR}/platform/",), 6, False, True)
        assert got.has_running_selector

    @pytest.mark.parametrize(
        "over",
        [
            {"scope": {"running_only": True, "aws_account_ids": []}},
            {"scope": {"running_only": True, "context_prefixes": []}},
            {"scope": {"running_only": True, "repository_prefixes": []}},
            {"scope": {"running_only": True, "aws_account_ids": ["12345"]}},
            {"scope": {"running_only": True, "aws_account_ids": ["12345678901a"]}},
            {"scope": {"running_only": True, "context_prefixes": [""]}},
            {"scope": {"running_only": True, "kubernetes_cluster_names": ["prod"]}},
            {"scope": {"running_only": "yes"}},
            {"inventory_max_age_hours": 0},
            {"inventory_max_age_hours": 1.5},
            {"create": {"eks": True}},
            {"create": {"ecs": "true"}},
        ],
    )
    def test_strict_settings_are_refused(self, over):
        with pytest.raises(cred.CredentialError):
            cred.credential_from_envelope(envelope(payload=data(**over)))

    def test_the_recorded_form_holds_every_setting_and_no_credential(self):
        payload = data(scope={"running_only": True, "context_prefixes": ["prod/"]})
        credential = cred.credential_from_envelope(envelope(payload=payload))
        recorded = credential.settings.as_recorded()
        assert recorded["scope"]["context_prefixes"] == ["prod/"]
        assert recorded["scope"]["running_only"] is True
        assert recorded["create"] == {"kubernetes": True, "ecs": False}
        assert recorded["inventory_max_age_hours"] == 24
        assert "pw-not-a-real-secret-value" not in repr(recorded)

    def test_the_envelope_class_is_unchanged(self):
        assert isinstance(envelope(), SecretEnvelope)


class TestAccountOfArn:
    @pytest.mark.parametrize(
        ("arn", "account"),
        [
            ("arn:aws:ecs:us-east-1:123456789012:container/prod/t/c", "123456789012"),
            ("arn:aws-us-gov:ecs:us-gov-west-1:210987654321:task/prod/t", "210987654321"),
            ("arn:aws:ecs:us-east-1::cluster/prod", None),
            ("arn:aws:ecs:us-east-1:12345:cluster/prod", None),
            ("arn:aws:s3:::bucket", None),
            ("prod/default", None),
            ("", None),
            (None, None),
            (12, None),
        ],
    )
    def test_the_fifth_field_when_it_is_an_account(self, arn, account):
        assert scope.account_of_arn(arn) == account


class TestFresh:
    def test_inside_and_outside_the_window(self):
        assert scope.is_fresh(ago(23.9), NOW, 24)
        assert scope.is_fresh(ago(24), NOW, 24)
        assert not scope.is_fresh(ago(24.1), NOW, 24)
        assert not scope.is_fresh(ago(24 * 100), NOW, 24)

    @pytest.mark.parametrize("value", [None, "", "yesterday", 1731153600, "2026-13-40T00:00:00Z"])
    def test_no_readable_time_is_not_running(self, value):
        assert not scope.is_fresh(value, NOW, 24)

    def test_offsets_and_naive_times_are_read(self):
        assert scope.is_fresh("2026-11-09T07:00:00-05:00", NOW, 1)
        assert scope.is_fresh("2026-11-09T11:30:00", NOW, 1)
        assert scope.is_fresh("2026-11-09T11:30:00.123456+00:00", NOW, 1)

    def test_a_time_ahead_of_ours_is_running(self):
        assert scope.is_fresh(ago(-2), NOW, 1)


class TestSelectRunning:
    def test_no_selector_selects_every_running_record(self):
        inventory = [item("prod/default", D1), item("dev/default", D2), item("old/default", D3, hours=200)]
        got = scope.select_running(inventory, [], settings(), NOW)
        assert got.digests == {D1, D2}
        assert got.stale == 1

    def test_context_prefix_selects_a_cluster_or_a_namespace(self):
        inventory = [item("prod-east/payments", D1), item("prod-east/default", D2), item("prod-eastern/default", D3)]
        cluster = scope.select_running(inventory, [], settings(context_prefixes=("prod-east/",)), NOW)
        assert cluster.digests == {D1, D2}
        namespace = scope.select_running(inventory, [], settings(context_prefixes=("prod-east/payments",)), NOW)
        assert namespace.digests == {D1}

    def test_account_is_read_from_the_container_arn_not_the_context(self):
        inventory = [item("ctx-a", D1, kind="ecs"), item("ctx-b", D2, kind="ecs")]
        containers = [container("123456789012", "ctx-a", D1), container("999999999999", "ctx-b", D2)]
        got = scope.select_running(inventory, containers, settings(aws_account_ids=("123456789012",)), NOW)
        assert got.digests == {D1}
        assert [c["context"] for c in got.ecs_containers] == ["ctx-a"]

    def test_the_two_selectors_are_a_union(self):
        inventory = [item("prod-east/default", D1), item("ctx-a", D2, kind="ecs"), item("other/default", D3)]
        containers = [container("123456789012", "ctx-a", D2)]
        chosen = settings(context_prefixes=("prod-east/",), aws_account_ids=("123456789012",))
        assert scope.select_running(inventory, containers, chosen, NOW).digests == {D1, D2}

    def test_an_ecs_container_takes_its_last_seen_from_the_inventory_item(self):
        inventory = [item("ctx-a", D1, kind="ecs", hours=200)]
        containers = [container("123456789012", "ctx-a", D1), container("123456789012", "ctx-z", D2)]
        got = scope.select_running(inventory, containers, settings(aws_account_ids=("123456789012",)), NOW)
        assert got.digests == set()
        assert got.ecs_containers == []
        assert got.stale == 1
        assert got.ecs_without_inventory == 2

    def test_a_record_without_a_usable_digest_selects_nothing_and_is_counted(self):
        inventory = [item("prod/default", "nginx:latest"), {"context": "prod/default", "last_seen": ago(1)}]
        containers = [container("123456789012", "ctx-a", "")]
        got = scope.select_running(inventory, containers, settings(), NOW)
        assert got.digests == set()
        assert got.no_digest == 3

    def test_one_image_in_two_contexts_is_two_items_and_one_digest(self):
        inventory = [item("prod/a", D1), item("prod/b", D1), item("prod/a", D1)]
        got = scope.select_running(inventory, [], settings(), NOW)
        assert len(got.items) == 2
        assert got.digests == {D1}

    def test_a_shorter_window_drops_what_a_longer_one_keeps(self):
        inventory = [item("prod/a", D1, hours=5)]
        assert scope.select_running(inventory, [], settings(inventory_max_age_hours=6), NOW).digests == {D1}
        assert scope.select_running(inventory, [], settings(inventory_max_age_hours=4), NOW).digests == set()


class TestRepositoryFilter:
    def test_no_prefix_passes_everything(self):
        assert scope.passes_repository(image(D1), ())
        assert scope.passes_repository({"image_digest": D1}, ())

    def test_registry_slash_repo_begins_with_a_prefix(self):
        platform = image(D1, ECR, "platform/api")
        assert scope.passes_repository(platform, (f"{ECR}/platform/",))
        assert scope.passes_repository(platform, (f"{ECR}/",))
        assert not scope.passes_repository(platform, (f"{ECR}/data/",))
        assert not scope.passes_repository(platform, ("platform/",))
        assert not scope.passes_repository(image(D2), (f"{ECR}/platform/",))

    def test_any_one_tag_is_enough(self):
        two = {"image_digest": D1, "image_detail": [{"registry": "docker.io", "repo": "x/y"}, {"registry": ECR, "repo": "platform/api"}]}
        assert scope.passes_repository(two, (f"{ECR}/platform/",))

    def test_a_record_without_tags_does_not_pass_a_set_filter(self):
        assert not scope.passes_repository({"image_digest": D1}, ("docker.io/",))
        assert not scope.passes_repository({"image_digest": D1, "image_detail": [{"registry": None, "repo": "x"}]}, ("docker.io/",))


class TestImagesToRead:
    LISTED = {D1: image(D1, ECR, "platform/api"), D2: image(D2, ECR, "data/etl"), D3: image(D3)}

    def test_running_only_reads_the_running_selection(self):
        got = scope.images_to_read(self.LISTED, {D1, D3}, settings())
        assert got.digests == [D1, D3]
        assert (got.images_listed, got.images_selected, got.images_out_of_scope) == (3, 2, 1)
        assert got.not_in_anchore == []

    def test_the_repository_filter_narrows_the_running_selection(self):
        got = scope.images_to_read(self.LISTED, {D1, D2, D3}, settings(repository_prefixes=(f"{ECR}/platform/",)))
        assert got.digests == [D1]
        assert got.images_out_of_scope == 2

    def test_a_running_digest_anchore_does_not_hold_is_counted_not_read(self):
        got = scope.images_to_read(self.LISTED, {D1, D4}, settings())
        assert got.digests == [D1]
        assert got.not_in_anchore == [D4]

    def test_a_selection_that_could_not_be_read_selects_nothing(self):
        got = scope.images_to_read(self.LISTED, None, settings())
        assert got.digests == []
        assert got.images_out_of_scope == 3

    def test_all_images_mode_reads_what_passes_the_repository_filter(self):
        everything = scope.images_to_read(self.LISTED, None, settings(False))
        assert everything.digests == [D1, D2, D3]
        assert everything.not_in_anchore == []
        ecr_only = scope.images_to_read(self.LISTED, {D3}, settings(False, repository_prefixes=(f"{ECR}/",)))
        assert ecr_only.digests == [D1, D2]
        assert ecr_only.images_out_of_scope == 1

    def test_the_list_order_is_kept(self):
        listed = {D3: image(D3), D1: image(D1), D2: image(D2)}
        assert scope.images_to_read(listed, {D1, D2, D3}, settings()).digests == [D3, D1, D2]
        assert scope.images_to_read(listed, None, settings(False)).digests == [D3, D1, D2]

    def test_a_listed_digest_of_any_form_is_read_in_all_images_mode(self):
        got = scope.images_to_read({"md5:abc": {"image_digest": "md5:abc"}}, None, settings(False))
        assert got.digests == ["md5:abc"]
