"""Anchore's policy evaluation of each image, per tag (req-anchore-image-policy).

Spec-derived payloads (OpenAPI 2.20.0), not recorded from an instance.
"""

import pytest
import tap_plugin.anchore.models as anchore  # noqa: F401 — trigger model registration
import tap_plugin.compliance_core.models as compliance  # noqa: F401 — trigger model registration
import tap_plugin.computing_core.models as computing  # noqa: F401 — trigger model registration
from tap_plugin.computing_core.models.host import Host

from tap_grid.models import Edge
from tap_plugin.anchore.models.policy_evaluation import AnchorePolicyEvaluation
from tap_plugin.anchore.models.scan_run import AnchoreScanRun
from tap_plugin.anchore.tests.test_collector_run import DIGEST, KEY, Instance, findings, no_sockets, run_against, secrets  # noqa: F401 — fixtures

TAG, OTHER_TAG = "registry.example/app:1.4", "registry.example/app:latest"
BASE = "sha256:" + "b" * 64
IMAGE = {"image_digest": DIGEST, "analysis_status": "analyzed", "image_detail": [{"registry": "registry.example", "repo": "app", "tag": "1.4", "full_tag": TAG}, {"registry": "registry.example", "repo": "app", "tag": "latest", "full_tag": OTHER_TAG}]}


def evaluation(status: str = "fail", action: str = "stop", tag: str = TAG, policy: str = "policy-1", **over) -> dict:
    body = {
        "image_digest": DIGEST,
        "policy_id": policy,
        "evaluated_tag": tag,
        "evaluations": [
            {
                "status": status,
                "final_action": action,
                "final_action_reason": "policy_evaluation",
                "number_of_findings": 3,
                "evaluation_time": "2026-11-10T12:00:00Z",
                "comparison_image_digest": BASE,
                "image_allowlisted": False,
                "image_denylisted": False,
                "image_mapped_to_rule": True,
                "evaluation_problems": [],
                "a_key_the_model_has_no_field_for": {"kept": True},
            }
        ],
    }
    body["evaluations"][0].update(over)
    return body


def server(**policy) -> Instance:
    instance = Instance(images=[IMAGE])
    instance.policy.update(policy or {(DIGEST, TAG): evaluation(), (DIGEST, OTHER_TAG): evaluation("pass", "go", OTHER_TAG)})
    return instance


def run() -> AnchoreScanRun:
    return AnchoreScanRun.objects.order_by("-finished_at").first()


def not_read() -> dict[str, str]:
    return {entry["scope"]: entry["reason"] for entry in run().scopes_not_read}


@pytest.mark.django_db
class TestEvaluations:
    def test_each_tag_has_its_verdict_as_anchore_returned_it(self, secrets, monkeypatch):
        instance = server()
        run_against(monkeypatch, instance)
        got = {e.evaluated_tag: e for e in AnchorePolicyEvaluation.objects.all()}
        assert set(got) == {TAG, OTHER_TAG}
        failed = got[TAG]
        assert (failed.scanner_key, failed.image_digest, failed.policy_id) == (KEY, DIGEST, "policy-1")
        assert (failed.status, failed.final_action, failed.final_action_reason, failed.number_of_findings) == ("fail", "stop", "policy_evaluation", 3)
        assert (failed.comparison_image_digest, failed.image_allowlisted, failed.image_denylisted) == (BASE, False, False)
        assert failed.evaluation_time.isoformat().startswith("2026-11-10T12:00:00") and failed.last_seen_run_id == run().run_id
        assert failed.record == instance.policy[(DIGEST, TAG)]
        assert (got[OTHER_TAG].status, got[OTHER_TAG].final_action) == ("pass", "go")
        host = Host.objects.get(stable_id=DIGEST)
        assert {e.to_entity_id for e in Edge.objects.filter(edge_type="EVALUATES_IMAGE__anchore")} == {host.entity_id}
        assert Edge.objects.filter(edge_type="EVALUATES_IMAGE__anchore").count() == 2
        assert {f"policy:{DIGEST}:{TAG}", f"policy:{DIGEST}:{OTHER_TAG}"} <= set(run().scopes_read)

    def test_the_read_names_the_tag_and_asks_for_the_base(self, secrets, monkeypatch):
        instance = server()
        run_against(monkeypatch, instance)
        asked = [str(call.url) for call in instance.transport.calls if "/check" in str(call.url)]
        assert len(asked) == 2 and all("base_digest=auto" in url and "tag=registry.example" in url for url in asked)
        assert all(call.method == "GET" for call in instance.transport.calls)

    def test_a_second_run_replaces_the_verdict_and_writes_no_second_node(self, secrets, monkeypatch):
        instance = server()
        run_against(monkeypatch, instance)
        instance.policy[(DIGEST, TAG)] = evaluation("pass", "go")
        run_against(monkeypatch, instance)
        assert AnchorePolicyEvaluation.objects.count() == 2
        assert AnchorePolicyEvaluation.objects.get(evaluated_tag=TAG).status == "pass"
        assert Edge.objects.filter(edge_type="EVALUATES_IMAGE__anchore").count() == 2

    def test_another_policy_is_another_evaluation(self, secrets, monkeypatch):
        instance = server()
        run_against(monkeypatch, instance)
        instance.policy[(DIGEST, TAG)] = evaluation(policy="policy-2")
        run_against(monkeypatch, instance)
        assert {e.policy_id for e in AnchorePolicyEvaluation.objects.filter(evaluated_tag=TAG)} == {"policy-1", "policy-2"}


@pytest.mark.django_db
class TestNotRead:
    @pytest.mark.parametrize("answer", [404, 500])
    def test_a_tag_whose_read_fails_is_recorded_and_the_rest_still_land(self, secrets, monkeypatch, answer):
        instance = server(**{})
        instance.policy[(DIGEST, OTHER_TAG)] = answer
        run_against(monkeypatch, instance)
        assert [e.evaluated_tag for e in AnchorePolicyEvaluation.objects.all()] == [TAG]
        assert not_read()[f"policy:{DIGEST}:{OTHER_TAG}"]
        assert len(findings()) == 2

    @pytest.mark.parametrize("change", [{"policy_id": None}, {"evaluations": []}])
    def test_a_response_with_no_policy_or_no_evaluation_is_not_a_verdict(self, secrets, monkeypatch, change):
        instance = server()
        body = {**evaluation(), **change}
        instance.policy[(DIGEST, TAG)] = {key: value for key, value in body.items() if value is not None}
        run_against(monkeypatch, instance)
        assert [e.evaluated_tag for e in AnchorePolicyEvaluation.objects.all()] == [OTHER_TAG]
        assert "no policy" in not_read()[f"policy:{DIGEST}:{TAG}"]

    def test_a_response_that_says_it_evaluated_another_tag_is_not_stored_under_this_one(self, secrets, monkeypatch):
        instance = server()
        instance.policy[(DIGEST, TAG)] = evaluation(tag=OTHER_TAG)
        run_against(monkeypatch, instance)
        assert [e.evaluated_tag for e in AnchorePolicyEvaluation.objects.all()] == [OTHER_TAG]
        assert "another tag" in not_read()[f"policy:{DIGEST}:{TAG}"]

    def test_a_tag_too_long_to_key_an_evaluation_is_recorded_not_written(self, secrets, monkeypatch):
        long = "registry.example/app:" + "t" * 600
        image = {**IMAGE, "image_detail": [{"registry": "registry.example", "repo": "app", "tag": "t" * 600, "full_tag": long}]}
        instance = Instance(images=[image])
        instance.policy[(DIGEST, long)] = evaluation(tag=long)
        run_against(monkeypatch, instance)
        assert AnchorePolicyEvaluation.objects.count() == 0 and f"policy:{DIGEST}:{long}" in not_read()

    def test_the_run_limit_holds_between_the_tags_of_one_image(self, tmp_path, monkeypatch):
        import itertools

        from tap_plugin.anchore.collectors.anchore_collector import collector as collector_module
        from tap_plugin.anchore.tests.test_collector_scope import configure

        configure(tmp_path, monkeypatch, {"running_only": False}, limits={"max_run_minutes": 1})
        # The clock is read for the deadline, once for the image, then once per tag: 25 s, 50 s, 75 s.
        ticks = itertools.count(0, 25)
        monkeypatch.setattr(collector_module, "_monotonic", lambda: float(next(ticks)))
        instance = server()
        run_against(monkeypatch, instance)
        asked = [str(call.url) for call in instance.transport.calls if "/check" in str(call.url)]
        assert len(asked) == 1 and AnchorePolicyEvaluation.objects.count() == 1
        assert "1-minute limit" in not_read()[f"policy:{DIGEST}:{OTHER_TAG}"]

    def test_an_image_with_no_tag_has_no_evaluation_and_is_not_called_unread(self, secrets, monkeypatch):
        collector = run_against(monkeypatch, Instance())
        assert AnchorePolicyEvaluation.objects.count() == 0
        assert not any(scope.startswith("policy:") for scope in not_read())
        (told,) = [m for m in collector.results["info"] if m["message_code"] == "POLICY_EVALUATIONS"]
        assert told["message_data"] == {"evaluations": 0, "failing": 0, "untagged_images": 1}

    def test_an_instance_that_refuses_the_base_parameter_is_asked_again_without_it(self, secrets, monkeypatch):
        instance = server()
        real = instance.transport.routes[f"/images/{DIGEST}/check"]
        from tap_plugin.anchore.tests.fakes import response

        instance.transport.routes[f"/images/{DIGEST}/check"] = lambda r: response(400, {"detail": "unknown parameter"}) if "base_digest" in str(r.url) else real(r)
        run_against(monkeypatch, instance)
        assert AnchorePolicyEvaluation.objects.count() == 2
