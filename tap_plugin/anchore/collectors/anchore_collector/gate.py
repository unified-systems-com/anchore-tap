"""The self-test, run against the instance (req-anchore-selftest-1 to -4).

Fetches the instance's own API description, reduces it with the reducer that built the committed
extract (``-5``), and compares it over the manifest's sources. A description the instance does not
serve is never recorded as a pass: the verdict is an error when the scanner's previous run recorded
the description as served (a gate that a server could pass by not answering is not a gate), and a
warning otherwise, the run then leaning on the per-response validation in ``validate.py`` (``-6``).

Reads only, through the read-only client; no grid, no Django. The previous run's fact is passed in by
the caller, which reads it from the grid. Messages name classes of failure, never response text.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tap_plugin.anchore.client import ClientError, ReadOnlyClient, RequestFailed
from tap_plugin.anchore.collectors.anchore_collector.manifest import Source, shipped_manifest
from tap_plugin.anchore.collectors.anchore_collector.selftest import ERROR, PASS, WARN, compare
from tap_plugin.anchore.contract.reduce import ReducerError, load_document, reduce_document

#: The instance's own OpenAPI file, relative to the API root (the same path the observation command reads).
SPEC_PATH = "/openapi.json"
_CONTRACT = Path(__file__).resolve().parents[2] / "contract"


@dataclass(frozen=True)
class SpecFetch:
    served: bool
    reason: str | None
    extract: dict[str, Any] | None = None
    version: str | None = None


@dataclass(frozen=True)
class GateResult:
    verdict: str
    ran: bool
    spec_served: bool
    detail: dict[str, Any]
    not_read: tuple[str, ...]

    @property
    def stops_the_run(self) -> bool:
        return self.verdict == ERROR

    def scan_run_fields(self) -> dict[str, Any]:
        """The scan run's selftest fields, and the sources the comparison found the instance does not offer."""
        return {
            "selftest_verdict": self.verdict,
            "selftest_detail": self.detail,
            "scopes_not_read": [{"scope": f"source:{s}", "reason": "not offered by the instance"} for s in self.not_read],
        }


def previous_spec_served(selftest_detail: Any) -> bool | None:
    """Whether the previous run recorded the description as served: True, False, or None when it did not say."""
    if isinstance(selftest_detail, dict) and isinstance(selftest_detail.get("spec_served"), bool):
        return selftest_detail["spec_served"]
    return None


def fetch_instance_extract(client: ReadOnlyClient, consumed: dict[str, Any] | None = None) -> SpecFetch:
    """Read and reduce the instance's own description. Never raises for what the instance does."""
    try:
        reply = client.get(SPEC_PATH)
    except RequestFailed as exc:
        last = exc.reply.status if exc.reply is not None else None
        return SpecFetch(False, f"failed after retries ({'HTTP ' + str(last) if last else 'no response'})")
    except ClientError as exc:
        return SpecFetch(False, f"refused before sending ({type(exc).__name__})")
    if reply.status in (401, 403):
        return SpecFetch(False, f"refused (HTTP {reply.status})")
    if reply.status == 404:
        return SpecFetch(False, "not offered (HTTP 404)")
    if reply.status != 200:
        return SpecFetch(False, f"unexpected HTTP {reply.status}")
    try:
        document = load_document(reply.body)
        wanted = consumed if consumed is not None else json.loads((_CONTRACT / "consumed.json").read_text(encoding="utf-8"))
        extract = reduce_document(document, wanted)
    except ReducerError:
        return SpecFetch(False, "the description was served but could not be read")
    return SpecFetch(True, None, extract, (extract.get("source") or {}).get("version"))


def run_selftest(
    client: ReadOnlyClient,
    *,
    previous_spec_served: bool | None,
    sources: tuple[Source, ...] | None = None,
    committed: dict[str, Any] | None = None,
    consumed: dict[str, Any] | None = None,
) -> GateResult:
    """Run the self-test. The caller stops the run, writing nothing, when ``stops_the_run``."""
    fetched = fetch_instance_extract(client, consumed)
    if fetched.served and fetched.extract is not None:
        baseline = committed if committed is not None else json.loads((_CONTRACT / "extract.json").read_text(encoding="utf-8"))
        result = compare(baseline, fetched.extract, sources if sources is not None else shipped_manifest())
        detail = {"ran": True, "spec_served": True, "instance_version": fetched.version, **result.as_detail()}
        return GateResult(result.verdict, True, True, detail, result.not_read)
    if previous_spec_served is True:
        verdict, message = ERROR, f"the instance described its API on the previous run and does not now ({fetched.reason}); a gate the server can pass by not answering is not a gate"
    else:
        verdict, message = WARN, f"the instance's API description was not available ({fetched.reason}); the self-test did not run, and every response is checked against the committed shapes instead"
    detail = {"ran": False, "spec_served": False, "differences": [{"level": verdict, "source": "*", "message": message}], "not_read": []}
    return GateResult(verdict, False, False, detail, ())


__all__ = ["ERROR", "PASS", "WARN", "GateResult", "SpecFetch", "fetch_instance_extract", "previous_spec_served", "run_selftest"]
