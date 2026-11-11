"""The Anchore collector: one run reads every configured scanner and submits one GRIFT batch.

For each credential it probes the instance (the account must be the configured one), runs the
self-test, lists the images, reads each analyzed image's vulnerabilities, and records what it read
and what it did not. A scanner that fails its probe or self-test, whose image list cannot be read, or that answers in a shape the
committed contract does not describe, is skipped with nothing written for it; a single image that cannot be read
(a failed request, a timeout) is recorded as not read and leaves its findings as they were. Reads only (``ReadOnlyClient``), each bounded by a wall-clock ceiling. Anchore's data is stored
as returned (req-anchore-findings-3); a finding a successful read of its image no longer reports is
marked resolved, never deleted, and an image that could not be read leaves its findings untouched.

Which images are read is the scope's decision (req-anchore-scope): the run reads Anchore's runtime
inventory, selects the records that count as running and are in scope, and reads only those images,
or every listed image when the envelope sets ``running_only`` false. Each selected inventory record
is written as a runtime image node. An image the scope leaves out is not read and its findings are
left as they were.

An ECS container Anchore reports is joined to the aws_core container with the same ARN, where the
grid has one, by ``RUNS_IMAGE`` to its image host; nothing on that container is written
(req-anchore-shared-1, -2). One the grid does not have is counted, unless the envelope sets
``create.ecs``: then the container and the task, service and cluster it leads to are created where
the grid has none, from what Anchore reported, with the hazards the spec lists.

With ``create.kubernetes``, on by default, the Kubernetes objects behind the running containers
are written into computing_core's Kubernetes types: cluster, namespace, node (with its host row),
pod and container, and the edges between them (req-anchore-inventory-kubernetes).

Not in this slice: VEX and application reads.

Spec: specs/spec-anchore-v0.md (req-anchore-findings, -probe, -selftest, -states, -scope, -inventory).
"""

import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

from tap import secrets_root

from tap_cares.collectors import CeilingExceeded, CollectorBase, run_with_ceiling
from tap_plugin.anchore import batching, kubernetes
from tap_plugin.computing_core.sbom import SbomParseError, Verification, parse_cyclonedx
from tap_plugin.anchore import scope as scoping
from tap_cares.collectors.readiness import CollectorReadinessStatus, CollectorSelfTestResult, check_fail, check_pass
from tap_plugin.anchore.client import TOTAL_BUDGET_SECONDS, ClientError, ReadOnlyClient, fill
from tap_plugin.anchore.collectors.anchore_collector import decompose, store
from tap_plugin.anchore.collectors.anchore_collector.gate import previous_spec_served, run_selftest
from tap_plugin.anchore.collectors.anchore_collector.manifest import Source, shipped_manifest
from tap_plugin.anchore.collectors.anchore_collector.probe import ProbeError, run_probe
from tap_plugin.anchore.collectors.anchore_collector.validate import validate_body
from tap_plugin.anchore.credential import Credential, canonical_root, discover

# record_* call-site tokens, minted with scripts/log-site-id.
_SITE_RUN_STARTED = "7797"
_SITE_NO_CREDENTIAL = "863b"
_SITE_CREDENTIAL_REFUSED = "bba8"
_SITE_SCANNER_SKIPPED = "29b1"
_SITE_SELFTEST = "eb84"
_SITE_IMAGES_NOT_READ = "99cc"
_SITE_IMAGE_NOT_READ = "5753"
_SITE_FIELDS_DROPPED = "adfb"
_SITE_ENTRIES = "73f3"
_SITE_STALE_FEEDS = "d0d8"
_SITE_RUN_FINISHED = "5c3d"
_SITE_NOTHING_WRITTEN = "ecc2"
_SITE_SBOM_NOT_READ = "bf32"
_SITE_NOT_LINKED = "f422"
_SITE_HOST_CREATED = "729b"
_SITE_PLAINTEXT = "684a"
_SITE_INVENTORY_NOT_READ = "8828"
_SITE_SCOPE = "8f55"
_SITE_INVENTORY_UNUSABLE = "a83a"
_SITE_ECS_LINK = "2f25"
_SITE_ECS_CREATE = "b1f6"
_SITE_KUBERNETES = "0070"
_SITE_BASE_IMAGE = "57eb"
_SITE_RUN_LIMIT = "49b9"
_SITE_PARENT_DIGEST = "7591"
_SITE_SBOM_PARSED = "dc6c"
_SITE_BATCHES = "c9cb"
_SITE_POLICY = "0c47"

#: A read's own budget is TOTAL_BUDGET_SECONDS; the ceiling sits above it so the client's
#: retry accounting ends the call first and the ceiling only catches what that cannot (DNS, a trickle).
READ_CEILING_SECONDS = TOTAL_BUDGET_SECONDS + 30
#: A feed whose last sync is older than this is recorded as stale (req-anchore-probe-3); it is a fact, not a verdict.
FEED_MAX_AGE = timedelta(days=2)
#: How many dropped values a run record lists by name; the counts are always exact.
_LISTED = 50
#: The most pages of ECS containers one run reads. The list has no documented end marker, so a page
#: that adds nothing new ends it; this is the stop for an instance that never sends one.
ECS_PAGE_LIMIT = 500
#: computing_core's Kubernetes types (req-computing-core-kubernetes), by the plan's kind.
KUBERNETES_TYPES = {kind: f"computing_core__kubernetes_{kind}" for kind in ("cluster", "namespace", "node", "pod", "container")}
#: The four lists and the wrapper keys each may arrive under. The vendor's file puts the node and
#: pod lists under ``namespaces``, which looks like a copy of the namespace response; the natural
#: key is accepted too until a recorded response settles it (req-anchore-inventory-kubernetes-3).
KUBERNETES_LISTS = (
    ("kubernetes_namespaces", ("namespaces",)),
    ("kubernetes_nodes", ("nodes", "namespaces")),
    ("kubernetes_pods", ("pods", "namespaces")),
    ("kubernetes_containers", ("containers",)),
)


class AnchoreCollectorError(Exception):
    """The run wrote nothing."""


class _ScannerSkipped(Exception):
    """One scanner is skipped; the others go on."""


@dataclass
class _Scanner:
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    findings: int = 0
    resolved: int = 0
    images_read: int = 0
    images_not_read: int = 0
    sboms: int = 0
    hosts_created: int = 0
    unlinked_images: int = 0
    vulnerability_links: int = 0
    hosts: set[str] = field(default_factory=set)
    sbom_refs: dict[str, str] = field(default_factory=dict)
    describes: set[tuple[str, str]] = field(default_factory=set)
    runtime_images: int = 0
    ecs_links: int = 0
    runs_image: set[tuple[str, str]] = field(default_factory=set)
    #: (image digest, ancestor digest) of each BUILT_ON_IMAGE edge this scanner staged.
    built_on: set[tuple[str, str]] = field(default_factory=set)
    #: Batch refs of the inventory rows (packages, libraries, operating systems, their edges) staged from parsed SBOMs.
    inventory_refs: set[str] = field(default_factory=set)
    #: Image hosts on the grid this scanner staged a name or operating system for, and the image records it staged.
    host_fills: set[str] = field(default_factory=set)
    image_records: int = 0
    #: Policy evaluations read, and how many of them Anchore marked as failing.
    policy_evaluations: int = 0
    policy_failures: int = 0
    policy_untagged: int = 0
    #: Content digests of the documents whose parsed inventory this scanner staged (not merely recorded).
    inventory_documents: set[str] = field(default_factory=set)
    #: SBOMs parsed into inventory, documents whose inventory was staged, rows staged, and findings joined to a package.
    sboms_parsed: int = 0
    sboms_staged: int = 0
    package_links: int = 0
    #: (index digest, platform image digest) of each INDEXES_PLATFORM_IMAGE edge this scanner staged.
    platform_of: set[tuple[str, str]] = field(default_factory=set)
    #: Images whose vulnerabilities response named a base image, and images read without the base parameter.
    images_with_base: int = 0
    #: Images not read because the run reached limits.max_run_minutes.
    images_out_of_time: int = 0
    #: Ancestors left unwritten because none of their tags is inside repository_prefixes.
    ancestors_out_of_scope: int = 0
    images_base_refused: int = 0
    #: ARN -> batch ref of each aws_core ECS node this scanner staged for creation.
    ecs_created: dict[str, str] = field(default_factory=dict)
    #: (kind, natural key) -> batch ref of each Kubernetes object, node host or edge this scanner staged.
    kubernetes: dict[tuple[str, Any], str] = field(default_factory=dict)
    #: The scope fields the scan run records (req-anchore-scope-14).
    run_fields: dict[str, Any] = field(default_factory=dict)


@dataclass
class _Shared:
    """What the batch already holds from scanners that finished, so two scanners never stage one node twice.

    A scanner that is skipped contributes nothing here, because everything it staged is dropped with it.
    """

    hosts: set[str] = field(default_factory=set)
    documents: set[str] = field(default_factory=set)
    describes: set[tuple[str, str]] = field(default_factory=set)
    runs_image: set[tuple[str, str]] = field(default_factory=set)
    built_on: set[tuple[str, str]] = field(default_factory=set)
    platform_of: set[tuple[str, str]] = field(default_factory=set)
    inventory_refs: set[str] = field(default_factory=set)
    inventory_documents: set[str] = field(default_factory=set)
    host_fills: set[str] = field(default_factory=set)
    ecs_created: dict[str, str] = field(default_factory=dict)
    kubernetes: dict[tuple[str, Any], str] = field(default_factory=dict)

    def absorb(self, scanner: _Scanner) -> None:
        self.ecs_created.update(scanner.ecs_created)
        self.kubernetes.update(scanner.kubernetes)
        self.hosts |= scanner.hosts
        self.documents |= set(scanner.sbom_refs)
        self.describes |= scanner.describes
        self.runs_image |= scanner.runs_image
        self.built_on |= scanner.built_on
        self.platform_of |= scanner.platform_of
        self.inventory_refs |= scanner.inventory_refs
        self.inventory_documents |= scanner.inventory_documents
        self.host_fills |= scanner.host_fills


#: The clock the run time limit is measured on; a test replaces it.
_monotonic = time.monotonic


def _bounded(call: Any, what: str) -> Any:
    return run_with_ceiling(call, READ_CEILING_SECONDS, name=f"anchore-{what}")


@dataclass(frozen=True)
class Failure:
    """Why a read gave nothing. ``incompatible`` means the instance answered in a shape the committed contract does not describe."""

    reason: str
    incompatible: bool = False
    #: The HTTP status, when the instance answered with one that is not 200.
    status: int | None = None

    @property
    def refused(self) -> bool:
        """The instance said the request itself is not one it accepts: 400 or 422, and nothing else.

        Not 401 or 403 (who is asking), not 404 (what is asked for), and not 408 or 429, which are
        about now and not about the request.
        """
        return self.status in (400, 422)


def _get_json(client: ReadOnlyClient, extract: dict[str, Any], source: Source, path: str, params: dict[str, Any] | None = None) -> tuple[Any, Failure | None]:
    """(body, None) for a read that returned the committed shape, else (None, why). Never raises for what the instance does."""
    try:
        reply = _bounded(lambda: client.get(path, params=params), source.id)
    except CeilingExceeded:
        return None, Failure("the read did not finish within its ceiling")
    except ClientError as exc:
        return None, Failure(f"not read ({type(exc).__name__})")
    if reply.status != 200:
        return None, Failure(f"HTTP {reply.status}", status=reply.status)
    try:
        body = json.loads(reply.body)
    except ValueError:
        return None, Failure("the body was not JSON", incompatible=True)
    checked = validate_body(extract, source, reply.status, body)
    return (body, None) if checked.ok else (None, Failure(checked.reason or "the body did not match the committed shape", incompatible=True))


def _image_entries(body: Any) -> list[Any] | None:
    items = body.get("items") if isinstance(body, dict) else body
    return items if isinstance(items, list) else None


#: A digest is the finding's target key; a longer one cannot be held, so the image is unidentified.
_MAX_DIGEST = 512


class AnchoreCollector(CollectorBase):
    """Collect vulnerability findings from every configured Anchore instance."""

    # A run reads one list and one request per image; the falsifier budget is not used (no reconcile yet).
    RECONCILE_BUDGET_DEFAULT: ClassVar[int] = 0

    @classmethod
    def self_test(cls) -> CollectorSelfTestResult:
        """Whether a usable credential exists. Reads no instance."""
        usable, refused = discover(secrets_root.resolve())
        if usable:
            return CollectorSelfTestResult.from_checks(
                [check_pass("CREDENTIAL_PRESENT", f"{len(usable)} usable credential(s); {len(refused)} refused.", context={"usable": [c.qualified for c in usable], "refused": [e.qualified for e in refused]})],
                summary="A credential is configured.",
            )
        return CollectorSelfTestResult.from_checks(
            [check_fail("NO_CREDENTIAL", "No usable credential in scope anchore.", readiness_status=CollectorReadinessStatus.UNCONFIGURED, context={"refused": [e.qualified for e in refused]})],
            summary="No credential is configured.",
        )

    def run(self) -> None:
        self.record_info(_SITE_RUN_STARTED, "RUN_STARTED", "Anchore collection started.")
        usable, refused = discover(secrets_root.resolve())
        for error in refused:
            self.record_warn(_SITE_CREDENTIAL_REFUSED, "CREDENTIAL_REFUSED", str(error), message_data={"credential": error.qualified})
        if not usable:
            self.record_error(_SITE_NO_CREDENTIAL, "NO_CREDENTIAL", "No usable credential in scope anchore; nothing was read or written.")
            raise AnchoreCollectorError("no usable credential")

        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        written: list[str] = []
        shared = _Shared()
        for number, credential in enumerate(usable):
            try:
                scanner = self._scan(credential, f"s{number}", shared)
            except _ScannerSkipped as exc:
                self.record_error(_SITE_SCANNER_SKIPPED, "SCANNER_SKIPPED", str(exc), message_data={"credential": credential.qualified})
                continue
            shared.absorb(scanner)
            nodes.extend(scanner.nodes)
            edges.extend(scanner.edges)
            written.append(f"{credential.qualified}: {scanner.findings} finding(s), {scanner.resolved} resolved, {scanner.images_read} image(s) read, {scanner.images_not_read} not read, {scanner.sboms} SBOM(s) recorded, {scanner.runtime_images} running image record(s), {scanner.ecs_links} ECS container(s) linked")
        if not written:
            self.summary = "No scanner could be read; nothing was written."
            self.record_error(_SITE_NOTHING_WRITTEN, "NOTHING_WRITTEN", self.summary)
            raise AnchoreCollectorError(self.summary)

        # One write per batch: the smallest limit any credential of this run sets (req-anchore-limits-7).
        max_rows = min(credential.settings.max_batch_rows for credential in usable)
        batches, unsplit = batching.split(nodes, edges, max_rows, store.natural_key_of)
        if unsplit is not None:
            self.record_warn(_SITE_BATCHES, "BATCH_NOT_SPLIT", f"The run's {len(nodes) + len(edges)} row(s) were written as one batch, over the limit of {max_rows}: {unsplit}.")
        elif len(batches) > 1:
            self.record_info(_SITE_BATCHES, "BATCHES", f"The run's {len(nodes) + len(edges)} row(s) were written as {len(batches)} batches of at most {max_rows}.", message_data={"rows": len(nodes) + len(edges), "batches": len(batches), "max_rows": max_rows})
        self.submit_grift(self._document(batches, written))
        self.summary = "; ".join(written)
        self.record_info(_SITE_RUN_FINISHED, "RUN_FINISHED", self.summary)

    def _scan(self, credential: Credential, tag: str, shared: _Shared) -> _Scanner:
        sources = shipped_manifest()
        by_id = {s.id: s for s in sources}
        extract = json.loads((_contract_dir() / "extract.json").read_text(encoding="utf-8"))
        run_id = decompose.new_run_id()
        started = datetime.now(UTC)
        previous = store.previous_run(credential.scanner_key)
        out = _Scanner()
        not_read: list[dict[str, str]] = []
        read: list[str] = []

        if credential.plaintext:
            # Allowed on purpose (the operator wrote the scheme), but never silent.
            self.record_warn(_SITE_PLAINTEXT, "PLAINTEXT_TRANSPORT", f"{credential.qualified}: this instance is read over plain http, so the credential and every response cross the network unencrypted.", message_data={"credential": credential.qualified})

        # The run time limit counts from here, the first request (req-anchore-limits-3).
        limit = credential.settings.max_run_minutes
        deadline = _monotonic() + limit * 60 if limit is not None else None
        with ReadOnlyClient(credential) as client:
            try:
                probe = _bounded(lambda: run_probe(client, credential.account, sources, qualified=credential.qualified), "probe")
            except ProbeError as exc:
                raise _ScannerSkipped(str(exc)) from None
            except CeilingExceeded:
                raise _ScannerSkipped(f"{credential.qualified}: the probe did not finish within its ceiling; nothing was read or written") from None
            try:
                gate = _bounded(lambda: run_selftest(client, previous_spec_served=previous_spec_served(previous.selftest_detail if previous else None), sources=sources), "selftest")
            except CeilingExceeded:
                raise _ScannerSkipped(f"{credential.qualified}: the self-test did not finish within its ceiling; nothing was written") from None
            if gate.stops_the_run:
                raise _ScannerSkipped(f"{credential.qualified}: the self-test failed: {gate.detail['differences'][0]['message'] if gate.detail.get('differences') else 'see the scan run'}; nothing was written")
            for difference in gate.detail.get("differences", []):
                self.record_warn(_SITE_SELFTEST, "SELFTEST_DIFFERENCE", f"{credential.qualified}: {difference.get('level')}: {difference.get('message')}")
            not_read.extend(probe.not_read())
            not_read.extend(gate.scan_run_fields()["scopes_not_read"])
            for stale in probe.stale_feeds(started, FEED_MAX_AGE):
                self.record_warn(_SITE_STALE_FEEDS, "FEED_STALE", f"{credential.qualified}: feed {stale['feed']} group {stale['group']} last synced {stale['age_seconds']} seconds ago.", message_data=stale)

            self._images(client, credential, extract, by_id, run_id, out, read, not_read, tag, shared, started, deadline)

        finished = datetime.now(UTC)
        scanner_ref, run_ref = f"{tag}:scanner", f"{tag}:run"
        out.nodes.insert(0, decompose.scanner_node(scanner_ref, canonical_root(credential.base_url), credential.account, credential.scanner_key, probe.reported_version))
        out.nodes.insert(1, decompose.scan_run_node(
            run_ref, credential.scanner_key, run_id,
            started_at=started.isoformat(), finished_at=finished.isoformat(), reported_version=probe.reported_version,
            status=probe.body("status") if isinstance(probe.body("status"), dict) else None,
            feeds=probe.body("feeds") if isinstance(probe.body("feeds"), list) else None,
            selftest_verdict=gate.verdict, selftest_detail=gate.detail, scopes_read=read, scopes_not_read=not_read,
            **out.run_fields,
        ))
        out.edges.append(decompose.edge(f"{tag}:run-of", "RUN_OF_SCANNER__anchore", run_ref, scanner_ref))
        return out

    def _images(self, client: ReadOnlyClient, credential: Credential, extract: dict[str, Any], by_id: dict[str, Source], run_id: str, out: _Scanner, read: list[str], not_read: list[dict[str, str]], tag: str, shared: _Shared, started: datetime, deadline: float | None = None) -> None:
        # The image list is a required source (req-anchore-selftest-6): without it there is no walk, so the
        # scanner stops with nothing written rather than recording a run that read nothing.
        listed, failure = _get_json(client, extract, by_id["images"], by_id["images"].path)
        entries = _image_entries(listed) if failure is None else None
        if entries is None:
            raise _ScannerSkipped(f"{credential.qualified}: the image list could not be read ({failure.reason if failure else 'it was not a list'}); nothing was written")
        read.append("source:images")
        dropped: list[dict[str, str]] = []
        skipped = duplicates = 0
        uncarried: set[str] = set()
        unidentified = repeated = 0
        # One entry per digest, in list order; of repeats the analyzed one is kept, so the order of a
        # repeated entry cannot hide an image that can be read.
        chosen: dict[str, dict[str, Any]] = {}
        for image in entries:
            digest = image.get("image_digest") if isinstance(image, dict) else None
            if not isinstance(digest, str) or not digest or len(digest) > _MAX_DIGEST:
                unidentified += 1
            elif digest in chosen:
                repeated += 1
                if chosen[digest].get("analysis_status") != "analyzed" and image.get("analysis_status") == "analyzed":
                    chosen[digest] = image
            else:
                chosen[digest] = image
        # Which of the listed images this run reads (req-anchore-scope). The rest are out of scope:
        # not read, not listed one by one, and their findings left exactly as they were.
        settings = credential.settings
        inventory_read: list[str] = []
        running = self._running(client, credential, extract, by_id, started, inventory_read, not_read)
        plan = scoping.images_to_read(chosen, running.digests if running is not None else None, settings)
        if not settings.running_only and settings.has_running_selector:
            not_read.append({"scope": "scope:selectors-do-not-narrow-images", "reason": "running_only is false, so the account and context selectors did not narrow the images read; they decide only which inventory records are written"})
        for absent in plan.not_in_anchore:
            # Running, by the inventory, and unknown to the image list: no findings, which is not none found.
            not_read.append({"scope": f"image:{absent}", "reason": "reported running by the inventory but not in Anchore's image list (scope:not-in-anchore)"})
        out.run_fields = {
            "settings": settings.as_recorded(),
            "images_listed": plan.images_listed,
            "images_selected": plan.images_selected,
            "images_out_of_scope": plan.images_out_of_scope,
            "images_not_in_anchore": len(plan.not_in_anchore),
            "inventory_stale": running.stale if running is not None else None,
        }
        self.record_info(_SITE_SCOPE, "SCOPE_APPLIED", f"{credential.qualified}: {plan.images_selected} of {plan.images_listed} listed image(s) selected, {plan.images_out_of_scope} out of scope, {len(plan.not_in_anchore)} running digest(s) not in the image list, {running.out_of_repository if running is not None else 0} running record(s) outside the repository prefixes.", message_data={**out.run_fields, "inventory_out_of_repository": running.out_of_repository if running is not None else None})
        for index, digest in enumerate(plan.digests):
            image = chosen[digest]
            scope = f"image:{digest}"
            # Anchore's own record of the image comes from the list already read, so it is written
            # whether or not the image's findings can be read this run (req-anchore-image-1).
            self._image_record(credential, image, digest, f"{tag}:i{index}", out, shared)
            if deadline is not None and _monotonic() >= deadline:
                # Out of time: not read is never clean, so each image left is named and nothing of it is resolved.
                not_read.append({"scope": scope, "reason": f"not read: the run reached its {settings.max_run_minutes}-minute limit (limits.max_run_minutes)"})
                out.images_not_read += 1
                out.images_out_of_time += 1
                continue
            if image.get("analysis_status") != "analyzed":
                not_read.append({"scope": scope, "reason": f"analysis_status is {image.get('analysis_status')!r}"})
                out.images_not_read += 1
                continue
            vuln_path = fill(by_id["image_vulnerabilities"].path, image_digest=digest, vuln_type="all")
            # Ask Anchore to work out the base image, so each finding says whether the base held it
            # (req-anchore-base-image-1). An instance that turns the parameter down is read without it.
            body, failure = _get_json(client, extract, by_id["image_vulnerabilities"], vuln_path, params={"base_digest": "auto"})
            if failure is not None and failure.refused:
                refused = failure.reason
                body, failure = _get_json(client, extract, by_id["image_vulnerabilities"], vuln_path)
                if failure is None:
                    out.images_base_refused += 1
                    not_read.append({"scope": f"base:{digest}", "reason": f"the instance refused base_digest=auto ({refused}); the findings were read without base-image attribution"})
            if failure is not None and failure.incompatible:
                # A response that does not have the committed shape is not a transient failure: the contract this
                # collector parses no longer describes the instance, so no image of it is trusted this run.
                raise _ScannerSkipped(f"{credential.qualified}: a vulnerability response did not match the committed shape ({failure.reason}); nothing was written")
            vulns = body.get("vulnerabilities") if isinstance(body, dict) else None
            if failure is not None or not isinstance(vulns, list):
                why = failure.reason if failure else "the response held no vulnerability list"
                not_read.append({"scope": scope, "reason": why})
                out.images_not_read += 1
                self.record_warn(_SITE_IMAGE_NOT_READ, "IMAGE_NOT_READ", f"{credential.qualified}: image {index} was not read ({why}); its findings were left as they were.")
                # The documents are separate reads: a failed vulnerability read does not stop them.
                self._ensure_host(out, digest, f"{tag}:h{index}", shared)
                self._sboms(client, credential, by_id, digest, f"{tag}:d{index}", out, read, not_read, shared)
                continue
            base = body.get("base_digest")
            base = base if isinstance(base, str) and decompose.OCI_DIGEST.fullmatch(base) and base != digest else None
            out.images_with_base += base is not None
            result = decompose.decompose_image(vulns, credential.scanner_key, digest, run_id, f"{tag}:f{index}", base)
            out.nodes.extend(result.nodes)
            out.findings += len(result.nodes)
            if result.skipped_entries:
                # An entry that could not be stored may be a finding already held, so absence from this
                # read proves nothing: nothing of this image is resolved.
                not_read.append({"scope": f"resolution:{digest}", "reason": f"{result.skipped_entries} entry(ies) could not be stored, so findings absent from this read were not resolved"})
            else:
                for row in store.current_findings(credential.scanner_key, digest):
                    if (row.vulnerability_id, row.package_key) not in result.seen_keys:
                        out.nodes.append(decompose.resolved_node(row, run_id, f"{tag}:r{index}:{out.resolved}"))
                        out.resolved += 1
            out.images_read += 1
            read.append(scope)
            self._ancestors(client, credential, extract, by_id["image_ancestors"], digest, f"{tag}:a{index}", out, shared, read, not_read)
            self._policy(client, credential, extract, by_id["image_policy_check"], image, digest, run_id, f"{tag}:p{index}", out, read, not_read)
            self._ensure_host(out, digest, f"{tag}:h{index}", shared)
            self._link_image(out, result.nodes, digest)
            packages = self._sboms(client, credential, by_id, digest, f"{tag}:d{index}", out, read, not_read, shared)
            self._link_packages(out, result.nodes, packages)
            dropped.extend(result.dropped_fields)
            skipped += result.skipped_entries
            duplicates += result.duplicate_entries
            uncarried |= result.uncarried_keys
        self._runtime_images(credential, running, out, tag, shared, plan.analyzed_for)
        # The two steps below make further reads; past the limit they are not started (req-anchore-limits-4).
        out_of_time = deadline is not None and _monotonic() >= deadline
        if out_of_time:
            why = f"not read: the run reached its {settings.max_run_minutes}-minute limit (limits.max_run_minutes)"
            if settings.create_ecs:
                not_read.append({"scope": "create:ecs", "reason": why})
            if settings.create_kubernetes:
                not_read.append({"scope": "create:kubernetes", "reason": why})
        else:
            self._ecs_create(client, credential, extract, by_id, running, out, tag, shared, inventory_read, not_read)
        self._ecs_links(credential, running, out, tag, shared, inventory_read, not_read)
        if not out_of_time:
            self._kubernetes(client, credential, extract, by_id, out, tag, shared, inventory_read, not_read, started)
        if out_of_time or out.images_out_of_time:
            self.record_warn(_SITE_RUN_LIMIT, "RUN_TIME_LIMIT_REACHED", f"{credential.qualified}: the run reached its {settings.max_run_minutes}-minute limit; {out.images_out_of_time} image(s) were not read and their findings were left as they were. What was read is written.", message_data={"max_run_minutes": settings.max_run_minutes, "images_not_read": out.images_out_of_time})
        read.extend(inventory_read)
        for gone in sorted(store.current_target_keys(credential.scanner_key) - set(chosen)):
            # An image that left the list is not a cleared image: its findings stay as they were, and say so.
            not_read.append({"scope": f"image:{gone}", "reason": "no longer in the image list; its findings were left as they were"})
        if out.images_read:
            self.record_info(_SITE_BASE_IMAGE, "BASE_IMAGES", f"{credential.qualified}: Anchore named a base image for {out.images_with_base} of {out.images_read} image(s) read; {out.images_base_refused} were read without the base parameter; {len(out.built_on)} ancestor link(s) written, {out.ancestors_out_of_scope} ancestor(s) outside the repository prefixes not written.", message_data={"images_read": out.images_read, "with_base": out.images_with_base, "base_refused": out.images_base_refused, "ancestor_links": len(out.built_on), "ancestors_out_of_scope": out.ancestors_out_of_scope})
        if out.policy_evaluations or out.policy_untagged:
            self.record_info(_SITE_POLICY, "POLICY_EVALUATIONS", f"{credential.qualified}: {out.policy_evaluations} policy evaluation(s) read, {out.policy_failures} failing; {out.policy_untagged} image(s) carry no tag and so have no evaluation.", message_data={"evaluations": out.policy_evaluations, "failing": out.policy_failures, "untagged_images": out.policy_untagged})
        if out.sboms_parsed:
            self.record_info(_SITE_SBOM_PARSED, "SBOMS_PARSED", f"{credential.qualified}: {out.sboms_parsed} CycloneDX SBOM(s) parsed as source-authenticated; the inventory of {out.sboms_staged} was written ({len(out.inventory_refs)} row(s)); {out.package_links} finding(s) joined to a package.", message_data={"parsed": out.sboms_parsed, "staged": out.sboms_staged, "rows": len(out.inventory_refs), "package_links": out.package_links})
        if out.hosts_created:
            self.record_info(_SITE_HOST_CREATED, "IMAGE_HOSTS_CREATED", f"{credential.qualified}: {out.hosts_created} image host(s) did not exist on the grid and were written with only their digest.")
        if out.unlinked_images:
            self.record_warn(_SITE_NOT_LINKED, "IMAGES_NOT_LINKED", f"{credential.qualified}: {out.unlinked_images} image(s) have a digest that is not a plain sha256 digest, so their findings and documents have no host edge.")
        missed = [n for n in not_read if n["scope"].startswith("sbom:")]
        if missed:
            self.record_warn(_SITE_SBOM_NOT_READ, "SBOM_NOT_READ", f"{credential.qualified}: {len(missed)} SBOM read(s) did not return a document.", message_data={"count": len(missed), "reads": missed[:_LISTED]})
        if unidentified:
            not_read.append({"scope": "source:images:entries", "reason": f"{unidentified} entry(ies) of the image list named no usable image_digest and were not read"})
            self.record_warn(_SITE_IMAGES_NOT_READ, "IMAGES_NOT_READ", f"{credential.qualified}: {unidentified} entry(ies) of the image list named no usable image_digest and were not read.")
        if repeated:
            self.record_warn(_SITE_IMAGES_NOT_READ, "IMAGES_REPEATED", f"{credential.qualified}: {repeated} entry(ies) of the image list repeated a digest already listed and were read once.")
        if dropped:
            self.record_warn(_SITE_FIELDS_DROPPED, "FIELDS_DROPPED", f"{credential.qualified}: {len(dropped)} value(s) could not be held by the model; each is listed with what became of it.", message_data={"count": len(dropped), "values": dropped[:_LISTED]})
        if skipped or duplicates or uncarried:
            self.record_warn(_SITE_ENTRIES, "ENTRIES_NOT_STORED", f"{credential.qualified}: {skipped} entry(ies) named no usable identifier, {duplicates} repeated an assertion already held, and {len(uncarried)} response key(s) are not stored.", message_data={"skipped": skipped, "duplicates": duplicates, "uncarried_keys": sorted(uncarried)})

    def _running(self, client: ReadOnlyClient, credential: Credential, extract: dict[str, Any], by_id: dict[str, Source], started: datetime, read: list[str], not_read: list[dict[str, str]]) -> scoping.Running | None:
        """The running selection from Anchore's inventory, or None when the inventory could not be read.

        None selects nothing (req-anchore-scope-9): a run never widens to every image because a selector
        failed. The ECS container list is a second read; without it no ECS container is in the selection
        and the account selector matches nothing, and the run says so.
        """
        source = by_id["inventories"]
        body, failure = _get_json(client, extract, source, source.path)
        items = body.get("items") if isinstance(body, dict) else None
        if failure is not None or not isinstance(items, list):
            why = failure.reason if failure is not None else "the response held no item list"
            not_read.append({"scope": "source:inventories", "reason": f"{why}; no running image was selected"})
            self.record_warn(_SITE_INVENTORY_NOT_READ, "INVENTORY_NOT_READ", f"{credential.qualified}: the runtime inventory was not read ({why}); no running image was selected.")
            return None
        read.append("source:inventories")
        containers, why = self._ecs_containers(client, extract, by_id["ecs_containers"])
        if why is None:
            read.append("source:ecs-containers")
        else:
            not_read.append({"scope": "source:ecs-containers", "reason": f"{why}; no ECS container was selected"})
            self.record_warn(_SITE_INVENTORY_NOT_READ, "ECS_CONTAINERS_NOT_READ", f"{credential.qualified}: the ECS container list was not read ({why}); no ECS container was selected.")
        return scoping.select_running([item for item in items if isinstance(item, dict)], containers, credential.settings, started)

    def _ecs_containers(self, client: ReadOnlyClient, extract: dict[str, Any], source: Source) -> tuple[list[dict[str, Any]], str | None]:
        """(every ECS container record, None), or ([], why) when the list could not be read whole."""
        return self._paged(client, extract, source, "containers")

    def _paged(self, client: ReadOnlyClient, extract: dict[str, Any], source: Source, wrapper: str | tuple[str, ...]) -> tuple[list[dict[str, Any]], str | None]:
        """(every record of a paged ECS list, None), or ([], why) when it could not be read whole.

        These lists are paged by a required ``page`` and document no end marker, so reading stops at
        the first page that adds no record not already seen: an empty page, or an instance that
        ignores the parameter and repeats itself. A partial list is no list: what depends on it
        fails closed.
        """
        seen: dict[str, dict[str, Any]] = {}
        for page in range(1, ECS_PAGE_LIMIT + 1):
            body, failure = _get_json(client, extract, source, source.path, params={"page": page})
            # The first wrapper key the body carries a list under; a body with none of them is no list.
            keys = (wrapper,) if isinstance(wrapper, str) else wrapper
            rows = next((body[key] for key in keys if isinstance(body.get(key), list)), None) if isinstance(body, dict) else None
            if failure is not None or rows is None:
                return [], f"page {page}: {failure.reason if failure is not None else 'the response held no record list'}"
            before = len(seen)
            for row in rows:
                if isinstance(row, dict):
                    seen.setdefault(json.dumps(row, sort_keys=True, default=str), row)
            if len(seen) == before:
                return list(seen.values()), None
        return [], f"the list did not end within {ECS_PAGE_LIMIT} pages"

    def _runtime_images(self, credential: Credential, running: scoping.Running | None, out: _Scanner, tag: str, shared: _Shared, analyzed_for: dict[str, list[str]]) -> None:
        """One runtime image node per selected inventory item, joined to its image host (req-anchore-scope-12).

        Written whatever else the run creates. The host is staged with only its digest where neither the
        batch nor the grid has one, for an image Anchore never analyzed as for any other.
        """
        if running is None:
            return
        unusable = several = 0
        for number, item in enumerate(running.items):
            if not decompose.runtime_image_identified(item):
                unusable += 1
                continue
            digest = item["image_digest"]
            self._ensure_host(out, digest, f"{tag}:rh{number}", shared)
            ref = f"{tag}:ri{number}"
            analyzed = sorted(analyzed_for.get(digest, ()))
            out.nodes.append(decompose.runtime_image_node(ref, credential.scanner_key, item, analyzed))
            out.edges.append(decompose.edge_to_key(f"{ref}:image", "OBSERVES_IMAGE__anchore", ref, "computing_core__host", decompose.host_key(digest)))
            out.runtime_images += 1
            # The running digest is an index and Anchore analyzed the platform image(s) under it: join the
            # two hosts, so what runs the index reaches the findings on the image (req-anchore-scope-16).
            for position, image in enumerate(analyzed):
                if image == digest or (digest, image) in out.platform_of or (digest, image) in shared.platform_of:
                    continue
                out.platform_of.add((digest, image))
                self._ensure_host(out, image, f"{ref}:p{position}:host", shared)
                out.edges.append(decompose.edge_between_keys(f"{ref}:p{position}", "INDEXES_PLATFORM_IMAGE__anchore", "computing_core__host", decompose.host_key(digest), "computing_core__host", decompose.host_key(image)))
            several += len([image for image in analyzed if image != digest]) > 1
        if out.platform_of:
            self.record_info(_SITE_PARENT_DIGEST, "RUNNING_DIGESTS_MATCHED_BY_PARENT", f"{credential.qualified}: {len({index for index, _ in out.platform_of})} running digest(s) were matched to analyzed image(s) by parent_digest; {several} runtime record(s) had more than one analyzed image under their digest and all were read.", message_data={"indexes": len({index for index, _ in out.platform_of}), "links": len(out.platform_of), "records_with_several": several})
        if unusable or running.no_digest or running.ecs_without_inventory:
            self.record_warn(_SITE_INVENTORY_UNUSABLE, "INVENTORY_RECORDS_NOT_USED", f"{credential.qualified}: {running.no_digest} inventory record(s) named no usable digest, {unusable} named no usable type or context, and {running.ecs_without_inventory} ECS container(s) had no recent inventory item to take a last-seen time from.", message_data={"no_digest": running.no_digest, "unusable": unusable, "ecs_without_inventory": running.ecs_without_inventory})

    def _kubernetes(self, client: ReadOnlyClient, credential: Credential, extract: dict[str, Any], by_id: dict[str, Source], out: _Scanner, tag: str, shared: _Shared, read: list[str], not_read: list[dict[str, str]], started: datetime) -> None:
        """With ``create.kubernetes``: write the Kubernetes objects behind the running containers (req-anchore-inventory-kubernetes).

        No other collector writes these types, so this plugin creates them and keeps them current:
        each run writes what Anchore reported for the objects in scope. All four lists must be read
        whole, or nothing is written: a pod without its namespace list would lose its place.
        """
        if not credential.settings.create_kubernetes:
            return
        if not store.types_installed(list(KUBERNETES_TYPES.values())):
            not_read.append({"scope": "create:kubernetes", "reason": "the installed computing_core has no Kubernetes types (v0.10.4 or later is needed), so no Kubernetes object was written"})
            return
        lists: dict[str, list[dict[str, Any]]] = {}
        for source_id, wrappers in KUBERNETES_LISTS:
            rows, why = self._paged(client, extract, by_id[source_id], wrappers)
            if why is not None:
                not_read.append({"scope": "create:kubernetes", "reason": f"{by_id[source_id].path}: {why}; no Kubernetes object was written"})
                self.record_warn(_SITE_KUBERNETES, "KUBERNETES_NOT_READ", f"{credential.qualified}: {by_id[source_id].path} was not read ({why}); no Kubernetes object was written.")
                return
            lists[source_id] = rows
        read.append("create:kubernetes")
        plan = kubernetes.plan(lists["kubernetes_containers"], lists["kubernetes_pods"], lists["kubernetes_namespaces"], lists["kubernetes_nodes"], credential.settings, started, credential.scanner_key)

        def ref_of(kind: str, key: Any) -> str | None:
            return out.kubernetes.get((kind, key)) or shared.kubernetes.get((kind, key))

        def stage(kind: str, key: Any, entity_type: str, name: str, fields: dict[str, Any]) -> None:
            # One object, one node per batch: two scanners can report the same cluster.
            if ref_of(kind, key) is not None:
                return
            ref = f"{tag}:k:{kind}:{len(out.kubernetes)}"
            out.nodes.append(decompose.typed_node(ref, entity_type, name, fields, store.default_dimensions(entity_type)))
            out.kubernetes[(kind, key)] = ref

        for kind, objects in (("cluster", plan.clusters), ("namespace", plan.namespaces), ("node", plan.nodes), ("pod", plan.pods), ("container", plan.containers)):
            for key, fields in objects.items():
                # A label map the record did not carry is left out, so a stored one is kept; a container's
                # runtime id and image reference are sent as reported, null included (a container not yet started has no id).
                sent = {name: value for name, value in fields.items() if value is not None or name in ("container_id", "image_reference")}
                stage(kind, key, KUBERNETES_TYPES[kind], fields.get("name") or str(key), sent)
        for uid, fields in plan.nodes.items():
            # The machine behind a node is a host under its own realm, written only where the grid has none.
            if not store.host_exists(kubernetes.REALM_NODE_HOST, uid):
                stage("host", uid, "computing_core__host", fields.get("name") or uid, {"realm": kubernetes.REALM_NODE_HOST, "stable_id": uid, "name": fields.get("name") or ""})
            if ref_of("edge", ("BACKED_BY_HOST", uid)) is None:
                host_ref = ref_of("host", uid)
                target = {"ref": host_ref} if host_ref is not None else {"entity_type": "computing_core__host", "key": {"realm": kubernetes.REALM_NODE_HOST, "stable_id": uid}}
                edge_ref = f"{tag}:k:edge:{len(out.kubernetes)}"
                out.edges.append(decompose.edge_ends(edge_ref, "BACKED_BY_HOST__computing_core", {"ref": ref_of("node", uid)}, target))
                out.kubernetes[("edge", ("BACKED_BY_HOST", uid))] = edge_ref
        for slug, source_kind, source_key, target_kind, target_key in plan.edges:
            identity = ("edge", (slug, source_key, target_key))
            if ref_of(*identity) is not None:
                continue
            edge_ref = f"{tag}:k:edge:{len(out.kubernetes)}"
            out.edges.append(decompose.edge(edge_ref, f"{slug}__computing_core", ref_of(source_kind, source_key), ref_of(target_kind, target_key)))
            out.kubernetes[identity] = edge_ref
        for key, digest in plan.images.items():
            identity = ("edge", ("RUNS_IMAGE", key, digest))
            if ref_of(*identity) is not None:
                continue
            edge_ref = f"{tag}:k:edge:{len(out.kubernetes)}"
            self._ensure_host(out, digest, f"{edge_ref}:host", shared)
            out.edges.append(decompose.edge_to_key(edge_ref, "RUNS_IMAGE__computing_core", ref_of("container", key), "computing_core__host", decompose.host_key(digest)))
            out.kubernetes[identity] = edge_ref
        counts = {"clusters": len(plan.clusters), "namespaces": len(plan.namespaces), "nodes": len(plan.nodes), "pods": len(plan.pods), "containers": len(plan.containers), "stale": plan.stale, "out_of_scope": plan.out_of_scope, "unusable": plan.unusable, "fallback_clusters": plan.fallback_clusters}
        if plan.unusable:
            not_read.append({"scope": "create:kubernetes:unusable", "reason": f"{plan.unusable} Kubernetes container record(s) named no usable name, context or listed pod and were not written"})
        self.record_info(_SITE_KUBERNETES, "KUBERNETES_WRITTEN", f"{credential.qualified}: {counts['containers']} container(s) in {counts['pods']} pod(s), {counts['namespaces']} namespace(s), {counts['nodes']} node(s), {counts['clusters']} cluster(s); {counts['stale']} not seen recently, {counts['out_of_scope']} out of scope, {counts['unusable']} unusable, {counts['fallback_clusters']} cluster(s) keyed by name.", message_data=counts)

    def _ecs_create(self, client: ReadOnlyClient, credential: Credential, extract: dict[str, Any], by_id: dict[str, Source], running: scoping.Running | None, out: _Scanner, tag: str, shared: _Shared, read: list[str], not_read: list[dict[str, str]]) -> None:
        """With ``create.ecs``: stage the aws_core ECS nodes the grid does not hold (req-anchore-shared-5, -11, -12).

        Off by default. Creation starts from the selected containers and reaches only the task,
        service and cluster each leads to by ARN. A node the grid holds is never written here. The
        hazards this accepts are listed in the spec by what an operator would see.
        """
        if not credential.settings.create_ecs or running is None or not running.ecs_containers:
            return
        tasks, why_tasks = self._paged(client, extract, by_id["ecs_tasks"], "tasks")
        services, why_services = self._paged(client, extract, by_id["ecs_services"], "services")
        if why_tasks is not None or why_services is not None:
            why = f"ECS tasks: {why_tasks}" if why_tasks is not None else f"ECS services: {why_services}"
            not_read.append({"scope": "create:ecs", "reason": f"{why}; no ECS node was created"})
            self.record_warn(_SITE_ECS_CREATE, "ECS_CREATE_NOT_READ", f"{credential.qualified}: {why}; no ECS node was created.")
            return
        plan = scoping.plan_ecs_creation(running.ecs_containers, tasks, services, credential.settings)
        wanted = {"container": plan.containers, "task": plan.tasks, "service": plan.services, "cluster": plan.clusters}
        # WORKAROUND(unified-systems-com/tap#1071): read, then write. tap has no insert-only node form, so a
        # node the provider creates between this read and the batch's import is replaced by ours.
        # WORKAROUND(unified-systems-com/tap#1170): only live rows are visible here. A node the provider
        # retired is absent, and is created again as a new one if Anchore saw it within the window.
        # WORKAROUND(unified-systems-com/tap#1172): a node this plugin created earlier is found here like
        # any other and never rewritten, because it cannot tell its own fields from the provider's.
        existing: dict[str, set[str]] = {}
        for kind, nodes in wanted.items():
            entity_type, key = store.ECS_TYPES[kind]
            found = store.aws_nodes_on_grid(entity_type, key, set(nodes))
            if found is None:
                not_read.append({"scope": "create:ecs", "reason": "aws_core is not installed, so no ECS node was created"})
                self.record_info(_SITE_ECS_CREATE, "ECS_CREATE_NOT_READ", f"{credential.qualified}: aws_core is not installed; no ECS node was created.")
                return
            existing[kind] = found
        read.append("create:ecs")
        created = dict.fromkeys(wanted, 0)
        for kind, nodes in wanted.items():
            entity_type, key = store.ECS_TYPES[kind]
            defaults = store.default_dimensions(entity_type)
            for arn, reported in sorted(nodes.items()):
                if arn in existing[kind] or arn in out.ecs_created or arn in shared.ecs_created:
                    continue
                parts = scoping.parse_ecs_arn(arn, kind)
                # WORKAROUND(unified-systems-com/tap#1173): aws_core requires a name on a container, a
                # service and a cluster, and Anchore reports none for a container. The last ARN segment
                # stands in (it is the real name of a cluster and a service) until the provider writes it.
                fields: dict[str, Any] = {key: arn}
                if kind != "task":
                    fields["name"] = parts.last
                # Only what Anchore reported: a field it did not carry is omitted, never sent empty.
                fields.update({name: value for name, value in reported.items() if value is not None})
                ref = f"{tag}:ec:{kind}:{len(out.ecs_created)}"
                out.nodes.append(decompose.provider_node(ref, entity_type, parts.last, fields, defaults, parts))
                out.ecs_created[arn] = ref
                created[kind] += 1

        def end(kind: str, arn: str) -> dict[str, Any] | None:
            entity_type, key = store.ECS_TYPES[kind]
            if arn in out.ecs_created:
                return {"ref": out.ecs_created[arn]}
            if arn in shared.ecs_created:
                # Staged by an earlier scanner of this run: one batch, so its ref is good here too.
                return {"ref": shared.ecs_created[arn]}
            if arn in existing[kind]:
                return {"entity_type": entity_type, "key": {key: arn}}
            return None

        ends = {"RUNS_CONTAINER": ("task", "container"), "RUNS_SERVICE": ("cluster", "service")}
        for number, (slug, source_arn, target_arn) in enumerate(plan.edges):
            source_kind, target_kind = ends.get(slug, ("service" if ":service/" in source_arn else "cluster", "task"))
            # The owner's edges are drawn for the nodes this run creates, not between two the grid already held.
            if source_arn not in out.ecs_created and target_arn not in out.ecs_created:
                continue
            source, target = end(source_kind, source_arn), end(target_kind, target_arn)
            if source is not None and target is not None:
                out.edges.append(decompose.edge_ends(f"{tag}:ece{number}", f"{slug}__aws_core", source, target))
        if plan.rejected:
            not_read.append({"scope": "create:ecs:rejected", "reason": f"{plan.rejected} selected ECS container(s) had an ARN, or an ancestor's ARN, that is not a well-formed ECS ARN in one partition, region and listed account; nothing was created for them"})
        self.record_info(_SITE_ECS_CREATE, "ECS_CREATED", f"{credential.qualified}: created {created['container']} ECS container(s), {created['task']} task(s), {created['service']} service(s) and {created['cluster']} cluster(s) the grid did not hold; {plan.rejected} container(s) rejected.", message_data={"created": created, "rejected": plan.rejected})

    def _ecs_links(self, credential: Credential, running: scoping.Running | None, out: _Scanner, tag: str, shared: _Shared, read: list[str], not_read: list[dict[str, str]]) -> None:
        """Join each selected ECS container to the aws_core container with its ARN, where the grid has one.

        The join is ``RUNS_IMAGE`` from that container to the image host. No field of the container
        is written and none is created here (req-anchore-shared-1, -2): a container the grid does
        not hold is counted as unresolved (req-anchore-shared-3). Where aws_core is not installed
        the join is recorded as not read and the run goes on (req-anchore-shared-4).
        """
        if running is None or not running.ecs_containers:
            return
        by_arn: dict[str, str] = {}
        for container in running.ecs_containers:
            arn = container.get("arn")
            if isinstance(arn, str) and arn:
                by_arn.setdefault(arn, container["image_digest"])
        found = store.ecs_containers_on_grid(set(by_arn))
        if found is None:
            not_read.append({"scope": "link:ecs-containers", "reason": "aws_core is not installed, so no ECS container was linked"})
            self.record_info(_SITE_ECS_LINK, "ECS_LINK_NOT_READ", f"{credential.qualified}: aws_core is not installed; {len(by_arn)} ECS container(s) were not linked.")
            return
        read.append("link:ecs-containers")
        for number, (arn, digest) in enumerate(sorted(by_arn.items())):
            # A container an earlier scanner staged in this batch is as linkable as one this scanner staged.
            staged = out.ecs_created.get(arn) or shared.ecs_created.get(arn)
            known = arn in found or staged is not None
            if not known or (arn, digest) in out.runs_image or (arn, digest) in shared.runs_image:
                continue
            # One relationship, one edge per batch: two scanners can report the same container.
            out.runs_image.add((arn, digest))
            self._ensure_host(out, digest, f"{tag}:eh{number}", shared)
            source = {"ref": staged} if staged is not None else {"entity_type": store.ECS_CONTAINER_TYPE, "key": {store.ECS_CONTAINER_KEY: arn}}
            out.edges.append(decompose.edge_ends(f"{tag}:el{number}", "RUNS_IMAGE__computing_core", source, {"entity_type": "computing_core__host", "key": decompose.host_key(digest)}))
            out.ecs_links += 1
        unresolved = len(set(by_arn) - found - set(out.ecs_created) - set(shared.ecs_created))
        if unresolved:
            not_read.append({"scope": "link:ecs-containers:unresolved", "reason": f"{unresolved} ECS container(s) have no aws_core container on the grid and were not linked"})
        self.record_info(_SITE_ECS_LINK, "ECS_LINKED", f"{credential.qualified}: {out.ecs_links} ECS container(s) linked to their image, {unresolved} with no aws_core container on the grid.", message_data={"linked": out.ecs_links, "unresolved": unresolved})

    def _ancestors(self, client: ReadOnlyClient, credential: Credential, extract: dict[str, Any], source: Source, digest: str, ref: str, out: _Scanner, shared: _Shared, read: list[str], not_read: list[dict[str, str]]) -> None:
        """Join an image to each image Anchore says forms its base layers (req-anchore-base-image-4, -5).

        ``BUILT_ON_IMAGE`` from this image's host to the ancestor's, whose host is written as a
        digest-only stub where the grid has none. With ``repository_prefixes`` set, an ancestor
        none of whose tags begins with a listed prefix is outside the scope and is not written
        (req-anchore-scope-8); the finding's ``base_digest`` still names the base. A read that
        fails writes nothing and is recorded; it never fails the image.
        """
        if not decompose.OCI_DIGEST.fullmatch(digest):
            return
        body, failure = _get_json(client, extract, source, fill(source.path, image_digest=digest))
        if failure is not None or not isinstance(body, list):
            not_read.append({"scope": f"ancestors:{digest}", "reason": failure.reason if failure is not None else "the response held no ancestor list"})
            return
        read.append(f"ancestors:{digest}")
        for number, entry in enumerate(body):
            ancestor = entry.get("image_digest") if isinstance(entry, dict) else None
            if not isinstance(ancestor, str) or not decompose.OCI_DIGEST.fullmatch(ancestor) or ancestor == digest:
                continue
            prefixes = credential.settings.repository_prefixes
            tags = entry.get("tags")
            if prefixes and not any(scoping.passes_reference(t, prefixes) for t in (tags if isinstance(tags, list) else [])):
                out.ancestors_out_of_scope += 1
                continue
            if (digest, ancestor) in out.built_on or (digest, ancestor) in shared.built_on:
                continue
            out.built_on.add((digest, ancestor))
            self._ensure_host(out, digest, f"{ref}:{number}:image", shared)
            self._ensure_host(out, ancestor, f"{ref}:{number}:host", shared)
            out.edges.append(decompose.edge_between_keys(f"{ref}:{number}", "BUILT_ON_IMAGE__anchore", "computing_core__host", decompose.host_key(digest), "computing_core__host", decompose.host_key(ancestor)))

    def _policy(self, client: ReadOnlyClient, credential: Credential, extract: dict[str, Any], source: Source, image: dict[str, Any], digest: str, run_id: str, ref: str, out: _Scanner, read: list[str], not_read: list[dict[str, str]]) -> None:
        """Read Anchore's policy evaluation of an image under each tag it carries (req-anchore-image-policy).

        Anchore evaluates under a tag, so there is one read per tag. The base image is asked for as it
        is for the vulnerabilities, so a finding of the evaluation can say it was inherited. A tag whose
        read fails, or that names no policy, is recorded as not read; it never fails the image.
        """
        if not decompose.OCI_DIGEST.fullmatch(digest):
            return
        tags = decompose.image_tags(image)
        if not tags:
            # Anchore evaluates under a tag, so an image it lists no tag for has no evaluation to read.
            # That is nothing there, not something unread; the run's log gives the count.
            out.policy_untagged += 1
            return
        for number, image_tag in enumerate(tags):
            scope = f"policy:{digest}:{image_tag}"
            body, failure = _get_json(client, extract, source, fill(source.path, image_digest=digest), params={"tag": image_tag, "base_digest": "auto"})
            if failure is not None and failure.refused:
                body, failure = _get_json(client, extract, source, fill(source.path, image_digest=digest), params={"tag": image_tag})
            node = decompose.policy_evaluation_node(f"{ref}:{number}", credential.scanner_key, digest, image_tag, body, run_id) if failure is None and isinstance(body, dict) else None
            if node is None:
                not_read.append({"scope": scope, "reason": failure.reason if failure is not None else "the response named no policy or held no evaluation"})
                continue
            read.append(scope)
            out.nodes.append(node)
            out.edges.append(decompose.edge_to_key(f"{ref}:{number}:image", "EVALUATES_IMAGE__anchore", node["entity"]["ref"], "computing_core__host", decompose.host_key(digest)))
            out.policy_evaluations += 1
            out.policy_failures += node["node"]["status"] == "fail"

    def _image_record(self, credential: Credential, image: dict[str, Any], digest: str, ref: str, out: _Scanner, shared: _Shared) -> None:
        """Stage Anchore's record of an image, and give the image's host its name and operating system.

        The record is this plugin's node and is written every run (req-anchore-image-1, -2). The host is
        computing_core's: a host this batch creates carries the name and operating system Anchore reports,
        and a host the grid already holds gets only the ones it lacks (req-anchore-image-3, -4).
        """
        out.nodes.append(decompose.image_node(ref, credential.scanner_key, image))
        out.image_records += 1
        if not decompose.OCI_DIGEST.fullmatch(digest):
            return
        name, os = decompose.image_naming(image)
        self._ensure_host(out, digest, f"{ref}:host", shared, name, os, count_unlinked=False)
        out.edges.append(decompose.edge_to_key(f"{ref}:image", "RECORDS_IMAGE__anchore", ref, "computing_core__host", decompose.host_key(digest)))
        if digest in out.hosts or digest in shared.hosts or digest in out.host_fills or digest in shared.host_fills or not (name or os):
            return
        held = store.image_host_fields(digest)
        if held is None:
            return
        # WORKAROUND(unified-systems-com/tap#1172): tap has no write that yields to a value already
        # held, so the host is read and only the fields it lacks are sent. A collector that fills the
        # same field between this read and the write is overwritten.
        fill_name, fill_os = (name if not held["name"] else None), (os if not held["os"] else None)
        if fill_name or fill_os:
            out.host_fills.add(digest)
            out.nodes.append(decompose.host_fill(f"{ref}:fill", digest, fill_name or held["name"] or digest, fill_name, fill_os))

    def _ensure_host(self, out: _Scanner, digest: str, host_ref: str, shared: _Shared, name: str | None = None, os: str | None = None, count_unlinked: bool = True) -> None:
        """Stage the image host for a digest only where neither this batch nor the grid has one.

        Where the grid has one it is not staged here, whatever another collector filled in. A digest that
        is not a plain sha256 digest names no host key, so nothing is staged and the image is counted.
        """
        if not decompose.OCI_DIGEST.fullmatch(digest):
            out.unlinked_images += count_unlinked
            return
        if digest not in shared.hosts and digest not in out.hosts and not store.image_host_exists(digest):
            out.nodes.append(decompose.host_node(host_ref, digest, name, os))
            out.hosts.add(digest)
            out.hosts_created += 1

    def _link_image(self, out: _Scanner, findings: list[dict[str, Any]], digest: str) -> None:
        """Edges from this image's findings to its host and, where it already exists exactly, to the shared vulnerability."""
        if decompose.OCI_DIGEST.fullmatch(digest):
            for node in findings:
                ref = node["entity"]["ref"]
                out.edges.append(decompose.edge_to_key(f"{ref}:image", "FOUND_ON_IMAGE__anchore", ref, "computing_core__host", decompose.host_key(digest)))
        known = store.known_vulnerabilities({n["node"]["vulnerability_id"] for n in findings})
        for node in findings:
            if node["node"]["vulnerability_id"] in known:
                ref = node["entity"]["ref"]
                out.edges.append(decompose.edge_to_key(f"{ref}:vuln", "ABOUT_VULNERABILITY__anchore", ref, "compliance_core__compliance_vulnerability", {"vuln_id": node["node"]["vulnerability_id"]}))
                out.vulnerability_links += 1

    def _sboms(self, client: ReadOnlyClient, credential: Credential, by_id: dict[str, Source], digest: str, ref: str, out: _Scanner, read: list[str], not_read: list[dict[str, str]], shared: _Shared) -> dict[str, tuple[str, str, str]]:
        """Record each SBOM format Anchore serves for an image as a document describing the image host.

        The body is hashed as received and never stored. The CycloneDX one is also parsed into the
        image's package inventory where it qualifies as source-authenticated (req-anchore-sbom-2).
        The vendor file calls these bodies strings, which they are not, so they are checked only for being JSON.
        Returns the image's packages by purl, for joining findings to them; empty when nothing was parsed.
        """
        packages: dict[str, tuple[str, str, str]] = {}
        for source_id in decompose.SBOM_FORMATS:
            source = by_id[source_id]
            scope = f"sbom:{decompose.SBOM_FORMATS[source_id]}:{digest}"
            try:
                reply = _bounded(lambda: client.get(fill(source.path, image_digest=digest)), source_id)
            except CeilingExceeded:
                not_read.append({"scope": scope, "reason": "the read did not finish within its ceiling"})
                continue
            except ClientError as exc:
                not_read.append({"scope": scope, "reason": f"not read ({type(exc).__name__})"})
                continue
            if reply.status != 200:
                not_read.append({"scope": scope, "reason": f"HTTP {reply.status}"})
                continue
            try:
                parsed = decompose.loads_strict(reply.body)
            except ValueError:
                parsed = None
            except RecursionError:
                not_read.append({"scope": scope, "reason": "the body nests too deeply to read"})
                continue
            if not isinstance(parsed, (dict, list)):
                not_read.append({"scope": scope, "reason": "the body was not a JSON document"})
                continue
            node = decompose.sbom_node(f"{ref}:{source_id}", source_id, reply.body, parsed, digest, canonical_root(credential.base_url), credential.account)
            content = node["node"]["content_digest"]
            if source_id == "sbom_cyclonedx":
                staged, packages = self._inventory(credential, digest, reply.body, content, out, shared, not_read)
                if staged:
                    # The parser's own document row and its edge to the host stand in for this plugin's.
                    read.append(scope)
                    out.sboms += 1
                    continue
            # A document is keyed by the digest of its bytes alone. Bytes already in this batch, or already on the
            # grid (possibly written by another collector, verified and signed), are linked to and never rewritten.
            if content in out.sbom_refs:
                doc_ref: str | None = out.sbom_refs[content]
            elif content in shared.documents or store.sbom_document_exists(content):
                doc_ref = None
            else:
                doc_ref = node["entity"]["ref"]
                out.sbom_refs[content] = doc_ref
                out.nodes.append(node)
            read.append(scope)
            out.sboms += 1
            # One relationship, one edge per batch: the same bytes can be served under two formats, or by two scanners.
            if decompose.OCI_DIGEST.fullmatch(digest) and (content, digest) not in out.describes and (content, digest) not in shared.describes:
                out.describes.add((content, digest))
                edge_ref = f"{ref}:{source_id}:host"
                if doc_ref is not None:
                    out.edges.append(decompose.edge_to_key(edge_ref, "DESCRIBES_HOST__computing_core", doc_ref, "computing_core__host", decompose.host_key(digest)))
                else:
                    out.edges.append(decompose.edge_between_keys(edge_ref, "DESCRIBES_HOST__computing_core", "computing_core__sbom_document", {"content_digest": content}, "computing_core__host", decompose.host_key(digest)))
        return packages

    def _inventory(self, credential: Credential, digest: str, body: bytes, content: str, out: _Scanner, shared: _Shared, not_read: list[dict[str, str]]) -> tuple[bool, dict[str, tuple[str, str, str]]]:
        """Parse a CycloneDX SBOM into the image's inventory with computing_core's parser (req-anchore-sbom-2).

        Returns (whether the parser's rows, its document row included, were staged; the packages by purl).

        The document is unsigned. It is parsed as source-authenticated only when that outcome's
        three conditions hold (req-computing-core-sbom-source-auth): this client fetched it, with
        the operator's credential, over verified TLS. Over plain http it is recorded and not parsed.
        A document the grid holds as refused is not read. One a signer verified, or another collector
        recorded, is parsed only to learn its packages for the finding joins: nothing of it is staged,
        so a row another collector wrote is never rewritten. One this plugin already staged for this
        host is not staged again.
        """
        none: tuple[bool, dict[str, tuple[str, str, str]]] = (False, {})
        if not decompose.OCI_DIGEST.fullmatch(digest):
            return none
        if credential.plaintext:
            not_read.append({"scope": f"sbom-inventory:{digest}", "reason": "the instance is read over plain http, so its SBOM is not source-authenticated; it was recorded and not parsed"})
            return none
        if len(credential.scanner_key) > 512:
            not_read.append({"scope": f"sbom-inventory:{digest}", "reason": "the scanner key is too long to name as the document's source; the SBOM was recorded and not parsed"})
            return none
        state = store.sbom_document_state(content)
        if state is not None and state["verified"] is False:
            # Not read is never clean: the inventory was deliberately not taken, and the run says so.
            not_read.append({"scope": f"sbom-inventory:{digest}", "reason": "the grid holds this document as refused by a verifier, so it was not parsed"})
            return none
        # The parser names the host by entity id; a host staged in this batch has none yet. A placeholder
        # derived from the digest stands in, and each edge end that carries it is rewritten to the host's key.
        placeholder = str(uuid.uuid5(uuid.NAMESPACE_URL, f"anchore-image-host:{digest}"))
        try:
            parsed = parse_cyclonedx(body, host_id=placeholder, verification=Verification("source-authenticated", source=credential.scanner_key))
        except (SbomParseError, ValueError, RecursionError) as exc:
            not_read.append({"scope": f"sbom-inventory:{digest}", "reason": f"the CycloneDX document was recorded and not parsed ({str(exc)[:200]})"})
            return none
        out.sboms_parsed += 1
        packages = {
            row.properties["purl"]: (row.properties["ecosystem"], row.properties["name"], row.properties["version"])
            for row in parsed.nodes_of("computing_core__package")
            if isinstance(row.properties.get("purl"), str) and row.properties["purl"]
        }
        # This scanner's own row: one it staged before (its key is the source), or one this plugin
        # recorded before it could parse (its note). Another scanner's row, of this plugin or any other, is foreign.
        ours = (
            state is not None
            and state["verified"] is None
            and not state["signer"]
            and (
                state["authenticated_source"] == credential.scanner_key
                or (not state["authenticated_source"] and state["verification_note"] == decompose.unsigned_note(canonical_root(credential.base_url), credential.account))
            )
        )
        # The same bytes recorded earlier in this batch without being parsed (another scanner read them over
        # plain http): the batch already holds that document row, so this scanner stages nothing over it.
        recorded_in_batch = (content in out.sbom_refs or content in shared.documents) and content not in out.inventory_documents and content not in shared.inventory_documents
        foreign = (state is not None and not ours) or recorded_in_batch
        already = ours and bool(state["authenticated_source"]) and store.sbom_describes_host(content, digest)
        if foreign or already:
            if foreign:
                # Only the packages the grid really holds, under the same purl, can be joined to.
                packages = store.packages_on_grid(packages)
                if state is None or state["verified"] is not True:
                    not_read.append({"scope": f"sbom-inventory:{digest}", "reason": "another scanner or collector holds this document unverified, so its row was left as it is and no inventory was written from it"})
            return False, packages
        host_key = {"entity_type": "computing_core__host", "key": decompose.host_key(digest)}
        for row in parsed.nodes:
            if row.ref in out.inventory_refs or row.ref in shared.inventory_refs:
                continue
            out.inventory_refs.add(row.ref)
            staged_node = row.as_grift()
            if row.entity_type == "computing_core__sbom_document":
                out.sbom_refs[content] = row.ref
                # The document may not name what it describes; this read does, by the image it was asked for.
                staged_node["node"]["subject_digest"] = staged_node["node"].get("subject_digest") or digest
            out.nodes.append(staged_node)
        for edge in parsed.edges:
            if edge.ref in out.inventory_refs or edge.ref in shared.inventory_refs:
                continue
            out.inventory_refs.add(edge.ref)
            staged = edge.as_grift()
            staged["entity"]["name"] = edge.edge_type
            for end in ("from", "to"):
                # Only the placeholder is this image's host; any other id the parser emitted is left as it is.
                if staged["edge"].get(f"{end}_entity_id") == placeholder:
                    del staged["edge"][f"{end}_entity_id"]
                    staged["edge"][f"{end}_key"] = host_key
            out.edges.append(staged)
        out.describes.add((content, digest))
        out.inventory_documents.add(content)
        out.sboms_staged += 1
        return True, packages

    def _link_packages(self, out: _Scanner, findings: list[dict[str, Any]], packages: dict[str, tuple[str, str, str]]) -> None:
        """Join each finding to the package its purl names, among the image's parsed packages (req-anchore-sbom-6)."""
        for node in findings:
            key = packages.get(node["node"].get("purl") or "")
            if key is None:
                continue
            ref = node["entity"]["ref"]
            out.edges.append(decompose.edge_to_key(f"{ref}:package", "FOUND_IN_PACKAGE__anchore", ref, "computing_core__package", {"ecosystem": key[0], "name": key[1], "version": key[2]}))
            out.package_links += 1

    @staticmethod
    def _document(batches: list[tuple[list[dict[str, Any]], list[dict[str, Any]]]], written: list[str]) -> dict[str, Any]:
        """One GRIFT document for the run: its batches in the order they are applied."""
        total = len(batches)
        out = []
        for number, (nodes, edges) in enumerate(batches, start=1):
            name = "Anchore collection" if total == 1 else f"Anchore collection ({number} of {total})"
            out.append({
                "batch_entity": {"entity_id": str(uuid.uuid4()), "entity_type": "batch", "name": name, "dimensions": {}},
                "batch_node": {
                    "source": "tap_plugin.anchore.collectors.anchore_collector",
                    "name": name,
                    "description": "One run of the Anchore collector." if total == 1 else f"Part {number} of {total} of one run of the Anchore collector.",
                    # A run that fits one batch describes itself exactly as it always did; the part numbers appear only when it is split.
                    "description_json": {"format": "tap.anchore.collection-v0", "data": {"scanners": written} if total == 1 else {"scanners": written, "part": number, "parts": total}},
                },
                "nodes": nodes,
                "edges": edges,
            })
        return {"metadata": {"grift_version": "0"}, "_reserved": {}, "batches": out}


def _contract_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "contract"


__all__ = ["AnchoreCollector", "AnchoreCollectorError"]
