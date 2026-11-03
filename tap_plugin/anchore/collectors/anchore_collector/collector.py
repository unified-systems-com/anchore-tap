"""The Anchore collector: one run reads every configured scanner and submits one GRIFT batch.

For each credential it probes the instance (the account must be the configured one), runs the
self-test, lists the images, reads each analyzed image's vulnerabilities, and records what it read
and what it did not. A scanner that fails its probe or self-test, whose image list cannot be read, or that answers in a shape the
committed contract does not describe, is skipped with nothing written for it; a single image that cannot be read
(a failed request, a timeout) is recorded as not read and leaves its findings as they were. Reads only (``ReadOnlyClient``), each bounded by a wall-clock ceiling. Anchore's data is stored
as returned (req-anchore-findings-3); a finding a successful read of its image no longer reports is
marked resolved, never deleted, and an image that could not be read leaves its findings untouched.

Not in this slice: the edges from a finding to the host, package, vulnerability and SBOM document
(they need those nodes resolved on the grid first), SBOM, VEX, application and inventory reads.

Spec: specs/spec-anchore-v0.md (req-anchore-findings, -probe, -selftest, -states).
"""

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

from tap import secrets_root

from tap_cares.collectors import CeilingExceeded, CollectorBase, run_with_ceiling
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

#: A read's own budget is TOTAL_BUDGET_SECONDS; the ceiling sits above it so the client's
#: retry accounting ends the call first and the ceiling only catches what that cannot (DNS, a trickle).
READ_CEILING_SECONDS = TOTAL_BUDGET_SECONDS + 30
#: A feed whose last sync is older than this is recorded as stale (req-anchore-probe-3); it is a fact, not a verdict.
FEED_MAX_AGE = timedelta(days=2)
#: How many dropped values a run record lists by name; the counts are always exact.
_LISTED = 50


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


@dataclass
class _Shared:
    """What the batch already holds from scanners that finished, so two scanners never stage one node twice.

    A scanner that is skipped contributes nothing here, because everything it staged is dropped with it.
    """

    hosts: set[str] = field(default_factory=set)
    documents: set[str] = field(default_factory=set)
    describes: set[tuple[str, str]] = field(default_factory=set)

    def absorb(self, scanner: _Scanner) -> None:
        self.hosts |= scanner.hosts
        self.documents |= set(scanner.sbom_refs)
        self.describes |= scanner.describes


def _bounded(call: Any, what: str) -> Any:
    return run_with_ceiling(call, READ_CEILING_SECONDS, name=f"anchore-{what}")


@dataclass(frozen=True)
class Failure:
    """Why a read gave nothing. ``incompatible`` means the instance answered in a shape the committed contract does not describe."""

    reason: str
    incompatible: bool = False


def _get_json(client: ReadOnlyClient, extract: dict[str, Any], source: Source, path: str) -> tuple[Any, Failure | None]:
    """(body, None) for a read that returned the committed shape, else (None, why). Never raises for what the instance does."""
    try:
        reply = _bounded(lambda: client.get(path), source.id)
    except CeilingExceeded:
        return None, Failure("the read did not finish within its ceiling")
    except ClientError as exc:
        return None, Failure(f"not read ({type(exc).__name__})")
    if reply.status != 200:
        return None, Failure(f"HTTP {reply.status}")
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
            written.append(f"{credential.qualified}: {scanner.findings} finding(s), {scanner.resolved} resolved, {scanner.images_read} image(s) read, {scanner.images_not_read} not read, {scanner.sboms} SBOM(s) recorded")
        if not written:
            self.summary = "No scanner could be read; nothing was written."
            self.record_error(_SITE_NOTHING_WRITTEN, "NOTHING_WRITTEN", self.summary)
            raise AnchoreCollectorError(self.summary)

        self.submit_grift(self._document(nodes, edges, written))
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

            self._images(client, credential, extract, by_id, run_id, out, read, not_read, tag, shared)

        finished = datetime.now(UTC)
        scanner_ref, run_ref = f"{tag}:scanner", f"{tag}:run"
        out.nodes.insert(0, decompose.scanner_node(scanner_ref, canonical_root(credential.base_url), credential.account, credential.scanner_key, probe.reported_version))
        out.nodes.insert(1, decompose.scan_run_node(
            run_ref, credential.scanner_key, run_id,
            started_at=started.isoformat(), finished_at=finished.isoformat(), reported_version=probe.reported_version,
            status=probe.body("status") if isinstance(probe.body("status"), dict) else None,
            feeds=probe.body("feeds") if isinstance(probe.body("feeds"), list) else None,
            selftest_verdict=gate.verdict, selftest_detail=gate.detail, scopes_read=read, scopes_not_read=not_read,
        ))
        out.edges.append(decompose.edge(f"{tag}:run-of", "RUN_OF_SCANNER__anchore", run_ref, scanner_ref))
        return out

    def _images(self, client: ReadOnlyClient, credential: Credential, extract: dict[str, Any], by_id: dict[str, Source], run_id: str, out: _Scanner, read: list[str], not_read: list[dict[str, str]], tag: str, shared: _Shared) -> None:
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
        for index, (digest, image) in enumerate(chosen.items()):
            scope = f"image:{digest}"
            if image.get("analysis_status") != "analyzed":
                not_read.append({"scope": scope, "reason": f"analysis_status is {image.get('analysis_status')!r}"})
                out.images_not_read += 1
                continue
            body, failure = _get_json(client, extract, by_id["image_vulnerabilities"], fill(by_id["image_vulnerabilities"].path, image_digest=digest, vuln_type="all"))
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
            result = decompose.decompose_image(vulns, credential.scanner_key, digest, run_id, f"{tag}:f{index}")
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
            self._ensure_host(out, digest, f"{tag}:h{index}", shared)
            self._link_image(out, result.nodes, digest)
            self._sboms(client, credential, by_id, digest, f"{tag}:d{index}", out, read, not_read, shared)
            dropped.extend(result.dropped_fields)
            skipped += result.skipped_entries
            duplicates += result.duplicate_entries
            uncarried |= result.uncarried_keys
        for gone in sorted(store.current_target_keys(credential.scanner_key) - set(chosen)):
            # An image that left the list is not a cleared image: its findings stay as they were, and say so.
            not_read.append({"scope": f"image:{gone}", "reason": "no longer in the image list; its findings were left as they were"})
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

    def _ensure_host(self, out: _Scanner, digest: str, host_ref: str, shared: _Shared) -> None:
        """Stage the image host for a digest only where neither this batch nor the grid has one.

        Where the grid has one it is never rewritten, whatever another collector filled in. A digest that
        is not a plain sha256 digest names no host key, so nothing is staged and the image is counted.
        """
        if not decompose.OCI_DIGEST.fullmatch(digest):
            out.unlinked_images += 1
            return
        if digest not in shared.hosts and digest not in out.hosts and not store.image_host_exists(digest):
            out.nodes.append(decompose.host_node(host_ref, digest))
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

    def _sboms(self, client: ReadOnlyClient, credential: Credential, by_id: dict[str, Source], digest: str, ref: str, out: _Scanner, read: list[str], not_read: list[dict[str, str]], shared: _Shared) -> None:
        """Record each SBOM format Anchore serves for an image as a document describing the image host.

        The body is hashed as received and never stored; none is parsed into packages (req-anchore-sbom-4).
        The vendor file calls these bodies strings, which they are not, so they are checked only for being JSON.
        """
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

    @staticmethod
    def _document(nodes: list[dict[str, Any]], edges: list[dict[str, Any]], written: list[str]) -> dict[str, Any]:
        return {
            "metadata": {"grift_version": "0"},
            "_reserved": {},
            "batches": [{
                "batch_entity": {"entity_id": str(uuid.uuid4()), "entity_type": "batch", "name": "Anchore collection", "dimensions": {}},
                "batch_node": {
                    "source": "tap_plugin.anchore.collectors.anchore_collector",
                    "name": "Anchore collection",
                    "description": "One run of the Anchore collector.",
                    "description_json": {"format": "tap.anchore.collection-v0", "data": {"scanners": written}},
                },
                "nodes": nodes,
                "edges": edges,
            }],
        }


def _contract_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "contract"


__all__ = ["AnchoreCollector", "AnchoreCollectorError"]
