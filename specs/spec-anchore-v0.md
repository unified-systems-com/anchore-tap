# Anchore Plugin Specification

**A read-only collector for Anchore Enterprise, hosted or on-prem: on a schedule it reads vulnerability findings, SBOMs, VEX statements, policy results and runtime inventory from Anchore's REST API and writes them to the grid, as `compliance_core` and `computing_core` types where a neutral home exists and as Anchore-specific nodes where it does not, so a FedRAMP vulnerability detection and response (VDR) implementation can read what Anchore knows without going to Anchore.**

## Plugin Identity

| Field | Value |
| --- | --- |
| Slug | `anchore` |
| Display name | TAP Anchore |
| Description | A read-only collector for Anchore Enterprise (hosted or on-prem) that lands vulnerability findings, SBOMs, VEX statements, policy results and runtime inventory on the grid. |
| Kind | Leaf plugin: consumes `compliance_core` (scanner, scan run, vulnerability, finding) and `computing_core` (package, sbom_document, host as the image host, and the SBOM parser); consumed by VDR plugins (`fedramp_20x_vdr`, `stackarmor_vdr`) through the grid, with no import. |

**Default dimensions.**

| Key | Value | Why |
| --- | --- | --- |
| `anchore.area` | `inventory` on the application, version and asset nodes; `annotation` on VEX annotation nodes; `runtime` on the runtime-observation nodes | Lets a page or Search group the Anchore-specific nodes without listing types. The key is namespaced by this vocabulary, which only this plugin gives meaning. The neutral `compliance_core` and `computing_core` nodes this plugin writes keep their owners' dimensions and receive none from here. |

## Philosophy

Anchore already does the hard part: it builds SBOMs, matches them against vulnerability feeds, evaluates policy and records VEX statements. A FedRAMP VDR implementation needs those answers on the grid, next to everything else the grid knows, with their provenance. This plugin carries them across. It does not scan, does not decide what a vulnerability means for a FedRAMP factor, and does not write to Anchore.

Six consequences shape v0:

1. **Read-only, always.** Every call is a GET. Anchore's export jobs, annotation writes, asset-adding jobs and inventory POST and DELETE endpoints are never called, so the credential can be a read-only role and a bug here cannot change Anchore.
2. **Consume the neutral vocabulary, add only what has no home.** Findings, vulnerabilities, scanners and scan runs are `compliance_core`'s; packages, SBOM documents and images are `computing_core`'s. Anchore's application, its versions and assets, its VEX annotations and its runtime observations have no neutral home and become Anchore-specific nodes, linked to the neutral ones by edges.
3. **Three states, never two.** A scope Anchore could not be asked about, a scope the instance does not offer, or an image whose analysis has not finished is recorded as *not read*, never as clean. A fact nothing observed is `null`. A run resolves only what that run actually read.
4. **A run names what it read and from where.** The instance, its reported version and its feed freshness are recorded on every scan run, so a finding can be judged against the data behind it.
5. **The API is a contract we can check.** Anchore changes its OpenAPI file on its own schedule and differs between hosted and on-prem. A committed extract of what we consume is tested offline, compared against the vendor's published file on a schedule, and compared against the configured instance at the start of every run.
6. **Unsigned does not mean verified.** Anchore's SBOMs come from an authenticated API and carry no signature. Until `computing_core` provides a source-authenticated outcome they are recorded and not parsed; once it does they are parsed and recorded as source-authenticated. They are never marked verified.

**Prior art, and what it changed.** Surveyed 2026-10-28 and 2026-10-29, documented from each project's own docs and Anchore's published OpenAPI file (version 2.20.0, 273 paths, Apache-2.0), not run. Anchore's own export jobs (one CycloneDX VDR, VEX or SBOM file per application version) were rejected as the ingest path: they are POST calls that create work on Anchore, so the credential could not be read-only, they are asynchronous, and they cover only application versions, losing per-image detail. `grype-tap` (this organisation) supplied the rules this plugin inherits: findings keyed by what they assert, resolve only what was scanned, three states, and operator settings never read from user-editable nodes. `anchorecli` targets the older Engine `/v1` API and no Anchore-maintained Python client for Enterprise `/v2` was found, so the client is ours, over `requests`.

**Provenance markers.** *Documented* (read from the OpenAPI file and Anchore's docs, 2026-10-28 and 2026-10-29): every endpoint, schema and field named below. *Designed* (this document): every node, edge, key and rule. *Observed*: nothing yet. No Anchore instance has been called; a trial instance is requested. Every parser, field mapping and "same on hosted and on-prem" claim is provisional until a recorded response from a real instance replaces it, and no requirement below reaches `Implemented` before that.

## Goals

| # | Name | Description |
| --- | --- | --- |
| 1 | Everything Anchore Knows | Findings, SBOMs in three formats, VEX annotations, policy results, the application graph and runtime inventory all reach the grid. |
| 2 | Read-Only By Construction | Only GET calls exist in the client; a read-only credential is enough. |
| 3 | Never Clean By Omission | A scope, an image or an instance feature not read is recorded as not read; unobserved facts are `null`. |
| 4 | Hosted And On-Prem | One client and one set of nodes serve both, with every difference between them kept in a ledger and observed before it is asserted. |
| 5 | Detect API Drift | Offline contract tests, a scheduled comparison with the vendor's file, and a per-run self-test against the configured instance catch a changed API before bad data lands. |
| 6 | Neutral Where Possible | Neutral types are used wherever one exists; Anchore-specific nodes are the exception, linked to the neutral ones. |
| 7 | Backend Only | No page or panel ships; the outputs are nodes and edges other surfaces read. |

## Requirements

| RID | Name | Status | Notes |
| --- | --- | --- | --- |
| req-anchore-connection | [Connection And Credential](#connection-and-credential) | Proposed | Base URL, credential, account and CA bundle are operator settings and the secret envelope; never fields on a node |
| req-anchore-client | [The Read-Only Client](#the-read-only-client) | Proposed | A thin `requests` client, GET only, cursor paging, timeouts, backoff, TLS verification on |
| req-anchore-probe | [Probe And Provenance](#probe-and-provenance) | Proposed | Version, status and feed freshness read first and recorded on the scan run |
| req-anchore-selftest | [Per-Run Schema Self-Test](#per-run-schema-self-test) | Proposed | The instance's own spec is checked against the committed extract before any data is read; error, warn or pass |
| req-anchore-contract-extract | [Contract Extract And Offline Tests](#contract-extract-and-offline-tests) | Proposed | A script-generated extract of the consumed paths and schemas, and tests against it with no network |
| req-anchore-drift-ci | [Scheduled Drift Check](#scheduled-drift-check) | Proposed | A scheduled workflow compares the vendor's public file with the extract and fails on drift in what we consume |
| req-anchore-states | [Three States And Resolution](#three-states-and-resolution) | Proposed | Not read is never clean; null is unobserved; a run resolves only what it read |
| req-anchore-scope-walk | [The Scope Walk](#the-scope-walk) | Proposed | Images, sources and application versions walked with GET calls; what is read at each |
| req-anchore-findings | [Findings And Vulnerabilities](#findings-and-vulnerabilities) | Proposed | Scanner, scan run, vulnerability and finding in `compliance_core`'s types, keyed by what they assert |
| req-anchore-sbom | [SBOMs](#sboms) | Proposed | Three formats stored as documents; CycloneDX parsed into packages under the source-authenticated outcome |
| req-anchore-application | [The Application Graph](#the-application-graph) | Proposed | Application, version and asset nodes with the version chain and edges to image hosts and SBOM documents |
| req-anchore-vex | [VEX Annotations](#vex-annotations) | Proposed | One annotation type for image and application-version scope, with edges to its scope and its subject |
| req-anchore-policy-result | [Policy Results](#policy-results) | Proposed | Version-level policy status and counts stored on the application version |
| req-anchore-inventory | [Runtime Inventory: Images In Use](#runtime-inventory-images-in-use) | Proposed | The flat list of images in use, per context, with when each was last seen |
| req-anchore-inventory-kubernetes | [Runtime Inventory: Kubernetes](#runtime-inventory-kubernetes) | Proposed | Namespace, node, pod and container as Anchore reports them, joined to the image host |
| req-anchore-inventory-ecs | [Runtime Inventory: ECS](#runtime-inventory-ecs) | Proposed | Container, joined to `aws_core`'s ECS container by ARN and to the image host; tasks and services not read in v0 |
| req-anchore-differences-ledger | [Hosted And On-Prem Differences](#hosted-and-on-prem-differences) | Proposed | The ledger of known and unknown differences, refreshed from the trial and from each run's self-test |
| req-anchore-fips | [FIPS Posture](#fips-posture) | Proposed | `requests` over system OpenSSL, no native binary, declared in `[fips]` |
| req-anchore-nongoals | [v0 Non-Goals](#v0-non-goals) | Proposed | What this plugin deliberately does not do, and who owns it |

### Connection And Credential
----
RID: `req-anchore-connection`

Status: `Proposed`

How the collector knows which Anchore to read and how to authenticate. The base URL, the credential, the account to scope to and an optional CA bundle are operator settings and the secret envelope, never fields on a grid node: whoever can edit a node must not be able to point a credential at another host (the same rule `grype-tap` states for its settings).

#### Implementation

Plugin-owned settings resolved at collection time: `base_url` (the API root including `/v2`; it must be `https://`, and the hosted URL and an on-prem `https://<host>:<port>/v2` both fit; plaintext is covered by `req-anchore-connection-4`), `account` (required: the Anchore account the credential reads, and part of every key; sent as `x-anchore-account` where the instance needs it), `ca_bundle` (a path, optional), `annotation_allowlist` (annotation keys that may be stored; empty by default), and a secret envelope holding the credential. Anchore documents Basic, API key (user `_api_key`), and OAuth2 bearer authentication; which of them the hosted service accepts is unknown until the trial (see the differences ledger), so the envelope names the scheme and the client supports the three. The bearer scheme is a token already minted and held in the envelope: the client never calls a token endpoint, because obtaining a token is a POST and the client sends only GET. Minting and renewing the token is the operator's, out of band. The secret kind and its minting guidance are wired through the `manage-secret` skill when the collector is built. Nothing in this section is read from a node, and the credential value never appears in a log, a scan-run field or an error message.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-anchore-connection-1 | Settings Are Not Nodes | Proposed | No node type declares a base URL, credential, account or CA-bundle field, and the collector reads none from the grid. | |
| req-anchore-connection-2 | Secret Never Echoed | Proposed | The credential is absent from logs, scan-run properties and exception text, including when a request fails. | |
| req-anchore-connection-3 | Scheme Is Declared | Proposed | The envelope names Basic, API key or bearer; an unknown scheme refuses the run before any request, and the bearer scheme uses a token supplied in the envelope, never one the client fetches. | The accepted schemes on the hosted service are not observed. |
| req-anchore-connection-4 | HTTPS Only | Proposed | A `base_url` that is not `https://` is refused before any request, with no override: the credential travels with every call, and a FedRAMP deployment requires encryption in transit. An on-prem install that serves plain HTTP must be fronted by TLS. | Added in response to the review of anchore-tap PR 2. Anchore's on-prem docs show an `http://` example on port 8228; the plugin does not follow it. |
| req-anchore-connection-5 | Redirects Are Refused | Proposed | The client follows no redirect: a 3xx response is an error recorded on the run, so the credential can never reach another origin (host, port or scheme). | Added in response to the review of anchore-tap PR 2. A negative test redirects to the same host on another port and to another host, and expects the refusal before any second request. |
| req-anchore-connection-6 | Account Is Required And In The Key | Proposed | The `account` setting is required; a run with none is refused before any request, and the scanner key always includes it. The effective account is read from `GET /account` and a mismatch with the setting is an error (`req-anchore-probe-4`). | Added in response to the review of anchore-tap PR 2. Whether Anchore reports the effective account, and whether the header is needed for a credential's own account, is unobserved. |

### The Read-Only Client
----
RID: `req-anchore-client`

Status: `Proposed`

A small client over `requests` (a direct dependency of core already; no Anchore-maintained Python client for Enterprise `/v2` exists, and `anchorecli` targets the older `/v1`). It exposes reads only.

#### Implementation

`tap_plugin/anchore/client.py`. One `requests.Session` with TLS verification on (the configured CA bundle when set), a connect and read timeout on every call, bounded retry with backoff on connection errors, 429 and 5xx, and a `Retry-After` respect. Paging follows the cursor or page parameters each endpoint declares in the extract. The client defines `get` and nothing that sends a body or uses another verb; enforcement is at the transport, not by reading source: every request leaves through one function that sends through a `Session` whose adapter rejects any method but GET before anything is sent, and a negative test calls `session.request("POST", ...)` and expects the refusal. A source scan for other verbs is a secondary check, since it alone can be bypassed by an alias or by `Session.request(method=...)`.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-anchore-client-1 | GET Only | Proposed | Every request passes through one transport that rejects any method but GET before sending; `session.request("POST", ...)`, an aliased method and a request from another module are each refused. | Negative tests for each; the source scan is secondary. |
| req-anchore-client-2 | Verified TLS | Proposed | Certificate verification is on; it is turned off by no setting. | A private CA is the `ca_bundle` setting. |
| req-anchore-client-3 | Bounded Retries | Proposed | Retries are limited in count and total time, and honour `Retry-After`; exhaustion is a recorded failure, not a silent empty result. | Ties to `req-anchore-states`. |

### Probe And Provenance
----
RID: `req-anchore-probe`

Status: `Proposed`

Before reading data, the collector asks the instance what it is and how fresh its data is, and records the answer on the scan run, so a finding can be judged against the data behind it.

#### Implementation

Reads `GET /account` first (documented: it returns the account of the authenticated user, with the configured `x-anchore-account` applied), and the run requires the returned account name to equal the configured `account`; a mismatch, or a failure to read it, ends the run before any scope is read (`req-anchore-probe-4`). Then reads `GET /status`, `GET /system` and `GET /system/feeds` (documented in the OpenAPI file; the hosted service may restrict the admin surface, which is why each is optional). Recorded on the scan run: the base URL host, the reported version, and the feed names with their last-sync times, each `null` when the instance did not answer. A feed older than a configured age records a warning on the run, and findings from it are still written, with the age visible.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-anchore-probe-1 | Probe Before Data | Proposed | The probe runs before any scope is read, and its results are on the scan run. | |
| req-anchore-probe-2 | A Refused Probe Is Null | Proposed | A probe call the instance refuses or does not offer leaves its field `null` and the run continues. | The hosted service's admin surface is unknown. |
| req-anchore-probe-3 | Stale Feed Is Visible | Proposed | A feed older than the configured age is recorded on the run as a warning with its age; it does not silently pass. | |
| req-anchore-probe-4 | Effective Account Verified | Proposed | The account returned by `GET /account` must equal the configured `account` before any scope is read; otherwise the run is an error and writes nothing. | Added in response to the review of anchore-tap PR 2. Whether the header is honoured, ignored or rejected for a non-admin credential is unobserved; the trial settles it with account A's credential and account B configured. |

### Per-Run Schema Self-Test
----
RID: `req-anchore-selftest`

Status: `Proposed`

At the start of every run the collector fetches the configured instance's own OpenAPI file, reduces it to the same extract format as the committed one, compares only what the plugin consumes, and either stops with an error or continues with a recorded warning. This catches a hosted or on-prem instance that differs from the version the extract came from, which the scheduled CI check on the vendor's public file cannot see.

#### Implementation

The instance serves its spec at `/v2/openapi.json` (documented in Anchore's API docs; not yet observed on the hosted service). The same reducer that builds the committed extract (`req-anchore-contract-extract`) runs on it. The comparison classifies each difference:

- **Error and stop, with no data written:** a path the plugin cannot work without is gone (the per-image vulnerability or SBOM read); a field the parser requires is removed or changes type; a new required parameter appears that the client does not send; or the credential can read neither the spec nor the data.
- **Warn and continue, recorded on the scan run:** a whole scope is unavailable (for example the application family on an older on-prem install), recorded as *not read*; a field read optionally disappears; a new enum value the parser does not know appears; the instance version differs from the extract's.
- **Pass:** only additive changes the plugin does not read.
- **Spec not served:** the self-test cannot run, and that is never recorded as passed. If the scanner's previous run recorded the spec as served, its absence now is error-class (a gate that can be bypassed by not answering is not a gate). If the previous run did not record it as served, or there was no previous run, the run warns and continues, but only because every response is independently validated against the extract's response schemas before any node is written (`req-anchore-selftest-6`); the unvalidated path does not exist.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-anchore-selftest-1 | Runs First | Proposed | The self-test completes before any scope is read, and its verdict is on the scan run. | |
| req-anchore-selftest-2 | Error Stops Without Writing | Proposed | An error-class difference ends the run before any node is written. | |
| req-anchore-selftest-3 | Warn Marks The Scope Not Read | Proposed | A warn-class difference that removes a scope records that scope as not read and leaves its prior findings untouched. | Ties to `req-anchore-states`. |
| req-anchore-selftest-4 | Absent Spec Is Not A Pass | Proposed | If the instance does not serve its spec, the self-test is recorded as not run, never as passed; the run errors if the scanner's previous run recorded the spec as served, and otherwise warns and continues. | The previous-run fact is a property of the scanner node. |
| req-anchore-selftest-5 | Same Reducer As The Committed Extract | Proposed | The committed extract and the live comparison come from one reducer, so a difference is never an artifact of two code paths. | |
| req-anchore-selftest-6 | Responses Validated Regardless | Proposed | Every response is validated against the extract's response schema before any node is written, with or without a self-test; a required scope that fails validation is an error, and an optional scope is recorded as not read. | Closes the gap an unserved spec would otherwise leave. |

### Contract Extract And Offline Tests
----
RID: `req-anchore-contract-extract`

Status: `Proposed`

A committed extract of the part of Anchore's OpenAPI file this plugin consumes, produced by a script and never typed, and tests that check the client and parser against it with no network. The plugin's `ci` boot record deliberately excludes network access, so nothing in the normal suite calls Anchore.

#### Implementation

`tap_plugin/anchore/contract/extract.json` with a `description` on the top level and every entry, produced by `tap_plugin/anchore/contract/reduce.py` from an OpenAPI file: the consumed paths, their methods and parameters, and the response schemas they reference, resolved to the fields the parser reads. The source is Anchore's published file (documented version 2.20.0). Recorded responses from the trial instance, once they exist, are committed as fixtures beside it and replace assumed shapes. The reducer takes the OpenAPI file as data and never executes anything from it.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-anchore-contract-extract-1 | Generated, Not Typed | Proposed | The extract is the output of the reducer from an OpenAPI file; a test regenerates it from a committed copy of the source and compares. | |
| req-anchore-contract-extract-2 | No Network In The Suite | Proposed | The plugin's tests open no socket; the client is exercised against recorded fixtures. | |
| req-anchore-contract-extract-3 | Described Data | Proposed | The extract has a JSON Schema and a `description` on its top level and each entry. | Repository rule for structured data files. |

### Scheduled Drift Check
----
RID: `req-anchore-drift-ci`

Status: `Proposed`

A scheduled GitHub workflow fetches Anchore's published OpenAPI file, reduces it with the same reducer, compares it with the committed extract, and fails when what the plugin consumes has changed. It follows the nightly-workflow pattern the organisation's other plugin repositories use.

#### Implementation

`.github/workflows/anchore-drift.yml`, scheduled, with read-only permissions (`contents: read`) and no write token: the failing run is the signal, and no issue is opened. It compares only consumed paths and schemas; other changes in the published file are listed in the run summary and do not fail it. It watches the vendor's public file only, not an instance (instances are the self-test's job, and checking one from CI would need a credential in CI). The fetch needs outbound access to Anchore's documentation host; CI egress is unrestricted today and an allowlist entry is needed if that changes.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-anchore-drift-ci-1 | Fails On Consumed Drift | Proposed | A change to a consumed path, method, parameter or response field fails the run. | |
| req-anchore-drift-ci-2 | Reports Other Changes Without Failing | Proposed | A change outside the extract is listed in the run summary and does not fail. | |
| req-anchore-drift-ci-3 | Read-Only Permissions | Proposed | The workflow grants `contents: read` and nothing else, and opens no issue. | Ruled by George 2026-10-29: the workflow only fails. |
| req-anchore-drift-ci-4 | Lands With The Scaffold | Proposed | The workflow is added with the package scaffold, with the other CI callers. | Ruled by George 2026-10-29: CI callers land with the scaffold. |

### Three States And Resolution
----
RID: `req-anchore-states`

Status: `Proposed`

How the collector records absence. Every place absence can occur has three outcomes, and the plugin keeps them apart.

#### Implementation

A scope the instance does not offer, a call that failed after its retries, an image whose analysis is not complete, and an inventory image with no analysis results are each recorded as *not read* on the scan run (with the reason), never as zero findings. A field nothing observed is `null`; an observed-empty list is `[]`. A finding closes only when its target was read successfully in this run and no longer appears; a target not read keeps whatever it had. Nothing is deleted: a finding no longer reported is `resolved`, and a returning one is reopened, as `grype-tap` does.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-anchore-states-1 | Not Read Is Not Clean | Proposed | A scope or image not read in a run produces no resolved findings and is listed as not read on the run. | |
| req-anchore-states-2 | Null Is Unobserved | Proposed | A field the response did not carry is `null`, never `""`, `0` or `false`. | |
| req-anchore-states-3 | Resolve Only What Was Read | Proposed | A finding resolves only when its target was read successfully by the same scanner and that scanner no longer reports it. | |
| req-anchore-states-4 | Unanalysed Image Has No Verdict | Proposed | An image in Anchore's inventory with no analysis results is recorded as having no verdict, not as clean. | Anchore's ECS page states such images "never gain vulnerability or policy results". |

### The Scope Walk
----
RID: `req-anchore-scope-walk`

Status: `Proposed`

What the collector reads, and at which scope. Anchore exposes the same kinds of facts at three scopes, and the walk reads all three.

#### Implementation

All GET, and all documented in the OpenAPI file, none observed.

- **Images** (by digest): `/images`, then per image `/vuln/{os|non-os|all}`, `/sboms/{native-json|spdx-json|cyclonedx-json}`, `/vex/{openvex|cyclonedx-json|cyclonedx-xml}`, `/vuln-annotations`, `/check` and the `/content/*` reads that carry package data.
- **Sources** (repository sources): `/sources` with `/sources/{id}/vuln` and its SBOM reads.
- **Application versions:** the `/apps/...` family (assets, packages, vulnerabilities, vulnerability annotations, policy status) and the older `/applications/...` family. Which family a given instance serves is probed and recorded; if both are served, the `/apps/...` family is preferred as the one that carries the asset concept.

The vendor's `/query/*` reads and the account-wide listings that return the same facts are not used in v0: the per-scope reads carry provenance the query forms drop. The runtime inventory has its own requirements.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-anchore-scope-walk-1 | Every Scope Walked | Proposed | Images, sources and application versions are each read when the instance offers them; one failing does not stop the others. | |
| req-anchore-scope-walk-2 | Family Is Probed | Proposed | The collector records which application path family the instance serves and reads that one. | Which is current is unknown until the trial. |
| req-anchore-scope-walk-3 | Only Extracted Paths | Proposed | The client calls only paths present in the committed extract. | A path outside it fails a test. |
| req-anchore-scope-walk-4 | Account In Every Key | Proposed | Every Anchore-specific node key begins with the scanner key (canonical API root and account together), so two accounts on one instance never share a node, whether or not Anchore's identifiers are unique across accounts. | Added in response to the review of anchore-tap PR 2; uniqueness across accounts is unobserved. |
| req-anchore-scope-walk-5 | Distinct Roots Are Distinct Scanners | Proposed | The same host and account on a different port or API root yields a different scanner key; a test asserts it, and asserts the key carries no credential. | Added in response to the review of anchore-tap PR 2. |

### Findings And Vulnerabilities
----
RID: `req-anchore-findings`

Status: `Proposed`

How Anchore's vulnerability results become `compliance_core` nodes. This plugin authors none of these types; it produces them.

#### Implementation

- `compliance_core__compliance_scanner`: one per Anchore instance and account, `source` `anchore`, `scanner_key` derived from the canonical API root and the account together. The canonical API root is the scheme-less, lower-cased host, port and path of `base_url`, with no credentials, query or fragment (`anchore.example:8228/v2`), so installations on different ports or API roots of one host are different scanners, and so are two accounts on one root. The reported version is a fact on the scanner, not part of its key.
- `compliance_core__compliance_scan_run`: one per collection, carrying the probe results, the self-test verdict and the lists of scopes not read.
- `compliance_core__compliance_vulnerability`: keyed by `vuln_id`, the public record (CVE, else GHSA), with Anchore's other identifiers as aliases. Anchore's CVSS and URL data fill the vulnerability only through partial patches that never overwrite what another producer wrote, and an absent value is `null`.
- `compliance_core__compliance_finding`: `source` `anchore`, `source_key` a compact JSON array of the `scanner_key`, the vulnerability id, the target kind (`image` or `source`), the target key and the package's key, never the run. For an image the target key is the image host's key; for a repository source it is the source's Anchore id within the scanner, and v0 has no source node, so a source finding attaches to the package it concerns and to the source's `sbom_document`, not to a source node. Whether a source finding can name an image is unobserved. The scanner is in the key so that two Anchore instances or accounts reporting the same assertion are two findings, and one instance's successful read can never resolve a finding another still reports. `CONCERNS_COMPLIANCE_VULNERABILITY` carries the fix: `fixed_versions` and `fix_state` in Anchore's own words, with the existing tri-state meaning (absent means not observed; `[]` means looked and none). A finding attaches to the image, SBOM or package it concerns; the application graph reaches it by traversal and the finding is never copied under an application.
- **Severity (open, a review ask).** `compliance_core` has no severity field on the finding and derives bands from CVSS on the vulnerability. Anchore reports its own severity per finding. The ruling is that severity goes on the finding side, not the shared vulnerability node. The existing home for per-finding scanner facts is the properties of `CONCERNS_COMPLIANCE_VULNERABILITY`, which carries only `fixed_versions` and `fix_state` today; this plugin proposes an optional `severity` property there, a `compliance_core` change that does not exist yet. Until it lands, Anchore's severity is not stored, and a finding says so by having no severity, not by carrying a guess.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-anchore-findings-1 | Neutral Types Only | Proposed | Scanner, scan run, vulnerability and finding nodes are `compliance_core`'s types; this plugin declares none of them. | |
| req-anchore-findings-2 | Keyed By Assertion | Proposed | A finding's key names the vulnerability and its target, never the run; two runs reporting the same assertion are one finding. | |
| req-anchore-findings-3 | Fix State Tri-State | Proposed | `fixed_versions` is the list when Anchore says fixed, `[]` when it says none, and absent when unknown. | Mirrors `grype-tap`. |
| req-anchore-findings-4 | Not Copied Under Applications | Proposed | The same finding is never stored under an application, version or asset; the application graph reaches it by traversal. | Ruled by George 2026-10-29: findings stay on the image or SBOM. |
| req-anchore-findings-5 | Severity Waits For A Home | Proposed | Anchore's severity is stored only once `compliance_core` has a per-finding home for it; until then it is not stored and the gap is documented. | A review ask. |
| req-anchore-findings-6 | Instance In The Key | Proposed | A finding's key includes the scanner key (instance and account); the same assertion from two instances or accounts is two findings, and resolution is scoped to one scanner. | Added in response to the review of anchore-tap PR 2. |
| req-anchore-findings-7 | Source Findings Have A Key | Proposed | A finding read at source scope has a key built from target kind `source` and the source's Anchore id; it is never given an invented image identity and is never skipped. | Added in response to the review of anchore-tap PR 2. |

### SBOMs
----
RID: `req-anchore-sbom`

Status: `Proposed`

Anchore offers each image's and source's SBOM in three formats. All three are stored as documents; the CycloneDX one is parsed into packages.

#### Implementation

Reads `/sboms/native-json`, `/sboms/spdx-json` and `/sboms/cyclonedx-json` per image (and the source equivalents). Each is recorded as a `computing_core__sbom_document` (content digest over the exact bytes, never the body). The CycloneDX document, and only that one, is parsed with `computing_core`'s CycloneDX parser into `package`, `library` and edges, for CycloneDX 1.4 to 1.7. The parser accepts only a verified document today and Anchore's are unsigned, so the plugin depends on a `computing_core` change that adds a fourth verification outcome, `source-authenticated`: the parser reads the document, and it is recorded with `verified` null and a note naming the Anchore instance and account, never marked verified. That change is not yet made (it is a separate `computing_core` pull request, with a trust-level column and a rule for what counts as current still to be settled). Until it lands, the plugin records every SBOM as a document and parses none, which is the safe state, not a failure. The SPDX and native JSON documents are stored but not parsed in v0.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-anchore-sbom-1 | Three Formats Recorded | Proposed | For each image and each repository source, the native, SPDX and CycloneDX documents are each recorded as an `sbom_document`. | Ruled by George 2026-10-29: store all three formats. |
| req-anchore-sbom-2 | Only CycloneDX Parsed | Proposed | Only the CycloneDX document is parsed into packages; the other two are recorded unread. | |
| req-anchore-sbom-3 | Never Marked Verified | Proposed | No Anchore document has `verified` true or a signer; the trust level names the source. | |
| req-anchore-sbom-4 | Safe Until The Outcome Exists | Proposed | Until `computing_core` provides the source-authenticated outcome, documents are recorded and none is parsed. | Depends on a pending `computing_core` change. |
| req-anchore-sbom-5 | Subject Is The Image Host | Proposed | Each document describes the image host (`DESCRIBES_HOST`) of the digest it is for. | |

### The Application Graph
----
RID: `req-anchore-application`

Status: `Proposed`

Anchore's application is a small graph of four levels: an application, its versions, each version's assets, and the image or SBOM behind each asset. It is mapped as nodes and edges, not as one node holding links as values.

#### Implementation

Three Anchore-specific types, each with `anchore.area: inventory`:

- `anchore_application`: key `(scanner_key, application_id)`. Name, description, the organization name Anchore shows for it, the owning policy id, and the version count as Anchore reports it. The contact's name, email and phone are personal data and are not stored: the VDR use does not need them, and the plugin asks for no more than it uses.
- `anchore_app_version`: key `(scanner_key, application_id, version_id)`. Name, description, status (`in_progress`, `released`, `eol`), release date. Policy results are `req-anchore-policy-result`.
- `anchore_asset`: key `(scanner_key, application_id, version_id, asset_id)`. Name, type (one of application, container, device, file, firmware, library, module, filesystem, virtual_machine_disk, unknown), reference, and the annotations Anchore holds on it (at most ten, with keys up to 150 and values up to 1000 characters, set by Anchore's users; the same operator allowlist as Kubernetes annotations applies, empty by default, because a user-set value can hold anything).

Edges: `HAS_VERSION__anchore` (application to version), `PRECEDES_VERSION__anchore` (a version to the one after it, from Anchore's previous-version pointer), `CONTAINS_ASSET__anchore` (version to asset), `REFERENCES_IMAGE__anchore` (asset to the image host) and `REFERENCES_SBOM__anchore` (asset to `sbom_document`). The image host is a `computing_core__host` with realm `oci-digest` and the manifest digest as `stable_id` (`computing-core-tap` pull request 60). An asset whose artifact carries a tag but no digest gets no image edge; the digest is unobserved and none is invented. 

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-anchore-application-1 | Graph, Not Links In A Value | Proposed | The application, version and asset are three node types joined by the edges above; no node stores another node's id as a value to be followed. | Ruled by George 2026-10-29: map the application as a subgraph. |
| req-anchore-application-2 | Version Chain | Proposed | `PRECEDES_VERSION__anchore` follows Anchore's previous-version pointer, and a missing pointer draws no edge. | |
| req-anchore-application-3 | Edges To Existing Nodes | Proposed | An asset's image edge targets the `computing_core` image host and its SBOM edge targets the `sbom_document`; neither is a new Anchore type. | |
| req-anchore-application-4 | No Invented Digest | Proposed | An asset with no digest draws no image edge and is recorded with the digest unobserved. | |
| req-anchore-application-5 | Dimensions | Proposed | The three types declare `anchore.area: inventory`. | |
| req-anchore-application-6 | Annotations Only By Allowlist | Proposed | An asset's annotations are stored only for keys on the operator's `annotation_allowlist`, empty by default. | Added in response to the review of anchore-tap PR 2; the same setting governs Kubernetes annotations. |
| req-anchore-application-7 | No Contact Personal Data | Proposed | An application's contact name, email and phone are not stored; only the organization name is. | Added in response to the review of anchore-tap PR 2; narrows the first draft. |

### VEX Annotations
----
RID: `req-anchore-vex`

Status: `Proposed`

A VEX annotation is a statement that says whether a vulnerability matters for a package ("CVE-X in package Y is `not_affected`, because `vulnerable_code_not_present`"). Anchore stores them at two scopes, an image and an application version, with the same fields. They live in Anchore-specific nodes linked to the neutral vulnerability and package nodes, and are never turned into a VDR factor automatically.

#### Implementation

One type, `anchore_vex_annotation` (`anchore.area: annotation`), key `(scanner_key, scope_kind, scope_id, annotation_id)` where `scope_kind` is `image` or `app_version`. Fields: the vulnerability id; package name, version and type (the package scope is null when the annotation is about a whole image; what that means in practice is unobserved); `status` (`not_affected`, `affected`, `fixed`, `under_investigation`); `justification` (the six values Anchore defines); status notes; impact statement; action statement; additional details; and source (type `external` or `user`, and a name). Edges: `ANNOTATES_IMAGE__anchore` (to the image host) or `ANNOTATES_VERSION__anchore` (to the application version), according to scope; `ABOUT_VULNERABILITY__anchore` (to the `compliance_vulnerability`); and `ABOUT_PACKAGE__anchore` (to the `package`) when the package scope is present. The free-text fields (status notes, impact and action statements, additional details) are operator-authored VDR evidence and are the point of the type; they are stored as Anchore returns them, bounded to their column lengths, and are not redacted by this plugin, so the grid's own access control is what protects them and an operator should treat them as sensitive. Whether an application version inherits its images' annotations is unobserved; both scopes are stored as Anchore reports them and nothing is merged.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-anchore-vex-1 | One Type, Scope In The Key | Proposed | A single `anchore_vex_annotation` type serves both scopes, with `scope_kind` and `scope_id` in its natural key. | Ruled by George 2026-10-29: one type; a later split is an accepted risk. |
| req-anchore-vex-2 | Scope Edge Matches Scope | Proposed | An image-scope annotation has `ANNOTATES_IMAGE__anchore` and no version edge, and the reverse for an application-version scope. | |
| req-anchore-vex-3 | Linked To Neutral Nodes | Proposed | Each annotation has `ABOUT_VULNERABILITY__anchore`, and `ABOUT_PACKAGE__anchore` when its package scope is not null. | |
| req-anchore-vex-4 | No Automatic VDR Mapping | Proposed | No VEX status is written into any VDR factor by this plugin. | Ruled by George 2026-10-28: VEX nodes link to the VDR nodes without automatic mapping; mapping belongs to the VDR plugins. |
| req-anchore-vex-5 | Null Package Scope Kept | Proposed | A null package scope is stored as null and is not widened to every package of the image. | Meaning to be observed on the trial. |
| req-anchore-vex-6 | Free Text Is Evidence, Not Redacted | Proposed | The free-text fields are stored as returned and bounded in length; no redaction is attempted, and the spec marks them sensitive. | Added in response to the review of anchore-tap PR 2. |

### Policy Results
----
RID: `req-anchore-policy-result`

Status: `Proposed`

Anchore evaluates policy per application version. The result is stored on the version, because it is scoped to the version and cannot be derived from images alone.

#### Implementation

From `GET /apps/{app_id}/versions/{version_id}/policy/status` and the policy-findings reads: on `anchore_app_version`, `policy_status`, `policy_id`, `policy_evaluated_at` and counts of findings by action, each `null` when not read. The individual policy findings are not stored as nodes in v0: Anchore's policy findings are already reachable through the vulnerability findings they reference, and a per-finding policy node would copy facts the finding already carries. They are listed as Backlog in the non-goals.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-anchore-policy-result-1 | Status On The Version | Proposed | `policy_status`, `policy_id`, `policy_evaluated_at` and finding counts are properties of `anchore_app_version`. | |
| req-anchore-policy-result-2 | Unevaluated Is Null | Proposed | A version Anchore has not evaluated has `null` policy fields, not a passing status. | |

### Runtime Inventory: Images In Use
----
RID: `req-anchore-inventory`

Status: `Proposed`

Anchore's runtime inventory says which images are running, and where. Two Anchore agents (one for Kubernetes, one for ECS) report running containers to Anchore on a schedule, and Anchore keeps what was last reported and expires the rest: by default 120 days after an agent last reported it, or by overwrite per cluster and namespace. This requirement reads the flat list of images in use.

#### Implementation

`GET /inventories` (documented: items of `inventory_type` ecs or kubernetes, `context`, `image_tag`, `image_digest`, `created_at`, `last_updated`, `last_seen`; filters `inventory_type`, `image_digest`, `context`). One Anchore-specific type `anchore_runtime_image` (`anchore.area: runtime`), key `(scanner_key, inventory_type, context, image_digest)`, with the tag, the three timestamps, and an edge `OBSERVES_IMAGE__anchore` to the image host. The key is the digest, not the tag: the Kubernetes agent can fill a missing tag with the digest, so a tag can be synthetic. An item with no digest makes no node and is counted as unobserved on the run. A record that disappears from Anchore is not proof that a workload stopped; it may be expiry or an agent outage, so the plugin stores `last_seen` and never closes or deletes on absence.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-anchore-inventory-1 | Keyed By Digest | Proposed | An image-in-use node is keyed by scanner key, inventory type, context and digest, and not by tag. | |
| req-anchore-inventory-2 | No Digest, No Node | Proposed | An inventory item with no digest creates no node; it is counted on the run. | |
| req-anchore-inventory-3 | Absence Is Not Stopped | Proposed | A record missing from a later read is not deleted or marked stopped; `last_seen` is the only age signal. | |
| req-anchore-inventory-4 | Joined To The Image Host | Proposed | Each node has `OBSERVES_IMAGE__anchore` to the `oci-digest` image host. | |

### Runtime Inventory: Kubernetes
----
RID: `req-anchore-inventory-kubernetes`

Status: `Proposed`

The Kubernetes side of the runtime inventory: the namespaces, nodes, pods and containers the Anchore Kubernetes agent reported, joined to the image each container runs.

#### Implementation

Reads `GET /kubernetes-namespaces`, `/kubernetes-nodes`, `/kubernetes-pods` and `/kubernetes-containers` (documented; each takes a required `page` and an optional `page_size`, default 1000). Four Anchore-specific types, each `anchore.area: runtime`, each keyed by the scanner key and the cluster context together with the uid Anchore reports: `anchore_k8s_namespace` (uid, name, labels, last seen), `anchore_k8s_node` (uid, name, labels, kernel, Kubernetes, kubelet, kube-proxy and container-runtime versions, architecture, operating system, last seen), `anchore_k8s_pod` (id, name, labels, last seen) and `anchore_k8s_container` (id, name, context, image tag, image digest). Edges: `IN_NAMESPACE__anchore` (pod to namespace), `SCHEDULED_ON__anchore` (pod to node), `CONTAINS_CONTAINER__anchore` (pod to container), and `RUNS_IMAGE__computing_core` from the container to the image host (an existing edge with an open source). Kubernetes annotations are not stored by default: they are free-form maps that routinely hold tool configuration (a last-applied manifest, for example) and can carry secrets. An operator setting names the annotation keys to keep, an empty list by default (`req-anchore-inventory-kubernetes-5`); labels are stored. These four types are provisional: they exist because no Kubernetes vocabulary is on the grid, and a neutral one should replace them if it appears. The vendor's schema declares the nodes and pods list responses under a wrapper key named `namespaces`, which looks like a copy of the namespaces response; the real key is unobserved, and the contract tests are where the correction lands.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-anchore-inventory-kubernetes-1 | The Chain | Proposed | A container reaches its pod, its namespace, its node and its image host by the edges above. | |
| req-anchore-inventory-kubernetes-2 | Identity Is The Reported Uid Within A Cluster | Proposed | Each type is keyed by scanner key, context and the uid or id Anchore reports, never by name. | Names are mutable. |
| req-anchore-inventory-kubernetes-3 | Wrapper Key Observed | Proposed | The parser's wrapper keys for the nodes and pods responses are set from a recorded response, not from the vendor schema. | |
| req-anchore-inventory-kubernetes-4 | Provisional Types | Proposed | The four types are documented as provisional pending a neutral Kubernetes vocabulary. | |
| req-anchore-inventory-kubernetes-5 | Annotations Only By Allowlist | Proposed | No Kubernetes annotation is stored unless its key is on the operator's allowlist, which is empty by default; labels are stored. | Added in response to the review of anchore-tap PR 2. |

### Runtime Inventory: ECS
----
RID: `req-anchore-inventory-ecs`

Status: `Proposed`

The ECS side: tasks, services and containers the Anchore ECS agent reported. `aws_core` already collects ECS clusters, services, tasks and containers, so the runtime facts attach to those by ARN instead of duplicating them.

#### Implementation

Reads `GET /ecs-containers` (documented; required `page`, optional `page_size`). There is no cluster list: the cluster is the `cluster_arn` or `context` on those records. For each ECS container Anchore reports (ARN, task ARN, context, image tag, image digest), the plugin looks up the `aws_core` ECS container by ARN and, when found, writes `RUNS_IMAGE__computing_core` from it to the image host. It never creates an `aws_core` node (a vocabulary it does not own); an ARN with no matching node is counted on the run as unresolved, and the observation is kept in `anchore_runtime_image`. `/ecs-tasks` and `/ecs-services` are not read in v0: the `aws_core` task and service nodes carry the same structure, and Anchore's copy adds only its own tags.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-anchore-inventory-ecs-1 | Join By ARN | Proposed | An Anchore ECS container is joined to the `aws_core` container with the same ARN, and no `aws_core` node is created by this plugin. | |
| req-anchore-inventory-ecs-2 | Unresolved Is Counted | Proposed | An ARN with no matching node is counted as unresolved on the run and does not fail it. | |
| req-anchore-inventory-ecs-3 | Image Edge From The Container | Proposed | A resolved container gets `RUNS_IMAGE__computing_core` to the image host. | |

### Hosted And On-Prem Differences
----
RID: `req-anchore-differences-ledger`

Status: `Proposed`

The plugin targets the hosted service first and must work on-prem. The difference between them is kept as a ledger, and no row says the two are the same until it has been observed on both. Today neither is observed (the trial instance is requested), so every row is documented, secondary or unknown.

#### Implementation

The ledger below is the spec's section and is refreshed from the trial and from the self-test of each run (`req-anchore-selftest`). Basis: *documented* is Anchore's docs or the OpenAPI file; *secondary* is third-party text; *unknown* needs the trial.

| # | Area | On-prem (self-hosted) | Hosted SaaS | Basis |
| --- | --- | --- | --- | --- |
| 1 | Base URL | `http(s)://<host>:<port>/v2`; the docs example uses port 8228 | unknown | on-prem documented |
| 2 | API version | customer-chosen release; a chart note says v5.0.0 broke API endpoints | presumably current | secondary |
| 3 | Version probe | `GET /system` and `/status` should report it | unknown | to observe |
| 4 | Two path families | `/applications/...` and `/apps/...` for application versions | unknown which is live | documented; which is current unknown |
| 5 | Auth | Basic, API key (user `_api_key`), OAuth2 bearer | unknown; SSO users may need API keys enabled | on-prem documented |
| 6 | Account scoping | `x-anchore-account` header for cross-account reads | may be single-account | unknown |
| 7 | Feeds | Data Syncer hourly; air-gapped by manual sync | vendor-managed (assumed) | on-prem documented |
| 8 | Feed freshness | `/system/feeds` | unknown | to observe |
| 9 | Admin surface | `/system/*`, `/accounts*`, services, configuration | likely restricted or absent | unknown |
| 10 | Analysis mode | centralized or distributed; malware needs centralized | unknown | documented; hosted unknown |
| 11 | TLS | private CA likely; plain HTTP is refused (`req-anchore-connection-4`) | public CA likely | assumed |
| 12 | Rate limits and paging caps | none documented | unknown | to observe |
| 13 | Runtime inventory | Kubernetes and ECS endpoints | unknown | to observe |
| 14 | GraphQL reports | `/v2/reports/graphql`, can lag REST | unknown | documented |

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-anchore-differences-ledger-1 | No Same Without Observation | Proposed | A ledger row says the two are the same only when it cites an observation on both. | |
| req-anchore-differences-ledger-2 | Refreshed From The Trial | Proposed | The first trial session replaces each "unknown" with an observation or leaves it unknown with a note. | |

### FIPS Posture
----
RID: `req-anchore-fips`

Status: `Proposed`

The plugin runs in a FIPS-mode TAP deployment. It needs only `requests`, which is already a direct dependency of core (`requests>=2.34.2,<3`), and the standard library; TLS goes through system OpenSSL.

#### Implementation

The manifest declares `[fips] status = "compatible"` after `validate_plugin --strict` reports no non-validated crypto provider. No native binary ships (AnchoreCTL is not used). If a dependency later introduces one, the declaration changes to `uses-nonvalidated` with a reason, in the same change.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-anchore-fips-1 | Declared Compatible | Proposed | The manifest declares `[fips]` as compatible and `validate_plugin --strict` agrees. | |
| req-anchore-fips-2 | No Native Binary | Proposed | The wheel ships no binary and calls none. | |

### v0 Non-Goals
----
RID: `req-anchore-nongoals`

Status: `Proposed`

What this plugin deliberately does not do, and who owns it instead.

#### Implementation

| Not done | Why | Owner or status |
| --- | --- | --- |
| Any write to Anchore: annotations, export jobs, asset-adding jobs, policy authoring, inventory POST or DELETE | Read-only; the credential can be a read-only role | Not built |
| Secret-search, retrieved-file and file-content results; account and API-key endpoints; operator configuration endpoints | Secret-bearing, credential or admin surfaces. Only the fact that a secret was found, its type and its path may be recorded | Excluded (ruled by George 2026-10-28) |
| The per-file listing of every image | Large, low value in v0 | Backlog (ruled by George 2026-10-28) |
| Mapping Anchore status to VDR factors | Policy, not collection | `fedramp_20x_vdr`, `stackarmor_vdr` |
| Pages and panels | No data to look at yet | A later spec |
| Enrichment such as KEV and EPSS | Another plugin's job | `vuln_mosaic` |
| The GraphQL reports API | It can lag REST | Revisit if REST gaps appear |
| Individual policy findings as nodes | They duplicate the vulnerability findings they reference | Backlog |
| A node per realm explaining each realm | Undecided; a first cut is a table in `computing_core` | `computing_core` Not Yet Built |

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | --- | --- | --- |
| req-anchore-nongoals-1 | No Write Path | Proposed | No code path sends a non-GET request. | Same test as `req-anchore-client-1`. |
| req-anchore-nongoals-2 | Excluded Endpoints Absent | Proposed | No excluded endpoint appears in the contract extract or the client. | |

## Model catalog

A design-time catalog, superseded by the manifest once the plugin ships.

| Model | Entity type | Category | Rationale |
| --- | --- | --- | --- |
| Application | `anchore__anchore_application` | Anchore-specific | Anchore's grouping of images and SBOMs; no neutral equivalent. |
| Application Version | `anchore__anchore_app_version` | Anchore-specific | A version with its own status, chain and policy result. |
| Asset | `anchore__anchore_asset` | Anchore-specific | A named, typed thing in a version that references an image or an SBOM. |
| VEX Annotation | `anchore__anchore_vex_annotation` | Anchore-specific | One type for both scopes; a vulnerability status statement. |
| Runtime Image | `anchore__anchore_runtime_image` | Anchore-specific | An image in use in a context, with its last-seen times. |
| Kubernetes Namespace | `anchore__anchore_k8s_namespace` | Anchore-specific, provisional | No Kubernetes vocabulary on the grid. |
| Kubernetes Node | `anchore__anchore_k8s_node` | Anchore-specific, provisional | As above. |
| Kubernetes Pod | `anchore__anchore_k8s_pod` | Anchore-specific, provisional | As above. |
| Kubernetes Container | `anchore__anchore_k8s_container` | Anchore-specific, provisional | As above. |

## Edge types

| Edge | From → To | Properties | Rationale |
| --- | --- | --- | --- |
| `HAS_VERSION__anchore` | application → version | none | Containment: a version exists only within its application. |
| `PRECEDES_VERSION__anchore` | version → version | none | Anchore's previous-version chain, drawn forward. |
| `CONTAINS_ASSET__anchore` | version → asset | none | Containment: an asset exists only within its version. |
| `REFERENCES_IMAGE__anchore` | asset → image host | none | Reference to a `computing_core` host. |
| `REFERENCES_SBOM__anchore` | asset → sbom_document | none | Reference to a `computing_core` document. |
| `ANNOTATES_IMAGE__anchore` | VEX annotation → image host | none | Image scope. |
| `ANNOTATES_VERSION__anchore` | VEX annotation → version | none | Application-version scope. |
| `ABOUT_VULNERABILITY__anchore` | VEX annotation → vulnerability | none | Links to the neutral vulnerability. |
| `ABOUT_PACKAGE__anchore` | VEX annotation → package | none | Links to the neutral package when scoped. |
| `OBSERVES_IMAGE__anchore` | runtime image → image host | none | Joins an image in use to the image host. |
| `IN_NAMESPACE__anchore` | pod → namespace | none | Kubernetes placement. |
| `SCHEDULED_ON__anchore` | pod → node | none | Kubernetes placement. |
| `CONTAINS_CONTAINER__anchore` | pod → container | none | A pod holds its containers. |
