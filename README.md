# anchore-tap

TAP plugin that reads vulnerability findings, SBOMs, VEX statements, policy results and runtime inventory
from Anchore Enterprise, hosted or on-prem, and holds them on the grid as Anchore returns them, to support
FedRAMP vulnerability detection and response (VDR).

**Status: v0.1.2, spec-derived and not yet run against a real Anchore.** The observation command, the
read-only client, the nodes and edges, the per-run self-test and probe, and a collector (`anchore:anchore`)
exist and are tested against a canned instance. Every field is taken from Anchore's published OpenAPI file
(2.20.0), not from a recorded response, so expect the first real run to find differences. The spec says no
requirement reaches `Implemented` before a recorded response replaces its assumptions.

## What it owns, and will own

- A read-only collector for Anchore's REST API (`/v2`), using `requests`.
- Built so far: the scanner, scan run and finding nodes, the image documents and the links described below. Still to build: VEX annotations, applications, versions, assets and runtime observations.
- Anchore-owned nodes (scanner, scan run, finding, VEX annotation, application, version, asset and
  runtime observations) holding Anchore's fields unchanged, linked to the `computing_core` image host,
  package and SBOM nodes they concern, and to the shared vulnerability node when it exists.

## What lives elsewhere

- Mapping Anchore status onto VDR factors: `fedramp_20x_vdr` and `stackarmor_vdr`.
- Reading Anchore beside other scanners (a shared fix model, severity scales, house mappings): a later
  layer, shaped once Anchore's data is on the grid. This plugin writes nothing to `compliance_core`.
- Pages and panels: a later spec, once there is data to look at.

## Read first

`specs/spec-anchore-v0.md`: identity, philosophy, every requirement with acceptance criteria, the model
catalog and the edge types.

## A first session against an Anchore instance

The observation command reads an instance, records every raw response in `~/anchore-recordings/`
(private, outside any repository) and prints which open questions it answered. It is read-only and
writes nothing to the grid.

1. Copy one of `tap_plugin/anchore/schemas/examples/*.secret.example.json` (basic, API key or bearer) to
   `anchore-<name>.secret.json` under a **private** secrets directory (not the shared `~/tap-secrets`),
   rename its `key` to match the file, and fill in a **read-only** credential. Never commit it, and never paste
   it into chat.
2. From a core checkout with a virtualenv holding `requests`, `jsonschema` and `django`:
   `TAP_SECRETS_ROOT=<private dir> PYTHONPATH=<core checkout>:<this checkout> python -m tap_plugin.anchore.observe --list`
   then `--key <name> --dry-run`, then `--key <name>`.
3. Run it once per credential scheme and per instance. Recordings stay local; commit a fixture only after
   reviewing a trimmed copy.

## Running the collector

The collector reads every credential in scope `anchore` under the secrets root, so do the first session above
first and keep the envelope. Per instance it checks that `GET /account` names the configured account, runs
the self-test against the instance's own API description, lists the images, and for each analyzed image reads
the vulnerabilities and the three SBOM formats, then submits one GRIFT batch.

What lands on the grid: an Anchore scanner, one scan run per collection (probe results, self-test verdict, and
every scope read or *not read* with the reason) and one finding per vulnerability assertion, all holding
Anchore's values as returned; an image host (`oci-digest`) only where none exists; one `sbom_document` per
format, keyed by the digest of its exact bytes, never marked verified, with nothing parsed into packages; and
edges from findings to the image host and, only where it already exists with exactly the same identifier, to the
shared vulnerability. A scope that was not read is never a clean result, and a read that failed leaves the
findings it would have updated as they were.

To try it, boot a profile that installs `computing_core` v0.10.3, `compliance_core` v0.8.11 and this plugin at
`v0.1.2` (the `ci` record in `tap_plugin/anchore/boot/ci.boot.json` is a working list), run `manage.py boot` so the
collector node is reconciled, and fire the collector as the scheduler actor:

    with acting_as(get_builtin_actor(SCHEDULER)):
        job = run_collection(collector, caller_context=CallerContext(), manual_run=True, manual_run_source="dev-test")

then read the job's `status`, `summary` and `results`. With no credential the job fails as unconfigured, which is
the intended refusal. Not yet built: findings linked to packages, source and application reads, VEX and inventory.

## Standing it up

The plugin's own tests run in the stack described by `tap_plugin/anchore/boot/ci.boot.json`:
`spawn-session.sh <label> --from 'git+https://github.com/unified-systems-com/anchore-tap@<rev>#ci' --dev-plugins anchore`,
then `pytest --pyargs tap_plugin.anchore.tests`. The record pins `computing_core` v0.10.3 and
`compliance_core` v0.8.11 at tags, and this plugin at its own release.
