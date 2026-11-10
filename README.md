# anchore-tap

TAP plugin that reads vulnerability findings, SBOMs, VEX statements, policy results and runtime inventory
from Anchore Enterprise, hosted or on-prem, and holds them on the grid as Anchore returns them, to support
FedRAMP vulnerability detection and response (VDR).

**Status: v0.1.4, with base-image attribution on main, spec-derived and not yet run against a real Anchore.** The observation command, the
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

## Choosing what a run reads

An Anchore account can hold far more images than are deployed, so the envelope says which ones a run reads
(`req-anchore-scope`). One setting is required and has no default:

    "scope": {"running_only": true}

- `true` reads only the images Anchore's runtime inventory reports as running. With nothing else set, that
  is everything running.
- `false` reads every image on the instance.

An envelope without it is refused, including one written for v0.1.3. The optional settings:

| setting | meaning |
| --- | --- |
| `scope.aws_account_ids` | Running in ECS in these accounts (read from the container's ARN). |
| `scope.context_prefixes` | Running in an inventory context that begins with one of these; `prod-east/` is one cluster. |
| `scope.repository_prefixes` | Registry and repository begin with one of these. Narrows what is read in either mode, and what the runtime inventory writes: a running container whose image is outside them is not written. |
| `inventory_max_age_hours` | How recently Anchore must have seen a record for it to count as running. Default 24. |
| `limits.max_response_mib` | The largest response body read, in MiB. Default 64, up to 1024. A larger body is not read and is listed as not read. Raise it for very large SBOMs. |
| `limits.max_run_minutes` | How long a run may keep starting new image reads. Unset by default: no limit. Past it, the images left are listed as not read, their findings are left alone, and what was read is written. |
| `create.ecs` | Default false. True creates the `aws_core` ECS container, task, service and cluster nodes the grid lacks for the selected containers. Read the spec's "Concerns to recognise in the field" first. |
| `create.kubernetes` | Default true. Writes the Kubernetes cluster, namespace, node, pod and container objects behind the running containers in scope, into `computing_core`'s Kubernetes types (v0.10.4 or later). |

Where `aws_core` is installed, each selected ECS container is joined to the `aws_core` container with the same ARN by `RUNS_IMAGE` to its image; nothing on that container is written, and one the grid does not have is counted on the scan run.

Account and context settings are a union. An image the scope leaves out is not read, and its findings on
the grid are left as they were: out of scope is not clean. The scan run records the settings it ran with
and how many images were listed, selected and left out.

A runtime reports a multi-platform image by its index digest, while Anchore analyzes one platform's
image under its own digest. A running digest is therefore matched on an image's `parent_digest` as
well as its `image_digest`: the findings are read under the analyzed image, the runtime image node
keeps the running digest and lists the analyzed ones in `analyzed_digests`, and several platform
images under one index are all read.

## Base image or application

Each image's vulnerabilities are read with `base_digest=auto`, so Anchore works out the image's
base image and marks each finding `inherited_from_base`: true when the vulnerable package came
with the base, false when it was added on top. The finding also records `base_digest`, the base
Anchore compared against. An image is joined to the images it was built on by
`BUILT_ON_IMAGE__anchore`.

Anchore can only name a base it has itself analyzed. Where it names none, the flag is empty,
which means unobserved, not "no base". Add your base images to Anchore to fill it.

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

To try it, boot a profile that installs `computing_core` v0.10.4, `compliance_core` v0.8.11 and this plugin at
`v0.1.4` (the `ci` record in `tap_plugin/anchore/boot/ci.boot.json` is a working list), run `manage.py boot` so the
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
