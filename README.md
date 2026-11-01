# anchore-tap

TAP plugin that reads vulnerability findings, SBOMs, VEX statements, policy results and runtime inventory
from Anchore Enterprise, hosted or on-prem, and holds them on the grid as Anchore returns them, to support
FedRAMP vulnerability detection and response (VDR).

**Status: package scaffold.** The package, manifest, CI record and workflows exist; nothing collects data
yet. Every requirement in `specs/spec-anchore-v0.md` is still `Proposed`, and the spec says no
requirement reaches `Implemented` before a recorded response from a real Anchore instance replaces its
assumptions.

## What it will own

- A read-only collector for Anchore's REST API (`/v2`), using `requests`.
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

## Standing it up

The plugin's own tests run in the stack described by `tap_plugin/anchore/boot/ci.boot.json`:
`spawn-session.sh <label> --from 'git+https://github.com/unified-systems-com/anchore-tap@<rev>#ci' --dev-plugins anchore`,
then `pytest --pyargs tap_plugin.anchore.tests`.

The image-host identity this plugin needs (the `oci-digest` realm) is in `computing-core-tap` main but not
yet in a release; the CI record pins `v0.10.2` until one ships.
