# anchore-tap

TAP plugin that reads vulnerability findings, SBOMs and VEX statements from Anchore Enterprise, hosted
or on-prem, and lands them on the grid to support FedRAMP vulnerability detection and response (VDR).

**Status: specification stage.** There is no package yet. The design is being written as
`specs/spec-anchore-v0.md` with the author; nothing here collects data.

## What it will own

- A read-only collector for Anchore's REST API (`/v2`), using `requests`.
- Anchore-specific nodes where the vendor concept has no neutral home (the application, its versions and
  assets, and VEX annotations), linked to the neutral `compliance_core` and `computing_core` types.

## What lives elsewhere

- Mapping Anchore status onto VDR factors: `fedramp_20x_vdr` and `stackarmor_vdr`.
- Pages and panels: a later spec, once there is data to look at.

## Read first

`specs/spec-anchore-v0.md`, once it lands.
