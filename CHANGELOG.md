# Changelog

## 0.1.0 (2026-11-02)


### Features

* **contract:** the extract, its bounded reducer and the scheduled drift check ([e5a91f5](https://github.com/unified-systems-com/anchore-tap/commit/e5a91f59f0f4d07ddccd7da00b6b2556335259a6))
* **contract:** the extract, its bounded reducer and the scheduled drift check ([464f9df](https://github.com/unified-systems-com/anchore-tap/commit/464f9df05d44fecfb887b6dcfa8c2be191ccef1e))
* the package scaffold, manifest, CI record and workflows ([bf1aaae](https://github.com/unified-systems-com/anchore-tap/commit/bf1aaae6b532c9449cc87decd9a6e90ac99e34a7))
* the package scaffold, manifest, CI record and workflows ([4a1afa0](https://github.com/unified-systems-com/anchore-tap/commit/4a1afa07d84bbdabcb3d783d26240157e1916289))
* the read-only client, the credential loader and the trial observation command ([451e5ef](https://github.com/unified-systems-com/anchore-tap/commit/451e5ef66d08c880ab081c39a9dfffea34287942))
* the read-only client, the credential loader and the trial observation command ([c61cc6e](https://github.com/unified-systems-com/anchore-tap/commit/c61cc6e0d4aec671d593627e8eb69a146d7d2a30))


### Bug Fixes

* **client,credential:** read the body arrival by arrival, and choose a redaction marker that cannot contain the credential ([23619ef](https://github.com/unified-systems-com/anchore-tap/commit/23619efc094445bc6790d1cee7e7e25efe0cf42d))
* **client,observe:** bind the session to the API root, redact echoed credentials, bound streaming time ([78afc74](https://github.com/unified-systems-com/anchore-tap/commit/78afc747be934e1fc52a2d1ca71560370ad915f3))
* **client,observe:** cap each request by the remaining budget, keep recordings out of repositories ([999bbf9](https://github.com/unified-systems-com/anchore-tap/commit/999bbf97a5a8c5b9dce63d9f6e1966e9689b0ba9))
* **client,observe:** contain malformed streams, and account for every consumed operation ([fb2b598](https://github.com/unified-systems-com/anchore-tap/commit/fb2b5984649d6f7dd567800814070745af238b72))
* **client,observe:** refuse encoded dot segments under the API root, create recordings owner-only ([6b5cf9d](https://github.com/unified-systems-com/anchore-tap/commit/6b5cf9d1f4d8db4f42d41bc247f125bd0d3c81ee))
* **client:** enforce every guard in the session's send, and do not expose the session ([840c510](https://github.com/unified-systems-com/anchore-tap/commit/840c51082b9cd386c85ab39e79948e55e3f25019))
* **client:** refuse non-https by adapter lookup, not by mounting an http prefix ([13c822a](https://github.com/unified-systems-com/anchore-tap/commit/13c822a5e420a5aff9b2e0b92f7fcfefff907d1a))
* **contract:** charge kept schema values by what they hold ([ea68de0](https://github.com/unified-systems-com/anchore-tap/commit/ea68de0c65e5a8193c6b3bb29b6ac86f4a6fdaae))
* **contract:** charge shared schemas per use, track defaults, forbid the files content type ([5460ead](https://github.com/unified-systems-com/anchore-tap/commit/5460eadab6be332a299ee3c9134c2d08ed380348))
* **contract:** report changed unconsumed operations, bound the walk, move the source copy ([c8c04b3](https://github.com/unified-systems-com/anchore-tap/commit/c8c04b343efa5063ffcbc4167153258f129fcd24))
* **contract:** take no path from arguments; read stdin and print to stdout ([6eaa9fe](https://github.com/unified-systems-com/anchore-tap/commit/6eaa9fe91344469f7af7ff14574a97441e05e492))
* **credential,observe:** redact the Basic header exactly as requests encodes it, and mask the account in the report ([19ecc0e](https://github.com/unified-systems-com/anchore-tap/commit/19ecc0e14f1e32a2f5bd3407ab9a76197ba9484e))
* **observe:** clean instance-derived text before printing, and keep the account out of --list ([9bd695d](https://github.com/unified-systems-com/anchore-tap/commit/9bd695de6044cdc51729fae4a13e9be8484221fe))
* **observe:** redact the credential from everything an instance controls, and never build a URL from it ([ad8f4a9](https://github.com/unified-systems-com/anchore-tap/commit/ad8f4a912e112f53a8b38c5169ae1141cf35a837))
* raise the core floor to 0.3.1 and align the requests pin with core's ([064beca](https://github.com/unified-systems-com/anchore-tap/commit/064becaf4e65cffd63270ed562536943474d71cd))


### Documentation

* **spec:** bound the OpenAPI reducer ([020e187](https://github.com/unified-systems-com/anchore-tap/commit/020e187493fe2c2480bb05626f709af316681b07))
* **spec:** bound the plaintext override; align the SBOM wording ([4c6d5c0](https://github.com/unified-systems-com/anchore-tap/commit/4c6d5c01afe3b9e651d796e457e99fc666f37934))
* **spec:** fail closed on an unserved spec; put the scanner in the finding key ([3fdae65](https://github.com/unified-systems-com/anchore-tap/commit/3fdae6519d4dfb15f7bff96b0555bbc1e8a72ce2))
* **spec:** HTTPS only with no override; the account is required ([c632304](https://github.com/unified-systems-com/anchore-tap/commit/c632304699d1b75fe0d0b847b40912c56cd4dbde))
* **spec:** HTTPS only, account in every key, annotations by allowlist ([0c9fec9](https://github.com/unified-systems-com/anchore-tap/commit/0c9fec9433dbe2a18cbb8226ca6958809abfd35a))
* **spec:** key source findings by target kind; bearer tokens are not minted here ([d107347](https://github.com/unified-systems-com/anchore-tap/commit/d1073473f982cdcb70a6427d60e0f1036b8a7709))
* **spec:** order the acceptance criteria numerically ([61a1e80](https://github.com/unified-systems-com/anchore-tap/commit/61a1e80c8bcd2ec8bd6487c3d4aefce7fea3d131))
* **spec:** record the ruling on unredacted VEX free text ([fcbe37a](https://github.com/unified-systems-com/anchore-tap/commit/fcbe37ab0e46fca08e58b8351a288d637e0bf5b2))
* **spec:** refuse redirects outright; cover source SBOMs in the acceptance criteria ([ae5c539](https://github.com/unified-systems-com/anchore-tap/commit/ae5c539e9c80d39c2c19425975765a7ee0ed549f))
* **spec:** runtime nodes are never withdrawn; mark the VEX text decision open ([25c5e28](https://github.com/unified-systems-com/anchore-tap/commit/25c5e28ab01d92e04bccfd2a54f647b683acecf4))
* **spec:** scanner identity is the canonical API root; GET-only at the transport ([a8d7cef](https://github.com/unified-systems-com/anchore-tap/commit/a8d7cef490724c9fad79f13d4873d3aff8a7f4f2))
* **spec:** state rationale in requirement notes, not review or ruling history ([74b4de3](https://github.com/unified-systems-com/anchore-tap/commit/74b4de33c1de3d3dc840221f5ba28b6446087e72))
* **spec:** store Anchore's findings as Anchore-owned nodes, as returned ([62c5ab7](https://github.com/unified-systems-com/anchore-tap/commit/62c5ab7e257034267f4ac614ecc71e03d89c685c))
* **spec:** store Anchore's findings as Anchore-owned nodes, as returned ([a91e7c6](https://github.com/unified-systems-com/anchore-tap/commit/a91e7c65e32da18358226ee7da88203d66672da5))
* **spec:** strict base URL; withdrawn annotations stop asserting ([a5e29b2](https://github.com/unified-systems-com/anchore-tap/commit/a5e29b29cc18f375d9ff61bffe3e799f5681b9ca))
* **spec:** the Anchore credential kind, its data and one envelope per instance ([6025fa7](https://github.com/unified-systems-com/anchore-tap/commit/6025fa739a0739d9fe023bfad3946525e5126311))
* **spec:** the Anchore credential kind, its data and one envelope per instance ([eae5d21](https://github.com/unified-systems-com/anchore-tap/commit/eae5d216636ba6f9582aa1c68e3a145d81751c48))
* **spec:** the Anchore plugin specification, v0 ([e495196](https://github.com/unified-systems-com/anchore-tap/commit/e4951961c172409429bf0577a177bff53dcf9091))
* **spec:** the Anchore plugin specification, v0 ([4749350](https://github.com/unified-systems-com/anchore-tap/commit/4749350746de1642f39b6ecc87b3f81f21425304))
* **spec:** verify the effective account; do not store contact personal data ([b6f560d](https://github.com/unified-systems-com/anchore-tap/commit/b6f560d4cc2fbc44d05af1f982e24010eb33622a))
