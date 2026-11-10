# Changelog

## [0.1.4](https://github.com/unified-systems-com/anchore-tap/compare/v0.1.3...v0.1.4) (2026-11-10)


### Features

* **ecs:** join an Anchore ECS container to the aws_core container with its ARN ([6a0dafc](https://github.com/unified-systems-com/anchore-tap/commit/6a0dafc4d920ece53f520eb5ad794537fd9359ac))
* **ecs:** join an Anchore ECS container to the aws_core container with its ARN ([455355a](https://github.com/unified-systems-com/anchore-tap/commit/455355aa0223338ab2d8f6d5e3762ee1e9e92ab0))
* **ecs:** with create.ecs, create the aws_core ECS nodes the grid does not hold ([106fe97](https://github.com/unified-systems-com/anchore-tap/commit/106fe9767d3d53de5e87a7bd5bc9a038c0e2e34b))
* **ecs:** with create.ecs, create the aws_core ECS nodes the grid does not hold ([b229037](https://github.com/unified-systems-com/anchore-tap/commit/b229037a03f71077314ab26ae05e3693f016506e))
* **inventory:** the runtime image node, its edge, and scope fields on the scan run ([bc3aa9d](https://github.com/unified-systems-com/anchore-tap/commit/bc3aa9d262ebff502e2cfa2604116ca11faf6875))
* **kubernetes:** the placement plan, pure ([5c33bb3](https://github.com/unified-systems-com/anchore-tap/commit/5c33bb320e0b9ddd2cab0b5d3b6bd69331da9b04))
* **kubernetes:** write Anchore's Kubernetes inventory into computing_core's types ([9281cee](https://github.com/unified-systems-com/anchore-tap/commit/9281ceecbf32a2f4595d7835968c291923097390))
* **kubernetes:** write the Kubernetes objects Anchore reports into computing_core's types ([dbf8c52](https://github.com/unified-systems-com/anchore-tap/commit/dbf8c52135d1cc9fa921b4bb8a81425d35395288))
* **scope:** envelope settings and the pure scope selection ([d6e827e](https://github.com/unified-systems-com/anchore-tap/commit/d6e827e035969e28f4540c2e8b651b977e09ef34))
* **scope:** read only what the scope selects, and record what Anchore saw running ([89d7c47](https://github.com/unified-systems-com/anchore-tap/commit/89d7c47be5a62b64a81517af3b22a0f1fdf12c07))
* **scope:** repository_prefixes narrows what the runtime inventory writes ([0a6a5ca](https://github.com/unified-systems-com/anchore-tap/commit/0a6a5ca65ec035bad43b80dc90374203df6b5c10))
* **scope:** scope.running_only is required, with no default ([453f55d](https://github.com/unified-systems-com/anchore-tap/commit/453f55d57ebb2ea751c53b8e1ea1acc315d2f429))
* **scope:** the collector reads only what the scope selects, and records what it saw running ([a43531c](https://github.com/unified-systems-com/anchore-tap/commit/a43531c60823ee5466b2c1162336ff458574fee2))


### Bug Fixes

* **ecs:** a later scanner joins its nodes to ancestors an earlier scanner staged ([e80381f](https://github.com/unified-systems-com/anchore-tap/commit/e80381f5b4ad14adc21674fba9ee030dfa382874))
* **ecs:** a later scanner links its image to a container an earlier scanner staged ([452d24f](https://github.com/unified-systems-com/anchore-tap/commit/452d24f636c85b71e43dc9ad93345e5fa6b8f01c))
* **ecs:** an ECS ARN needs a real partition and region shape and a bounded length ([4b6cdd9](https://github.com/unified-systems-com/anchore-tap/commit/4b6cdd9a64264b82e66626c3e43a5c3e2ff2b590))
* **ecs:** reject malformed ARN paths and a task and service that disagree on the cluster ([dce89ac](https://github.com/unified-systems-com/anchore-tap/commit/dce89ac8dd23595b5a66d7b0cba4a8ad1a62930f))
* **kubernetes:** a kube-system uid keys a cluster only when the namespace list confirms it ([aa5c538](https://github.com/unified-systems-com/anchore-tap/commit/aa5c5385bd9d45c130b9b4d863dbc0bbfbb13bb7))
* **scope:** bound the freshness window on both sides; say the create settings write nothing yet ([ab8f5c0](https://github.com/unified-systems-com/anchore-tap/commit/ab8f5c07906216d01a331925a46b1347bc22f83f))
* **scope:** cap inventory_max_age_hours at one year ([aa3d26f](https://github.com/unified-systems-com/anchore-tap/commit/aa3d26ff32c5bb41a57fb9d4bc2b95a77828c438))


### Documentation

* **spec:** an unconfigured collector reads running images only ([69e21b5](https://github.com/unified-systems-com/anchore-tap/commit/69e21b5566214c645719f928216ab197b9176846))
* **spec:** borrowed freshness does not identify a container ([0fab149](https://github.com/unified-systems-com/anchore-tap/commit/0fab149d337c86e49a7407c79d06c2d753211a33))
* **spec:** collection scope from Anchore's inventory, and opt-in node creation ([94063a7](https://github.com/unified-systems-com/anchore-tap/commit/94063a71fb9d4cbe32f45cadd23fed6abab3b104))
* **spec:** collection scope from Anchore's inventory, and opt-in node creation ([c1ff99c](https://github.com/unified-systems-com/anchore-tap/commit/c1ff99c169f2b71881d9977784a8ffa2352d2a72))
* **spec:** make the EKS rule read the same everywhere ([225b4aa](https://github.com/unified-systems-com/anchore-tap/commit/225b4aa175fcc8c39bc5ffd75d1ccff1c849f65d))
* **spec:** no EKS link on a cluster name alone ([8c6b134](https://github.com/unified-systems-com/anchore-tap/commit/8c6b134242418f6d4b8ed823c536af973c143cc8))
* **spec:** region is the ARN's fourth field and account its fifth ([7c29b6f](https://github.com/unified-systems-com/anchore-tap/commit/7c29b6f3c1f31674ea930bf38788bdc3d798db58))
* **spec:** running_only must be stated; list create.ecs concerns by what an operator sees ([eb2e802](https://github.com/unified-systems-com/anchore-tap/commit/eb2e8026367619686814bc85e248a9fb0d889dc7))
* **spec:** runtime inventory shares nodes with provider collectors, provider first ([0e37dc9](https://github.com/unified-systems-com/anchore-tap/commit/0e37dc970abc70cccb0ccb4951e939d82d264d82))
* **spec:** scope the cluster-name fallback to the scanner; validate ECS ARNs before creating ([6384b81](https://github.com/unified-systems-com/anchore-tap/commit/6384b81c35cf088cd5aca307eb82ce9ad9bac205))
* **spec:** share runtime-inventory nodes with the provider collectors ([5bc59d3](https://github.com/unified-systems-com/anchore-tap/commit/5bc59d3ffb51f02ea24cd002f571322e144056de))
* **spec:** shared inventory nodes: provider first, Anchore alone later ([16b1ccc](https://github.com/unified-systems-com/anchore-tap/commit/16b1cccc253d975e3ed5ed4357dc72a8569cfb7d))
* **spec:** shared nodes: say tags are discarded, require the write race as a test ([313cc9c](https://github.com/unified-systems-com/anchore-tap/commit/313cc9c918c409108f7638ae4983df8957a50dc5))
* **spec:** state the create race in the criteria; limit ECS creation to selected containers' ancestors ([1ca6fb9](https://github.com/unified-systems-com/anchore-tap/commit/1ca6fb91b2a20847ad8c19ef1ad787af8f507d2a))
* the ECS link is built ([dcc6243](https://github.com/unified-systems-com/anchore-tap/commit/dcc6243a548ff6330da620fa3881aa9b44ca0c30))
* the Kubernetes requirement as built ([3e54863](https://github.com/unified-systems-com/anchore-tap/commit/3e54863d30e91ef59f5fdd23f781191a92e50a53))
* the scope requirement is in development; README says how to choose what a run reads ([ca54331](https://github.com/unified-systems-com/anchore-tap/commit/ca54331839f5a01fc00ad55d57cbba864005ebc3))

## [0.1.3](https://github.com/unified-systems-com/anchore-tap/compare/v0.1.2...v0.1.3) (2026-11-03)


### Features

* **connection:** the base URL's scheme is the operator's, http or https ([837ce4e](https://github.com/unified-systems-com/anchore-tap/commit/837ce4e261c3c7805f34bc0f03f4d47085b30f6f))
* **connection:** the base URL's scheme is the operator's, http or https ([af7c23e](https://github.com/unified-systems-com/anchore-tap/commit/af7c23ec86c07c36e0e5598fb0e9cd7a338b905e))


### Documentation

* say what v0.1.2 does and how to try the collector ([9316927](https://github.com/unified-systems-com/anchore-tap/commit/9316927f44f6d9a17bf17c584358f276e99fbe93))
* say what v0.1.2 does and how to try the collector ([5862eb6](https://github.com/unified-systems-com/anchore-tap/commit/5862eb611c7ff9f5e085a033b3e11d5cf7a8287b))
* say which of the owned nodes exist yet ([fbe30e6](https://github.com/unified-systems-com/anchore-tap/commit/fbe30e6cb9d7057eb6f4f99459004a07ad4a31fd))

## [0.1.2](https://github.com/unified-systems-com/anchore-tap/compare/v0.1.1...v0.1.2) (2026-11-03)


### Features

* **collector:** fetch the instance's description, apply the previous-run rule, and validate responses ([63066e7](https://github.com/unified-systems-com/anchore-tap/commit/63066e769d20f17a313dc2b05661d63f18ddc917))
* **collector:** fetch the instance's description, apply the previous-run rule, and validate responses [spec-derived, unverified] ([97416cf](https://github.com/unified-systems-com/anchore-tap/commit/97416cfbd5dd004628f9ec612908e36ee290aeed))
* **collector:** image host and vulnerability links; SBOM documents ([5576d06](https://github.com/unified-systems-com/anchore-tap/commit/5576d069c6d6fb50821943c24a6a778645dbc0ba))
* **collector:** link findings to the image host and shared vulnerability; record the three SBOM formats ([4db390a](https://github.com/unified-systems-com/anchore-tap/commit/4db390a19f546f19e6b64142728214c5f7903b61))
* **collector:** the Anchore collector class ([c8d1d45](https://github.com/unified-systems-com/anchore-tap/commit/c8d1d45a7fcb21087d2609f24db41788deef761b))
* **collector:** the Anchore collector class — probe, self-test, image walk, one GRIFT batch ([82913e9](https://github.com/unified-systems-com/anchore-tap/commit/82913e9b1321981dc79348beeca4310e68ad253e))
* **findings:** edge from a finding to the SBOM document it was read from ([0fd60c2](https://github.com/unified-systems-com/anchore-tap/commit/0fd60c2b9a2eb09398c1c76d53c1f1f2a20dcb35))
* **findings:** the source finding's edge to the SBOM document it was read from ([624fc55](https://github.com/unified-systems-com/anchore-tap/commit/624fc555d18dde11051029a7ffff39369df96258))


### Bug Fixes

* **collector:** a repeated digest keeps its analyzed entry ([dc3323c](https://github.com/unified-systems-com/anchore-tap/commit/dc3323cb2e74e36e285ed8e76cea4a32139bafe3))
* **collector:** a required source that cannot be read, or answers in the wrong shape, stops the scanner ([8a408cd](https://github.com/unified-systems-com/anchore-tap/commit/8a408cd208b0327f01bdb8db595093aebd72c9f0))
* **collector:** list an image that left the image list in scopes_not_read; test the self-test error path ([36418ef](https://github.com/unified-systems-com/anchore-tap/commit/36418ef93d26e4ae4e49d10a39b195439f0b71aa))
* **collector:** never store a finding under a nulled identity; list unreadable image-list entries ([ed10b90](https://github.com/unified-systems-com/anchore-tap/commit/ed10b9081778fce1ecacb0712aad88bf23064028))
* **collector:** read a repeated image digest once; prove a hostile digest cannot leave its path ([6bed2ff](https://github.com/unified-systems-com/anchore-tap/commit/6bed2ff614c2af4d50b30eba70232dd92ab51a64))
* **collector:** read the image documents independently of the vulnerability read; refuse non-standard JSON constants ([05a017a](https://github.com/unified-systems-com/anchore-tap/commit/05a017a7cc0ab754a5535eb78afcf46c3a3a2463))
* **collector:** stage a shared host or document once per batch, never rewrite a document the grid holds, list a body too deeply nested ([6c6f67f](https://github.com/unified-systems-com/anchore-tap/commit/6c6f67f801422704ae7d1b20c7f6090258b36c2b))

## [0.1.1](https://github.com/unified-systems-com/anchore-tap/compare/v0.1.0...v0.1.1) (2026-11-03)


### Features

* **collector:** the collector manifest and the per-run self-test comparison ([a24140d](https://github.com/unified-systems-com/anchore-tap/commit/a24140d37d8abff8b2457d70f828b6294cd962f8))
* **collector:** the collector manifest and the per-run self-test comparison [spec-derived, unverified] ([cdd4dfa](https://github.com/unified-systems-com/anchore-tap/commit/cdd4dfae7358481689a60b54a459c32489dddcab))
* **collector:** the probe, with the account checked before anything else is read ([ef48ec6](https://github.com/unified-systems-com/anchore-tap/commit/ef48ec6b442d678008fde2c1eb6a437af97537e4))
* **collector:** the probe, with the account checked before anything else is read [spec-derived, unverified] ([9c4cc25](https://github.com/unified-systems-com/anchore-tap/commit/9c4cc25b59c80aa6a10f54d4b4929a9fda4feabb))
* **findings:** the finding's edge to the shared vulnerability, with no change to compliance_core ([0b8d819](https://github.com/unified-systems-com/anchore-tap/commit/0b8d8192e4adfb664d017503e4942cffe23f2b0f))
* **findings:** the finding's edge to the shared vulnerability, with no change to compliance_core [spec-derived, unverified] ([a404fbb](https://github.com/unified-systems-com/anchore-tap/commit/a404fbb9ec90bb5661bcc287ed483902bc6b423e))
* **findings:** the scanner, scan-run and finding nodes, and three edges ([75b858b](https://github.com/unified-systems-com/anchore-tap/commit/75b858b91e9b538d1689cb1684324e739c6f0d9f))
* **findings:** the scanner, scan-run and finding nodes, and three edges [spec-derived, unverified] ([a83fa27](https://github.com/unified-systems-com/anchore-tap/commit/a83fa2773dd66e628af661b6f883bdc0593c654c))


### Bug Fixes

* **collector:** a needed field that stops being required by its object is a difference ([51d7a90](https://github.com/unified-systems-com/anchore-tap/commit/51d7a90afd97c69aaed16ba00b3e07589b4dc7dc))
* **collector:** a new success response with no described body is a loss ([f115a00](https://github.com/unified-systems-com/anchore-tap/commit/f115a00410e769f524465a85dc0ce90b551431b8))
* **collector:** compare the containers on the way to a field, and every successful response ([4094814](https://github.com/unified-systems-com/anchore-tap/commit/409481416cec05dec2e292eab718b3707c1ea5d1))
* **collector:** enforce the account gate inside the probe, not in the list it is given ([69fe5ba](https://github.com/unified-systems-com/anchore-tap/commit/69fe5ba926fc75484a0ae865dd054a9dae112ef2))
* **collector:** hold needed fields to every success response, and keep every allOf definition ([d5842c7](https://github.com/unified-systems-com/anchore-tap/commit/d5842c72a3ecdb3ade13dc5442d53fdc4e159ca0))
* **collector:** read requiredness along the whole path, and ignore allOf member order ([8c97f02](https://github.com/unified-systems-com/anchore-tap/commit/8c97f02f0fee98cf2a3ac9cca42d5f7de039dda5))
* **collector:** the account source must read /account, and the tests carry no review history ([8423320](https://github.com/unified-systems-com/anchore-tap/commit/8423320ed2955403a3292931509d3524273538b1))
* **collector:** warn when a field the collector reads loses its enum ([5fd8bd9](https://github.com/unified-systems-com/anchore-tap/commit/5fd8bd936935bbed637d016b3ee33c7e6129fe1a))
* **findings:** derive package_key as a digest of its two columns, and keep review talk out of the code ([b64e151](https://github.com/unified-systems-com/anchore-tap/commit/b64e1517f2d4b847f3bb99d665de0f3c613331a4))
* **findings:** refuse a scanner key that disagrees with its columns, and size package_key to its parts ([fae4f43](https://github.com/unified-systems-com/anchore-tap/commit/fae4f43c312f48e9d6cfd3ef515be5a8b3fbbf0c))


### Documentation

* **edge:** say what the edge definition permits and who owns the exact-identifier rule ([4bf37b7](https://github.com/unified-systems-com/anchore-tap/commit/4bf37b78d8ed9ff583741b47e456eeb7ad22845e))
* **spec:** ABOUT_VULNERABILITY is defined and needs no compliance_core change ([fe29790](https://github.com/unified-systems-com/anchore-tap/commit/fe29790cf5322ad28af868d53ed9fc296146a113))

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
