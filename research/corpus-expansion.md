# Corpus Expansion — every additional detection corpus RepoGate can legally vendor or consume

**Date:** 2026-11-20 · **Method:** licenses read from the source repos themselves
(GitHub API `license` field + raw LICENSE files + the Semgrep Rules License page
read in full), sizes/counts from live repo trees and bucket headers on
2026-11-20. Scope note: Sigil core packs, GuardDog YARA + top-packages, and
SkillSpector fixtures are already covered in `code-merge-feasibility.md` and
are excluded here. Weighting is for a **pre-clone repo/skill scanner**: a
corpus earns its rank by catching malicious *source trees, manifests, hooks
and agent instructions* before anything runs — binary-malware corpora are
discounted accordingly, however good they are at their own job.

**Freshness flags** are marked ⚠ where a source falls outside the ~2-month
window. Rule/intel corpora age slower than tools, but a dead feed is a dead
feed: update mechanism is scored as part of value.

---

## Ranked vendor / consume list (value per integration-day)

### 1. OSV MAL- — OpenSSF Malicious Packages · **CONSUME (distilled snapshot)**
- **License (verified):** Apache-2.0 — `ossf/malicious-packages` repo LICENSE
  + OSV data-sources page lists "OpenSSF Malicious Packages (Apache 2.0)".
- **Size / format:** **239,225 active MAL- reports** as of 2026-11-02 (~93%
  npm), each an OSV-schema JSON record
  (`osv/malicious/<ecosystem>/<package>/MAL-*.json` in the source repo,
  ~348 MB repo). Ecosystems: npm, PyPI, crates.io, Go, Maven, NuGet,
  Packagist, RubyGems, VS Code / Open VSX.
- **Update mechanism:** continuous ingestion — repo pushed 2026-11-20 (same
  day as this audit); OSV.dev re-exports to `gs://osv-vulnerabilities`
  (per-ecosystem `all.zip` regenerated continuously — npm `all.zip` is
  222 MB because it carries *all* npm vulns; PyPI 38 MB), with per-ecosystem
  `modified_id.csv` for incremental sync. OSV's stated SLO: sources ≤15 min
  stale, 99.5% of the time.
- **Conversion cost:** ~0.5 day. MAL records need no rule conversion at all:
  parse → `{ecosystem, name, affected versions | all}` → compact name index
  (est. single-digit MB distilled). Same OSV parser later serves #6.
- **Pre-clone value: HIGHEST of anything in this document.** It is the only
  corpus that answers "is this exact dependency name+version *known
  malicious*" with near-zero false positives, at manifest stage, before
  clone completes. This is the synthesis doc's step-5 item; this audit
  confirms the mechanics are as cheap as hoped.
- **Caveats (carry into the design):** keep record provenance + the
  `withdrawn` field live in the snapshot — OSV has withdrawn bad automated
  records before (157 in May 2026, incl. a FastAPI false flag), so a MAL hit
  must cite its record ID and a withdrawn record must stop firing. Registries
  often act before OSV does (median harmful-npm lifetime ~35 days), so MAL-
  is a floor, not a ceiling.

### 2. DataDog malicious-software-packages-dataset — manifests · **VENDOR manifests; samples EVAL-LAB ONLY**
- **License (verified):** Apache-2.0 (repo LICENSE + README "released under
  the Apache-2.0 license… with attribution"). Caveat in README: individual
  samples may contain third-party code under its own license.
- **Size / format:** **29,847 malicious packages** (README counter, Nov
  2026), ecosystems npm / PyPI / IDE extensions / **AI Skills** (directly
  RepoGate-shaped). Two layers: (a) per-ecosystem `manifest.json` —
  name → `null` (all versions malicious-intent) or version list
  (compromised versions); (b) `samples/` — the actual packages as
  password-encrypted ZIPs (`infected`). The full repo is sample-heavy and
  impractically large to clone whole; consume the manifests (small) +
  selective samples by path.
- **Update:** Datadog research pipeline (GuardDog detections feed it);
  repo pushed 2026-11-06.
- **Conversion cost:** ~0.25 day for manifests (the name/version semantics
  map 1:1 onto the MAL- index from #1 — merge both into one blocklist with
  per-record source tags); samples are a download-and-unzip harness job for
  the eval corpus, ~0.5 day, **outside** the shipped repo.
- **Pre-clone value: HIGH.** A second, independent known-malicious index
  (Datadog's curation ≠ OpenSSF's ingestion — overlap is partial), plus the
  single best *real-world* eval corpus available anywhere: live-fire
  packages, labeled by ecosystem and intent, including an AI-skills slice
  no other dataset has. Recall numbers measured against this are numbers
  the maintainer can publish.
- **Hard rule:** the samples are actively malicious software. They never
  enter the RepoGate repo, a release artifact, or a CI checkout that runs
  anything. Eval-lab storage only, extracted only inside the harness's
  quarantine path (RepoGate never executes scanned code — the samples are
  scan *targets*, which is exactly the scanner's safe case).

### 3. bartblaze/Yara-rules · **VENDOR**
- **License (verified):** MIT (GitHub API + repo LICENSE).
- **Size / format:** 110 `.yar`/`.yara` files (~337 KB repo) — malware-family,
  webshell, hacktool and technique rules, plain text patterns.
- **Update:** ⚠ last push 2026-01-28 — outside the freshness window; the set
  is curated and slow-moving, but treat it as a pinned snapshot, not a feed.
- **Conversion cost:** ~0.5–1 day *marginal* once the GuardDog YARA→RRF
  transpiler exists (same string-extraction path); rules using hex/offset
  conditions get rejected-and-logged per the synthesis converter rule.
- **Pre-clone value: MEDIUM-LOW, real.** Family malware strings rarely fire
  on source trees; the webshell/technique subset does fire on shipped
  droppers and backdoors in repos. Cheap because the converter already
  exists by the time this lands.

### 4. YARAify / YARAhub (abuse.ch) · **CONSUME with per-rule license filter**
- **License (verified):** two layers. (a) abuse.ch Terms of Use (eff.
  2025-11-04, updated 2026-10-21) §3.4: **YARAify data is free for commercial
  and non-commercial use under CC0 principles**. (b) Individual YARAhub
  rules carry a mandatory per-rule `yarahub_license` meta field (CC0 1.0,
  CC BY 4.0, CC BY-SA 4.0, CC BY-ND, CC BY-NC…) — the platform is *not*
  uniformly CC0. **Filter: ingest only rules whose meta says CC0 or CC BY
  4.0; skip SA/ND/NC rules** (share-alike/no-derivatives/no-commercial all
  conflict with conversion into RRF packs).
- **Size / format:** 23K+ YARA rules deployed on the platform; access via
  API (free auth key) / rule-pack downloads, not a single git repo.
- **Update:** continuous, community-fed — the freshest YARA source in this
  list.
- **Conversion cost:** 2–3 days (API harvest + license filtering + the YARA
  transpiler + FP triage).
- **Pre-clone value: MEDIUM, with a scope warning.** Most YARAhub rules
  target PE/ELF binaries. Unscoped, they'd be dead weight and FP surface on
  source trees. Scoped to RepoGate's shipped-binary/bytecode surface
  (files with no source, `.pyc`/`.class`/`.wasm`, bundled blobs), they cover
  the one place string rules are the *right* tool. Land after #3 proves the
  pipeline.

### 5. MITRE ATT&CK® STIX data (mitre/cti) · **VENDOR the taxonomy slice**
- **License (verified from `LICENSE.txt` in the repo):** MITRE grants a
  non-exclusive, royalty-free license to use ATT&CK "for research,
  development, and commercial purposes," provided MITRE's copyright
  designation and the license are reproduced in copies. ATT&CK® is a
  registered trademark — use the name descriptively, never as RepoGate
  branding. (The same LICENSE file carries the CAPEC™ section on identical
  terms.)
- **Size / format:** STIX 2.x JSON bundles (Enterprise/Mobile/ICS);
  repo ~390 MB with history, the current Enterprise bundle is a single
  multi-MB JSON.
- **Update:** ATT&CK releases ~twice yearly (repo pushed 2026-11-05).
- **Conversion cost:** ~0.5 day — extract technique ID → name/URL table only.
- **Pre-clone value: LOW as detection, REAL as reporting.** ATT&CK contains
  zero detection content. Its value is that RepoGate's chains already speak
  MITRE (GuardDog meta carries `mitre_tactics`); vendoring the canonical
  technique table makes every report's ATT&CK references resolvable,
  correctly named, and offline. Buy it once, cheap, never think again.
- **CAPEC** (same terms, capec.mitre.org XML/STIX): attack-*pattern*
  taxonomy, even further from detection. Skip unless a report feature wants
  CAPEC IDs; the license would allow it.

### 6. GitHub Advisory Database · **OPTIONAL consume — only the malware slice**
- **License (verified):** CC-BY-4.0 (GitHub API + repo LICENSE) — attribution
  required, otherwise permissive for data.
- **Size / format:** repo ~3.5 GB, OSV-format JSON, one file per advisory;
  continuously updated (pushed 2026-11-20). Includes GHSA "malware"-type
  advisories, but the overwhelming mass is CVE vulnerability data.
- **Conversion cost:** parser is free (same OSV code as #1), but 2–3 days
  total once size handling, malware-vs-vuln filtering, and attribution
  plumbing are counted.
- **Pre-clone value: MEDIUM-LOW for this product.** The malware slice is
  largely upstream of / duplicated by OSV MAL- (#1). The rest answers
  "known-*vulnerable* dependency," which is a different product question
  (vuln scanning) than RepoGate's "is this artifact malicious." Take it
  only if the maintainer decides manifest-stage vuln flags are in scope; if so,
  consume the same per-ecosystem OSV bucket export filtered to GHSA
  malware advisories, not the 3.5 GB git repo.

### 7. capa rules (Mandiant FLARE) · **DEFER**
- **License (verified):** Apache-2.0 (repo LICENSE + API) — legally clean.
- **Size / format:** ~1,059 `.yml` files (rules + tests) on `master`,
  pushed 2026-11-06 — fresh and actively maintained. Rules express
  *capabilities* (namespaces like `collection/file-managers`) over capa
  features: disassembly-derived API/string/number features for PE/ELF/.NET
  binaries.
- **Conversion cost:** HIGH for low yield — capa features are not regexes.
  Only the pure-string-feature subset converts, est. 3–5 days for partial
  coverage, and the result duplicates what #3/#4 give cheaper.
- **Pre-clone value: LOW.** capa answers "what can this *binary* do."
  RepoGate's targets are source trees and skills; when a repo ships a
  binary, string rules (#3/#4) plus the bytecode treatment already cover
  the realistic case. Revisit only if RepoGate grows a dedicated
  shipped-binary stage. (capa's *namespace taxonomy* is a free idea —
  capability names as chain labels — no code or rules needed.)

### 8. InQuest yara-rules (+ yara-rules-vt) · **VENDOR opportunistically**
- **License (verified):** MIT (both repos).
- **Size / format:** ~40 `.rule` files in the main repo (malware, exploit-doc
  and technique rules); the `-vt` companion is small (36 KB).
- **Update:** ⚠⚠ stale — main repo last pushed **2022-05-11**, `-vt`
  2024-04-04. Treat as an archaeological snapshot.
- **Conversion cost:** ~0.25 day marginal on the YARA transpiler.
- **Pre-clone value: LOW.** A few document-exploit rules are repo-relevant;
  the rest duplicates #3. Fold in only when someone is already running the
  transpiler batch.

### 9. Didier Stevens YARA rules · **VENDOR opportunistically**
- **License (verified):** no repo-level LICENSE in `DidierStevensSuite`
  (GitHub API: none) — **but** the files carry an explicit per-file
  dedication, read verbatim from raw sources: *"Source code put in public
  domain by Didier Stevens, no Copyright."* That is a usable public-domain
  dedication for the files that carry it; vendor **only files whose header
  carries the dedication**, and record the header as the license evidence
  in SOURCES.md.
- **Size / format:** a handful of rules (`maldoc.yara` shellcode-in-docs,
  PE-file detectors), distributed inside the suite / as a rules zip.
- **Update:** suite is active (pushed 2026-10-13); the YARA subset is old
  and stable.
- **Conversion cost:** ~0.25 day.
- **Pre-clone value: LOW** — malicious-Office-document detection matters
  only for repos shipping droppers/docs; tiny, clean, harmless to include.

### 10. Backstabber's Knife Collection · **METADATA ONLY, eval seed**
- **License / access (verified):** the *paper* (DIMVA 2020) and the public
  dataset site (dasfreak.github.io/Backstabbers-Knife-Collection) expose the
  index — package names, versions, ecosystems, attack categorization for
  174 obtained packages (469 identified). The **sample collection itself is
  gated**: access by email request from an institutional address, for
  verified research; no public license grant. Samples date 2015–2019 —
  ⚠ stale as detection content.
- **Conversion cost:** ~0.25 day to fold the public name/version index into
  the eval seed list.
- **Pre-clone value: LOW as data, MODEST as eval.** 174 hand-analyzed,
  attack-tree-categorized real cases are a good *qualitative* recall seed
  (do the chains name the right attack?), useless as a feed. **Do not
  request or hold the gated samples** — #2 supersedes them with 29,847
  openly licensed ones.

### 11. Typosquat reference data beyond GuardDog · **GENERATE, don't vendor**
No additional clean corpus exists:
- npm and PyPI do **not** publish their typosquat blocklists.
- `hugovk/top-pypi-packages` (monthly top-PyPI JSON) carries **no license**
  in the repo (GitHub API: none) → all-rights-reserved by default → do not
  vendor its data files.
- The NSS 2024 typosquatting dataset (Zenodo; 406 npm typosquat packages
  *with source*) is sample data — eval-lab material in the same class as
  #2's samples, not a name list.
- **Recommended route:** GuardDog's top-packages lists (already in the
  merge plan) are the vendored base. If RepoGate later needs bigger
  reference lists, *generate* top-N lists from the registries' own
  download-count APIs under their terms — first-party-derived data with no
  third-party license attached. Zero legal risk, ~0.5 day when wanted.

---

## DO NOT TOUCH list (with the exact reason)

| Corpus | Reason |
|---|---|
| **Semgrep community rules** (`semgrep/semgrep-rules`, ~2,194 YAML rule files) | **Semgrep Rules License v1.0** (read in full at semgrep.dev/legal/rules-license, 2026-11-20): use "only for your own internal business purposes"; "**does not allow you to distribute the rules, or to make them available to others as a service**"; non-sublicensable, non-transferable. GitHub reports the repo license as NOASSERTION for this reason. Vendoring any rule into a shipped RepoGate — converted or verbatim — is unlicensed use. Clean-room only: RepoGate may hold the same *knowledge*, never their rule text/YAML. This is also why "GuardDog uses Semgrep" being stale (GuardDog v3 dropped it) matters. |
| **ClamAV signature databases** (main/daily/bytecode CVD) | The ClamAV *engine* is GPL-2.0, but the **signature databases are Cisco/Talos content, not covered by the GPL and not licensed for redistribution** — distributors explicitly fetch them from Cisco under Cisco's terms rather than bundling them. Separately useless here anyway: hash/byte-pattern signatures for binaries say nothing about a source tree. (A user running ClamAV themselves fetches CVDs under Cisco's terms; RepoGate must not ship or mirror them.) |
| **Socket (socket.dev) rules / data** | **There is no public corpus.** Socket's engine and its 70+ detection signals are proprietary SaaS; `SocketDev/socket-cli` is MIT but is only an API client containing no rules. Package scores/findings are served under Socket's terms with no redistribution grant. Nothing to vendor; scraping is unlicensed republication. |
| **DataDog dataset — the samples, in the shipped repo** | Legal (Apache-2.0) but a hard safety/distribution line: 29,847 actively malicious packages do not ship inside a security tool's repo or releases. Eval-lab only (see #2). |
| **Backstabber's Knife — the samples** | Gated access, no license grant, real malware, 2015–2019 vintage. Metadata only (see #10). |
| **hugovk/top-pypi-packages data** | No license in repo → all rights reserved by default. Generate equivalent data instead (see #11). |
| **YARAhub rules with SA / ND / NC meta** | Per-rule Creative Commons variants inside YARAify: CC BY-SA (share-alike infects the pack), CC BY-ND (no derivatives — conversion *is* a derivative), CC BY-NC (no commercial). Filter at ingest; CC0/CC BY only (see #4). |
| *(cross-ref)* **YARA-Forge full/extended, Neo23x0/signature-base, Sigil LOLBin pack, ScanRepo scam DB** | Already ruled in `SYNTHESIS-v2.md` / `code-merge-feasibility.md`: Elastic License 2.0 mixing, DRL-1.1 output-attribution, GPL-3.0, and no-license-grant respectively. Unchanged. |

---

## Bottom line for the build sequence

The corpus story after this audit: **two name-index feeds (#1 + #2
manifests) do more pre-clone work than every rule corpus combined** — they
are also the two cheapest integrations on the list (~0.75 day together).
Everything else is either taxonomy polish (#5), scoped binary-surface depth
(#3, #4, #8, #9 — all riding one YARA transpiler), or a deliberate no
(#6, #7 deferred; Semgrep/ClamAV/Socket closed). Total new legal surface:
Apache-2.0 ×3, MIT ×2, CC0/CC-BY-filtered ×1, MITRE terms ×1, CC-BY-4.0
optional ×1 — all compatible with the `third_party/` + `SOURCES.md` layout
from the merge-feasibility audit, and none of it adds a copyleft or
no-distribution obligation to the shipped product.
