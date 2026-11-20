# YARA Merge-Path Research — Is YARA the Vehicle for Merging the Field into RepoGate?

**Date:** 2026-11-20 (all live checks performed this date)
**Method:** Repo trees and raw rule files read directly from GitHub; license texts read in full; YARA-X status from VirusTotal docs, GitHub releases, lib.rs, and third-party trackers. Nothing installed or run.
**Freshness rule applied:** Claims anchored to sources from the past ~2 months where possible; older material flagged.

**Short answer:** YARA is a real merge vehicle for exactly one layer — byte-pattern matching over files, especially binaries and known-malware corpora. It is not, and cannot be, the whole engine: both tools that "use YARA" actually keep their correlation, scoping, structural, and metadata logic *outside* YARA in Python. The right move for RepoGate is a layered design: adopt **yara-x as the pattern/binary layer in a Rust build**, keep RepoGate's semantic core (structural checks, risk chains, prompt-injection normalization, metadata) as native code, and treat community corpora as pinned external packs — because the biggest corpora carry license terms (DRL 1.1, Elastic License 2.0) that reach into your product if you bundle them naively. Details and evidence below.

---

## 1. What SkillSpector and GuardDog actually ship as YARA

### 1.1 NVIDIA SkillSpector — a small, mostly source-text corpus (and a license split inside it)

**Location:** `src/skillspector/yara_rules/` on `main` (tree read 2026-11-20, HEAD `48e0f94`).
**Engine:** classic YARA via `yara-python` (listed in the repo's THIRD_PARTY_NOTICES.md, read 2026-11-20). Not yara-x.
**Scale:** YARA is 1 of SkillSpector's 17 detection categories (4 pattern IDs in the README catalog). The corpus is **5 files, ~20 rules visible + one encoded file**:

| File | Rules | Targets | License position |
|---|---|---|---|
| `agent_skills.yar` (7,296 B) | 5: credential-exfil-via-webhook, remote bootstrap execution, prompt-injection hidden instructions, MCP tool-poisoning metadata, destructive autonomous actions | Agent-skill abuse in **source code and manifests** — regexes over Python/JS/shell text, webhook domains (Discord/Telegram/Slack), hidden-instruction phrases, zero-width/RLO byte sequences | **Clean.** In-file header: `SPDX-License-Identifier: Apache-2.0`, © 2026 NVIDIA |
| `webshells.yar` (4,649 B) | 6: PHP generic / obfuscated / known families (c99, r57, WSO, Behinder…), Python, JSP, ASPX webshells | Webshell strings and `eval($_POST[…])`-shaped regexes in source files | **DRL-tainted.** Header: *"Based on patterns from Neo23x0/signature-base (DRL-1.1) and community research."* No SPDX header |
| `cryptominers.yar` (3,646 B) | 4: stratum protocol, mining pools, miner software, browser coinjacking | Pool domains, `stratum+tcp://`, xmrig/CoinHive strings | **DRL-tainted** (same derivation note) |
| `hacktools.yar` (3,959 B) | 5: offensive tools, network recon, privesc tools, exploit frameworks, phishing kits | nmap/sqlmap/hydra/linpeas/msfvenom-shaped regexes | **DRL-tainted** (same derivation note) |
| `malware.yar.b64` (12,649 B) | Unknown — est. ~10–15 rules at the sibling files' density (~9.5 KB decoded) | Generic malware signatures, presumably | **Unverifiable as shipped.** Base64-encoded in the repo (decoded at load, plausibly so the repo itself doesn't trip scanners); provenance is **not** stated in THIRD_PARTY_NOTICES.md, which lists only Python dependencies. Given all three readable siblings are signature-base-derived, treat as DRL-suspect until decoded and header-checked |

Two structural observations:

- **These are source-text rules, not binary rules.** No `pe`/`elf`/module usage anywhere in the readable files — just text strings, regexes, and hex byte sequences. They would run against a skill's `.py`/`.js` files, not against executables.
- **YARA *can* express single-file correlation.** `agent_skill_credential_exfiltration_webhook` fires only on `any of ($secret_*) and any of ($send_*) and any of ($collector_*)` in one buffer. The limit is the single-buffer boundary (see §4), not boolean expressiveness.

### 1.2 DataDog GuardDog — ~55 rules, and the rules are only half the product

**Location:** `guarddog/analyzer/sourcecode/` on branch `v3` (tree read 2026-11-20, HEAD `5da9538`).
**Engine:** classic YARA via **yara-python** — Datadog's 3.0 release article (2026-06-26) states it verbatim: *"we moved away from Semgrep and migrated our rules to YARA, which we run with yara-python."* Even a sophisticated team shipping in mid-2026 chose classic YARA, not yara-x.
**Scale:** **55 `.yar` files ≈ 55 rules** (one rule per file, spot-verified), plus 4 `.meta` data files (`hooks.meta`, `lolbas-net.meta`, `lolbas-proc.meta`, `lolbas-sysinfo.meta`) that feed string lists into rules:

- **11 `capability-*.yar`** — browser credential access, filesystem delete/read/write-executable, network download / LOLBAS / outbound, process hooks/schedule/spawn, clipboard.
- **44 `threat-*.yar`** — filesystem (autostart, destruction, sensitive read), network (DNS exfil, messenger exfil, sysinfo exfil, generic exfil, shady links, reverse shell), npm (dependency confusion, HTTP dependency, preinstall script), process (cryptomining, download-exec, hooks, DLL injection, memory scraping, encoded PowerShell, silent spawn, sysinfo), runtime (21, including a 13-rule obfuscation family: base64-exec, `chr()`-exec, dynamic eval, JS `_0x` mangling, PyArmor, steganography, unicode homoglyphs, hidden code, log suppression…), setup.py (3).

**The critical detail is the meta schema.** A sampled rule (`capability-filesystem-browser.yar`, read in full 2026-11-20) carries meta the YARA engine itself ignores:

```
author = "GuardDog Team, Datadog"
identifies = "capability.filesystem.browser"
severity / specificity / sophistication = ...
max_hits = 1
path_include = "*.py,*.pyx,*.pyi,*.pth,*.js,*.ts,..."
```

`path_include` (which files a rule applies to), the capability/threat typing, and the scoring inputs are consumed by GuardDog's **Python harness** — correlation and risk scoring live in `guarddog/analyzer/risk_engine.py` (~20 KB of Python), and all 11 metadata detectors (typosquatting, new-install-script, provenance regression, integrity mismatch…) are Python, not YARA. **GuardDog is the proof of this report's thesis: YARA is its pattern layer; the product is the machinery around it.**

**License:** Repo-wide Apache-2.0; sampled rules are Datadog-authored with no third-party rule attribution (LICENSE-3rdparty.csv covers Python dependencies only). This is the cleanest vendoring candidate in the field — with the caveat that vendoring the `.yar` files without the meta conventions discards the scoping and correlation semantics that make them precise.

---

## 2. yara-x status, November 2026

| Fact | Evidence |
|---|---|
| **Latest release: v1.23.0, published 2026-11-05** (flagged by SANS ISC 2026-11-15); v1.22.1 late Oct 2026; 45 releases / 28 stable on lib.rs; repo last commit 2026-11-19 | GitHub releases page + lib.rs + awesome-rea tracker, all read 2026-11-20 |
| **1.0.0 stable shipped June 2025**; project self-describes as "already mature and stable" | andreafortuna.org threat-hunting guide (2026-04-22); yara-x README via lib.rs |
| **License: BSD-3-Clause** — clean for bundling | GitHub repo page |
| **Production:** VirusTotal runs YARA-X in production for **Livehunt and Retrohunt**, "scanning billions of files with tens of thousands of rules" (VT's own words). It is the flagship — and honestly the only clearly documented at-scale production user; adoption signals beyond VT are bindings (Rust crate, PyPI `yara_x`, Go, C API, WASM), a language server, and third-party rule libraries now tracking per-rule yara-x compile status | VT docs/README; yararules.org YARA-X guide (updated 2026-11-17) |
| **Classic YARA is in maintenance mode** (v4.6.0, 2026-10-27 — bug fixes/hardening only); all new feature work is YARA-X-only | Heimdal 2026 roundup (versions verified against official release pages as of 2026-11-09); VT statements |

### Compatibility with classic YARA — the `pe` question is settled, with fine print

The assumption that YARA-X lacks the `pe` module is **outdated**. As of the 1.23 release cycle, YARA-X ships modules: **`pe`, `elf`, `macho`, `dotnet`, `lnk`, `dex`, `crx`, `hash`, `math`, `string`, `time`, `console`, `cuckoo`, `vt`, `zip`**, plus experimental `msi`/`vba`/`olecf`. The `pe` module is actively extended (e.g. `pe.offset_to_rva` added in the latest release notes). The one real gap: **`magic`** requires a libmagic-enabled build and is absent from the WASM build and default PyPI wheels.

Parity caveats that matter for porting corpora:

- **Field-level parity is not 100%.** Some module fields were renamed/reorganised vs YARA 4.x, and YARA-X treats an unknown field as a **compile error** where classic YARA silently evaluated to undefined. Rules using renamed fields fail loudly (good for hygiene, but they fail).
- **Stricter language overall:** duplicate modifiers are errors, invalid escapes are errors, negative array indexing (`$a[-1]`) is unsupported, XOR/`fullword` interaction order changed, base64 matching semantics refined.
- **Empirical port rate is high:** yararules.org, which tracks thousands of community rules, reports "the vast majority compile with YARA-X 1.20 without any change," and its scanner packs include only rules that compile.
- **Not a drop-in at the API level:** the C/Python/Go APIs are new (`import yara_x`; Compiler/Scanner model). Code written against `yara-python` must be ported even when the rules don't change.
- **No process (memory) scanning** — irrelevant for RepoGate's pre-clone file scanning, noted for completeness.

### Performance claims

Vendor-sourced but specific: VT's own comparison docs state YARA-X is "faster than YARA in almost all cases," with the dramatic wins on pathological patterns — a complex hex/regex rule that takes **>20 s on a 200 MB file in YARA runs in <1 s in YARA-X**; a cited example rule runs **5–6× faster**; third-party summaries put the problematic-rule improvement at 5–10×. Mechanisms visible in recent release notes: SIMD-accelerated masked-literal matching, Aho-Corasick automata serialized into compiled rules (fast load), fast-scan mode. For RepoGate's actual workload (many small text files, dozens of rules) this headroom is not the deciding factor — it becomes one only if RepoGate loads *thousands* of community rules or scans large binaries. The other performance-adjacent win is safety: a Rust engine has no C parser memory bugs, which matters when the input is hostile by definition (classic YARA's parser has had CVEs; GuardDog sandboxes its scanner for exactly this class of reason).

---

## 3. Community YARA corpora — and the licensing traps

| Corpus | Scale | License | Trap level |
|---|---|---|---|
| **Neo23x0/signature-base** | ~5,000 rules (4,978 in YARA-Forge's full package) | **Detection Rule License (DRL) 1.1** — full text read 2026-11-20 | **Medium — attribution with teeth** (below) |
| **YARA-Forge** (YARAHQ) packages: core / extended / full | Latest release read 2026-11-20: **core 5,089 / extended 10,849 / full 11,852 rules**, aggregated from ~40 sources (Malpedia 1,621 in core, signature-base 1,060 in core, SEKOIA 700, ESET, FireEye-RT, Volexity, ReversingLabs…) | The Forge *tool* is GPL-3.0; the *packages are license-heterogeneous* — each source's license text is embedded per section | **High if treated as one license** (below) |
| **Elastic protections-artifacts** (a major Forge source) | ~1,000+ rules | **Elastic License 2.0** | **High** — not OSI; bars providing the rules as a hosted/managed service, bars circumvention, notices must be retained; ELv2 content inside an MIT/Apache product does not relicense |
| **bartblaze/Yara-rules** | hundreds | MIT | Low |
| **InQuest/yara-rules-vt** | hundreds | MIT | Low |
| **Didier Stevens Suite** | dozens | Public domain | Low |
| **abuse.ch YARAify** | community feed | CC0 | Low |
| **Malpedia** (Forge core's largest single source) | 1,621 rules in Forge core | Per-source — **must be verified before bundling**; Forge embeds it, which is not the same as clearing it | Check first |

(License column for the MIT/public-domain/CC0 rows is per Mailstrix's ruleset license table, a third-party compilation read 2026-11-20, spot-consistent with the projects; the DRL and Forge rows are from primary sources read today.)

### The traps, precisely

1. **DRL 1.1 is permissive — with attribution that reaches into your output.** The current text (signature-base `LICENSE`, read in full today) grants use, copy, modify, merge, publish, distribute, sublicense, and **sell** "without restriction," subject to: (a) if you *share* the rules, retain the author identification, a URI to the rule set, and the DRL notice; (b) if you *use* the rules on data, **messages based on matches must retain the author identification**. Clause (b) is the one products trip on: your scanner's findings must carry rule-author attribution. DRL 1.1 is not OSI-approved. Ecosystem behavior confirms the caution: downstream projects fetch signature-base as a *pinned, opt-in download with its LICENSE carried alongside* rather than bundling it (documented in a public project's rules-fetch tooling, read 2026-11-20), and packagers keep it as a separately toggleable set. Note also that older DRL versions were more restrictive — check the version in any given copy, don't assume 1.1.
2. **"YARA-Forge core" is a quality tier, not a license tier.** Forge filters by age/quality/importance/score — *not* by license permissiveness. A core package mixes BSD, MIT, DRL 1.1, and Elastic License 2.0 rules in one file with per-section license headers. Bundling it wholesale into an MIT product means shipping a mixed-license bundle and honoring the strictest terms per rule (including ELv2's service restriction). Forge itself disables some upstream sources "due to license restrictions" — follow that example per-source, not per-package.
3. **SkillSpector's own corpus inherits trap #1.** Three of its five YARA files are signature-base-derived (see §1.1). NVIDIA's repo-level Apache-2.0 does not cleanse upstream DRL conditions on derived content. Copying those files into RepoGate imports DRL obligations; copying `malware.yar.b64` imports *unknown* obligations.
4. **No license = no rights.** The long tail of GitHub rule dumps with no LICENSE file is all-rights-reserved by default. Absence of a license is a stop sign, not a green light.

---

## 4. What YARA cannot express that RepoGate needs

YARA's unit of analysis is **one buffer** (one file's bytes). Everything RepoGate does above that unit is structurally out of reach:

1. **Cross-file / cross-package correlation.** Rule-to-rule references work only within a single scan of a single buffer. GuardDog's design is the field's own admission: capability + threat *in the same file* forms a risk in the engine's terms; anything cross-file is computed in Python at downgraded severity. RepoGate's 8 named risk chains (stealer = credential access in one file + exfil in another + install hook in a third) are tree-level facts. No YARA version changes this.
2. **Structural checks on parsed formats.** "package.json's `scripts.postinstall` value contains a URL," "tasks.json pairs `runOn: folderOpen` with silent presentation," "this workflow pairs `pull_request_target` with a head-ref checkout" — these are statements about *parsed JSON/YAML semantics* (key paths, value relationships, insensitivity to key order/formatting). YARA sees bytes; regex approximations exist (GuardDog ships one for npm preinstall) but they are the brittle layer, not the check. Same for AST-level detections — SkillSpector's reflective-`getattr` sink detection (its AST9) is Python AST work, not YARA.
3. **Declared-vs-actual diffing.** SkillSpector's MCP least-privilege and tool-poisoning checks compare what a manifest *declares* against what code *does*. That is a two-artifact semantic comparison; YARA can hold neither side's meaning.
4. **Metadata and ecosystem state.** Typosquat edit-distance against top-package lists, version-history diffs (new install script on a previously clean package, provenance-attestation regression), registry↔repo integrity comparison, maintainer-domain checks. These need external data and computation. YARA has no I/O; external variables can inject precomputed scalars, but the computation is external by definition — which is why all 11 of GuardDog's metadata detectors are Python.
5. **Normalization pipelines.** RepoGate decodes base64 blobs and *re-scans the decoded content with the full rule set*, folds string concatenations back together, decodes Unicode Tags-block smuggling, and re-checks whitespace-pushed payloads. YARA's `base64`/`base64wide` string modifiers match *known strings in encoded form* — they do not decode arbitrary payloads for a full rescan. (SkillSpector likewise keeps a ~27 KB Python `unicode_confusables.py`; the normalization lives outside YARA in every serious tool.)
6. **Prompt-injection semantics beyond phrase lists.** YARA demonstrably *can* carry the phrase layer — SkillSpector's `agent_skill_prompt_injection_hidden_instructions` is a good one (hidden-comment + override-verb conjunctions). But judging that text *instructs the agent*, that a tool description mismatches its behavior (SkillSpector's TP4 is LLM-powered), or that natural language is a covert command rather than documentation, is not pattern matching. Phrase rules also inherit the field's worst false-positive surface (the prior audit documented a benign skill scored 100/100 over the word "arsenic" in prose).
7. **Path and role awareness.** YARA doesn't know a buffer's path or role in the tree; the identical string is benign in a test fixture and critical in `setup.py`. GuardDog bolts this on with `path_include` meta consumed by its harness — the engine ignores it.
8. **The verdict machinery itself.** Coverage accounting and the INCONCLUSIVE verdict, quarantine workflow, trust signals, baselines, per-category score caps — all harness, by construction.

**Conclusion of this section:** in every mature tool examined, YARA is one layer. A "merge into YARA" plan merges the pattern layer only, and silently drops the parts of each tool that make it accurate.

---

## 5. Porting analysis — what moving each source into a yara-x layer actually costs

| Source | Syntax port to yara-x | Real cost | License gate |
|---|---|---|---|
| **GuardDog `.yar` (55)** | Near-total. Plain text/regex rules written for classic YARA, no module dependencies observed; expect ~100% compile under yara-x 1.23, with strictness errors (if any) being quick fixes | **Meta-schema translation, not syntax:** map `identifies` / `severity` / `specificity` / `sophistication` / `max_hits` / `path_include` onto RepoGate's finding taxonomy and re-implement scoping in the harness. The correlation model ports as *concepts* into RepoGate's existing chains (already done in the current build) | **None.** Apache-2.0, Datadog-authored; vendor with NOTICE attribution |
| **SkillSpector `agent_skills.yar` (5)** | Trivial — already YARA, simple patterns | None beyond wiring | **None.** SPDX Apache-2.0 in-file, NVIDIA-authored |
| **SkillSpector webshells / cryptominers / hacktools (15)** | Trivial syntactically | — | **DRL 1.1 (derived from signature-base).** Options: (a) vendor with DRL attribution plumbing, including author ID in match output; (b) clean-room rewrite — the patterns are largely factual string lists (pool domains, shell family names, tool names) that can be re-expressed in RepoGate's own structure; (c) don't vendor — consume via an external signature-base pack. **Recommend (b) or (c); do not copy the files** |
| **SkillSpector `malware.yar.b64`** | Unknown until decoded | Decode + header inspection is a prerequisite to any use | **Unknown / DRL-suspect.** Do not vendor blind |
| **SkillSpector's 71 Python patterns** | Partial. The regex subset (most of the catalog is substrings + simple regex) translates mechanically; patterns using Python-only constructs (lookahead/backreferences) need manual rewrite — YARA's regex dialect doesn't offer them. The 9 behavioral-AST patterns, 5 taint patterns, OSV lookup, and LLM-powered checks **do not port at all** — they are code, and stay code in any architecture | Moderate for the regex subset; the taxonomy (17 categories) ports as *organization*, which the current RepoGate build already absorbed | Apache-2.0 for NVIDIA's own code/patterns (the YARA-file DRL derivation is the exception, above) |
| **CloneGuard's Go regex packs** | Easy for the patterns. CloneGuard deliberately uses simple line regexes (Go RE2 flavor); RE2 and YARA regex overlap almost completely at that complexity, so pattern strings translate ~1:1 (modifiers move from inline flags to YARA string modifiers) | Its file-classification scoping (code/config/docs/lockfile classes, docs & lockfiles exempt) and cross-category combination escalation are Go harness logic — re-implement regardless of pattern language. The corpus is small (solo project, Nov 2026), so the durable steal is its rule *format* (`{id, title, severity, category, scope, regex, why}` + a test per rule), not volume | MIT (per the specialized audit) |

---

## 6. Verdict and recommendation

**Do not make YARA the engine. Do adopt yara-x as a first-class layer — in the Rust build, for the three jobs only it can do:**

1. **Binary payload scanning.** Repos and packages ship binaries (GuardDog has a whole `bundled_binary` metadata detector because of it). RepoGate today can say little about a bundled `.exe`/`.so`/`.dll` beyond "present." YARA-X's `pe`/`elf`/`macho`/`dotnet` modules are the only credible open way to pattern-scan those artifacts — regex packs can't, at any effort level.
2. **Community-corpus leverage.** Thousands of maintained malware-family rules exist *only* as YARA. With yara-x, RepoGate can load a pinned YARA-Forge **core** package (5,089 rules) or signature-base as an **external, version-pinned, attribution-carrying pack** — fetched, license-screened per source, and excludable — instead of re-deriving that knowledge. This is where "merging the field" is literally true.
3. **Scale headroom.** Compiled Aho-Corasick matching is what makes #2 affordable; a Python `re` loop over 5,000 rules × thousands of files is not a plan.

**Keep as native code (the actual product):** structural checks, the 8 risk chains, prompt-injection phrase+normalization layers, metadata/typosquat detectors, coverage accounting, and the verdict contract. YARA cannot hold them (§4), and they are RepoGate's differentiation.

**Language coupling, stated plainly:**

- **If RepoGate goes Rust** (the owner's stated preference, and the direction of the wider merge question): the `yara-x` crate is the native path — one static binary, compiled rules embedded or loaded, no C libyara, memory-safe scanning of hostile input. This is the single strongest technical argument for the Rust build.
- **If RepoGate stays Python:** yara-x is reachable only via the PyPI `yara_x` wheel (real, maintained, ships all default modules except `magic`) or by shelling out to the `yr` CLI — both break the current build's zero-dependency guarantee, which is one of its agent-skill selling points. Classic `yara-python` is the worse option in Nov 2026: it chains the project to the maintenance-mode engine.
- **Either way:** do not choose classic YARA/libyara for new work. VirusTotal has frozen its future; GuardDog's June-2026 choice of yara-python is already the conservative outlier.

**Concrete merge plan for the pattern layer:**

1. Vendor GuardDog's 55 rules (Apache-2.0) with meta translated to RepoGate's taxonomy; vendor SkillSpector's `agent_skills.yar` (Apache-2.0) as-is.
2. Clean-room rewrite the 15 DRL-derived SkillSpector patterns (factual string lists) — or skip them and let the external pack cover that ground.
3. Decode and provenance-check `malware.yar.b64` before any decision on it.
4. Ship community corpora as **opt-in external packs**: pinned YARA-Forge core or signature-base, downloaded with their LICENSE files, per-source license screen (drop ELv2-sourced rules if RepoGate is ever offered as a service), DRL author attribution surfaced in findings output.
5. Keep RepoGate's own rules in the portable native layer so the semantic core never depends on the YARA layer being present.

---

## Sources (all accessed 2026-11-20)

- SkillSpector repo tree + `src/skillspector/yara_rules/{agent_skills,webshells,cryptominers,hacktools}.yar` + THIRD_PARTY_NOTICES.md — github.com/NVIDIA/SkillSpector (main @ 48e0f94)
- GuardDog repo tree (branch `v3` @ 5da9538) + `guarddog/analyzer/sourcecode/capability-filesystem-browser.yar` — github.com/DataDog/guarddog
- Datadog Security Labs, "Introducing GuardDog 3.0" (2026-06-26) — securitylabs.datadoghq.com (yara-python engine statement; capability/threat model)
- signature-base LICENSE (DRL 1.1, full text) — github.com/Neo23x0/signature-base
- YARA-Forge releases (latest: core 5,089 / extended 10,849 / full 11,852; per-source tables) — github.com/YARAHQ/yara-forge/releases; YARAHQ org page (tool GPL-3.0)
- YARA-X: GitHub releases (v1.23.0 cycle notes), lib.rs crate page (45 releases, BSD-3-Clause, VT production statement), virustotal.github.io/yara-x comparison docs (performance, API/process-scanning limits), yararules.org YARA-X + modules guides (updated 2026-11-17; module list; "vast majority compile" port rate), SANS ISC via securityarsenal.com (v1.23.0, 2026-11-15), Heimdal 2026 roundup (classic YARA v4.6.0 maintenance mode, verified 2026-11-09)
- Mailstrix ruleset license table (bartblaze MIT, InQuest MIT, Didier Stevens public domain, YARAify CC0, signature-base DRL 1.1, YARA-Forge as aggregator) — mailstrix.com
- Prior audits: `research/tool-audit-nvidia-datadog.md`, `research/tool-audit-specialized.md` (2026-11-20)
