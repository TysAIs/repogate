# Code-Merge Feasibility Audit — Can RepoGate literally merge the other scanners?

**Date:** 2026-11-20 · **Method:** live inspection of the actual repositories — GitHub API metadata (license, default branch, push dates), full recursive git trees, and raw file reads of LICENSE/NOTICE files, rule files, and pack data. Nothing was copied into RepoGate; source trees were downloaded to a scratch dir for counting/inspection only.
**Question (owner):** make RepoGate "one big thing" by merging the other tools' code/rules where legal, instead of only re-implementing their ideas.

## Bottom line

**Yes — a literal merge is legally feasible for almost everything that matters, and the best assets are data, not code.** Four of the five open-source tools are Apache-2.0 or MIT; there is **no copyleft anywhere in the five tools' own code**. The reusable gold, in order:

1. **Sigil's core signature packs** — 19 JSON files, ~400+ rules, plain data, Apache-2.0. The single highest-value vendor: it drops straight into a rules-as-data engine.
2. **GuardDog's 55 YARA rules** (`guarddog/analyzer/sourcecode/*.yar`, 2,354 lines, one rule per file, Datadog-authored, Apache-2.0) — vendor the files; transpile to RepoGate's regex engine where RepoGate's zero-dependency rule forbids a YARA runtime.
3. **SkillSpector's eval fixtures** — 33 fixture skills + pattern samples (Apache-2.0): an instant known-malicious/known-benign test corpus. Its 71 detection patterns are **code, not data** (~33k lines of Python analyzers) — those are a *port*, not a vendor.
4. **CloneGuard's 20 line rules + repo-guard's 4 Python modules** — small, MIT, an afternoon-to-two-days port.

**The one hard exclusion:** Sigil's optional LOLBin pack (`packs/lolbin/v1/`) is **GPL-3.0** (derived from GTFOBins + LOLBAS, both GPL-3.0) and Sigil itself segregates it from its Apache-2.0 binary for exactly this reason. RepoGate must do the same: skip it, or ship it only as a clearly separate, opt-in GPL-3.0 bundle. **ScanRepo has no public engine source at all** (confirmed below) — nothing to merge, ideas only.

A compliant merge keeps RepoGate MIT-licensed overall, with vendored components keeping their own licenses inside a `third_party/` tree plus a `SOURCES.md` manifest and a `NOTICE` file (layout in §4).

---

## 1. License matrix (verified live, 2026-11-20)

| Tool | Repo | License | Verified via | Default branch / last push |
|---|---|---|---|---|
| NVIDIA SkillSpector | github.com/NVIDIA/SkillSpector | **Apache-2.0** | GitHub API + `LICENSE` + per-file SPDX headers (`SPDX-License-Identifier: Apache-2.0` in source) | `main` / 2026-11-19 |
| DataDog GuardDog | github.com/DataDog/guarddog | **Apache-2.0** | GitHub API + `LICENSE`; repo also ships a `NOTICE` file (Datadog, Inc.) and `LICENSE-3rdparty.csv` for its *dependencies* | `v3` / 2026-11-16 |
| tharun208/cloneguard | github.com/tharun208/cloneguard | **MIT** | GitHub API + `LICENSE` (Copyright (c) 2026 Tharun Rajendran) | `main` / 2026-11-08 |
| NOMARJ/sigil | github.com/NOMARJ/sigil | **Apache-2.0** (core) — **GPL-3.0** for `packs/lolbin/v1/` only | GitHub API + root `LICENSE`; sub-licenses at `packs/lolbin/v1/LICENSE` (GPL-3.0 text), `plugins/vscode/LICENSE` (Apache-2.0), `sigil-skill/LICENSE` (Apache-2.0) | `main` / 2026-10-09 |
| WBChain3/repo-guard | github.com/WBChain3/repo-guard | **MIT** | GitHub API + `LICENSE` (Copyright (c) 2026 WBChain3) | `main` / 2026-05-19 |
| ScanRepo | scanrepo.dev (hosted) | **No public engine source** | §5 | — |

No GPL/LGPL/AGPL in any of the five tools' own code. Two third-party wrinkles inside otherwise-clean repos: SkillSpector's YARA files are partly derived from **Neo23x0/signature-base (DRL-1.1)** (§2.1), and GuardDog's `LICENSE-3rdparty.csv` lists an **LGPL-2.1 Semgrep dependency** — a dependency of GuardDog, not GuardDog content; it only matters if RepoGate vendored GuardDog's *runtime*, which the plan does not do.

---

## 2. What is concretely reusable, per tool

### 2.1 NVIDIA SkillSpector (Apache-2.0)

| Asset | Path | Size / count | Form |
|---|---|---|---|
| Pattern analyzers | `src/skillspector/nodes/analyzers/static_patterns_*.py` (15 modules: prompt_injection, data_exfiltration, supply_chain, tool_misuse, anti_refusal, privilege_escalation, memory_poisoning, rogue_agent, ssrf, deserialization, excessive_agency, harmful_content, output_handling, system_prompt_leakage, agent_snooping) | **~32,950 lines total** (tool_misuse alone 17,779) | **Code, not data.** Patterns are Python logic (regex + AST context + fp-suppression), driven by `pattern_defaults.py`. Extracting the 71 patterns = a port (§6). |
| Other analyzers | same dir: `behavioral_ast.py`, `behavioral_taint_tracking.py`, `mcp_tool_poisoning.py`, `mcp_least_privilege.py`, `mcp_rug_pull.py`, `whitespace_padding.py`, `osv_client.py`, … | 37 analyzer modules total | Code; the taint + MCP modules are the most original — port candidates, not vendors. |
| YARA rules | `src/skillspector/yara_rules/`: `agent_skills.yar` (5 rules), `cryptominers.yar` (4), `hacktools.yar` (5), `webshells.yar` (6) = **20 rules**, plus `malware.yar.b64` (a base64-encoded 5th rule file) | 4 files + 1 encoded | Data — **but provenance-wrinkled**: file headers state "Based on patterns from Neo23x0/signature-base (DRL-1.1)". DRL-1.1 is a permissive, attribution-style license (not copyleft), so reuse is allowed — keep the in-file headers intact and credit signature-base in the manifest (§4). |
| Eval fixtures | `tests/fixtures/` — **33 `SKILL.md` fixture skills**: `malicious_skill/`, `mcp_poisoned_tool/`, `mcp_overprivileged_skill/`, `mcp_underdeclared_skill/`, `mcp_mismatched_skill/`, `mcp_clean_skill/`, `safe_skill/`, `e2_shell_env_harvest/`, `pe3_bare_keyring/`, `sdi/*` (4 scope-divergence cases), `as3_self_reference/`; plus `tests/unit/data/patterns/` (9 per-pattern sample snippets: `e2_env_harvesting.txt`, `pe3_ssh_key_access.txt`, `sc2_curl_bash.txt`, `sc3_base64_exec.txt`, …) | 33 skills + 9 snippets | **Vendor verbatim as RepoGate's eval corpus.** Highest value-per-hour in this whole audit: labeled malicious/benign agent-skill cases RepoGate currently lacks. |
| Third-party notices | `THIRD_PARTY_NOTICES.md` | Lists runtime *dependencies* (typer, rich, pydantic, yara-python, …) | Only relevant if vendoring SkillSpector code wholesale; the pattern/fixture assets carry no extra third-party burden beyond the DRL note above. SkillSpector ships **no Apache NOTICE file**, so §4(d) imposes nothing extra for it. |

### 2.2 DataDog GuardDog (Apache-2.0)

| Asset | Path | Size / count | Form |
|---|---|---|---|
| YARA source rules | `guarddog/analyzer/sourcecode/*.yar` | **55 files, 55 rules, 2,354 lines** — 11 `capability-*.yar` + 44 `threat-*.yar` (obfuscation family alone: 13 files). Every rule carries structured meta: `author = "GuardDog Team, Datadog"`, `identifies =`, `severity`, `mitre_tactics`, `specificity`, `sophistication`, `path_include`, `max_hits` | **Data — the cleanest rule asset in the field.** Datadog-authored, Apache-2.0, no third-party derivation noted in the files. Vendor verbatim; the meta block maps almost 1:1 onto RepoGate's rule schema + GuardDog-style chain scoring. |
| Metadata detectors | `guarddog/analyzer/metadata/` (+ `npm/`, `pypi/`, `go/`, `github_action/` subdirs) | **31 Python modules**: `typosquatting.py` (×4 ecosystems), `npm/new_install_script.py`, `npm/provenance_regression.py`, `npm/risky_new_dependency.py`, `npm/direct_url_dependency.py`, `*/bundled_binary.py`, `*/deceptive_author.py`, `*/metadata_mismatch.py`, `pypi/repository_integrity_mismatch.py`, `*/potentially_compromised_email_domain.py`, `*/unclaimed_maintainer_email_domain.py` | Code (Python). Ports cleanly to RepoGate's Python, but most detectors need **registry metadata + version history** — they only fire in RepoGate's GitHub/registry-metadata stage, not in local-tree scans. Port the subset (§6). |
| Typosquat reference data | `guarddog/analyzer/metadata/resources/top_{pypi,npm,rubygems,go}_packages.json` | 4 JSON lists | **Vendor verbatim (data).** RepoGate's current popular-package list is 30 hand-typed names; this replaces it with the real corpus. |
| Rule docs | `RULES.md`, `WRITING_RULES.md`, `.claude/skills/writing-guarddog-rules/SKILL.md` | Full rule catalog + authoring guide | Reference for the port; the rule-writing SKILL.md is itself adaptable (Apache-2.0) for RepoGate's own rule-authoring skill. |
| Test samples | `tests/analyzer/sourcecode/` — **82 per-rule sample files** (26 under `benign/`, the rest malicious/positive samples named per rule), 134 test files total | ⚠️ **Git-only**: GuardDog's `.gitattributes` sets `/tests export-ignore`, so release tarballs omit them — vendor from a pinned git clone, not a tarball. License still Apache-2.0. |
| Evals harness | `evals/` (`benchmark.py`, `recall.py`, `recall_samples.json`, …) | Harness code in-repo; the underlying malicious-packages dataset is **Datadog's external dataset**, referenced not bundled | Port the harness idea later; do not count the dataset as an asset. |
| NOTICE | `NOTICE` — "Datadog guarddog / Copyright [2022-Present] Datadog, Inc." | — | **Must travel** with any vendored GuardDog material (Apache §4(d), §4). |

### 2.3 tharun208/cloneguard (MIT)

| Asset | Path | Size / count | Form |
|---|---|---|---|
| Line rules | `internal/scanner/rules.go` | **20 rules** in 158 lines: `reads-ssh-keys`, `reads-cloud-credentials`, `reads-browser-or-wallet-data`, `dumps-environment`, `sends-to-ip-address`, `uses-dropoff-service`, `uses-tunnel-service`, `pipes-download-into-shell`, `runs-downloaded-or-decoded-code`, `hidden-after-whitespace`, `long-base64-blob`, … Each rule = `{id, title, sev, cat, scope, regex, exclude, suppresses, why}` | Go structs — the **regexes and metadata port in an afternoon** into RepoGate's rule format; the `scope` (code / code+config / any-text) and `suppresses` fields are schema ideas worth adopting wholesale. |
| Structural checks | `internal/scanner/` (package.json hooks, tasks.json, setup.py, binary detection) + `demo/` malicious demo repo | Small Go package; demo repo is a ready-made fixture | Port the checks RepoGate lacks (it has most); vendor the demo as a fixture. |

### 2.4 NOMARJ/sigil (Apache-2.0 core / GPL-3.0 lolbin pack)

| Asset | Path | Size / count | Form |
|---|---|---|---|
| **Core signature packs** | `cli/packs/core/v1/*.json` — **19 files, 672 KB total**: `prompt_injection.json` (18), `agent_instructions.json` (33), `agent_manipulation.json` (13), `agent_supply_chain.json` (19), `skill_security.json` (24), `creds.json` (39), `network_exfil.json` (25), `code_patterns.json` (22), `obfuscation.json` (15), `obfuscation_chain.json` (19), `install_hooks.json` (13), `persistence.json` (13), `insecure_transport.json` (10), `inference_security.json` (12), `multilingual_injection.json` (4), `supply_chain.json` (20), `reverse_shells.json` (81), `provenance.json` + `structural.json` (dict-form packs) | **~400+ rules as pure JSON data** | **Vendor verbatim — the #1 merge target.** JSON regex/signature packs load into any engine (Python now, Rust later) with a thin adapter for severity/phase naming. `reverse_shells.json` derives from the MIT-licensed reverse-shell-generator (per Sigil's own NOTICE) — still fine under Apache-2.0 distribution with attribution kept. |
| Eval fixtures | `tests/fixtures/` (76 files) + `tests/fixtures/MANIFEST.json` | **36 synthetic cases** with expected phase + minimum severity per case, hand-authored from published advisories (Shai-Hulud preinstall shape, etc.); plus `sigil-skill/tests/fixtures/` (clean / medium-risk / malicious mini-projects) | **Vendor as eval corpus** alongside SkillSpector's fixtures. MANIFEST's own honesty note: synthetic, not live malware. |
| Threat signatures (API side) | `api/data/threat_signatures.json` (30 KB), `api/data/whitelist_patterns.json` | Server-side data for Sigil's hosted API | **Skip** (§5): provenance/update path is their service's, not the CLI's; the CLI packs supersede it for RepoGate's purposes. |
| LOLBin pack | `packs/lolbin/v1/{lolbin_unix.json, lolbin_windows.json}` + own `LICENSE` + `NOTICE.md` | Derived from **GTFOBins + LOLBAS, both GPL-3.0** | ⛔ **NOT vendorable into the main tree** (§3, §5). |
| Engine code | `cli/src/*.rs` (Rust), `api/` (Python) | Full Rust CLI | Not a merge target: RepoGate would port *behavior* (quarantine flow, evidence-gated verdicts), not adopt a second engine. |

### 2.5 WBChain3/repo-guard (MIT)

| Asset | Path | Size / count | Form |
|---|---|---|---|
| Scanner modules | `repo_guard/modules/`: `hook_scanner.py` (10,795 B), `ioc_extractor.py` (14,096 B), `vscode_scanner.py` (8,071 B), `trust_score.py` (7,962 B) | ~41 KB Python total | **Port (near-vendor)**: Python→Python, MIT. `hook_scanner` (`.githooks/` patterns + comment-to-code-ratio heuristic) and `vscode_scanner` (structured tasks.json/settings.json checks) fill real RepoGate gaps; `ioc_extractor` becomes RepoGate's IOC module; `trust_score` plugs into the existing GitHub-API acquisition stage. |
| IOC feed | `IOC_FEED.md` | **Exactly 1 entry** (2026-05-17 "FlexPay", itself replicated from published Contagious Interview analysis) | Take the *format* (dated entries, attack type, IOCs, reporting status, PR intake); the data itself is one entry — no intel value to merge. |
| Fixtures | `tests/fixtures/flexpay_mock/` (mock malicious repo: `.githooks/post-checkout`, `.vscode/tasks.json`, settings), `tests/fixtures/clean_repo/` | 2 mini-repos | Vendor as fixtures (MIT). |

---

## 3. The copyleft / provenance traps (complete list)

1. **Sigil `packs/lolbin/v1/` — GPL-3.0.** Derived from GTFOBins (`GTFOBins/GTFOBins.github.io`) and LOLBAS (`LOLBAS-Project/LOLBAS`), both GPL-3.0. Sigil's own `packs/lolbin/v1/NOTICE.md` states the conservative position: regex signatures distilled from GPL corpora are treated as GPL-3.0 derivative works, kept out of the compiled binary, shipped as a separate opt-in bundle. **RepoGate ruling: exclude from the merge.** If LOLBin coverage is ever wanted, ship it exactly Sigil's way — separate directory, own GPL-3.0 LICENSE + NOTICE, opt-in load, never in the default rule set — or write original rules from the underlying public *facts* (binary names/behaviors) without copying their rule text.
2. **SkillSpector YARA ← Neo23x0/signature-base — DRL-1.1.** The Detection Rule License 1.1 is permissive (use/modify/redistribute allowed) with attribution conditions — **not copyleft**, but the attribution must survive: keep the in-file headers ("Based on patterns from Neo23x0/signature-base") and add a signature-base line to RepoGate's manifest/NOTICE. Affects `webshells.yar`, `malware.yar.b64` (both self-declare the derivation); treat all 5 YARA files as DRL-attributed to be safe.
3. **GuardDog's dependency list ≠ GuardDog's license.** `LICENSE-3rdparty.csv` lists Semgrep (LGPL-2.1) among GuardDog's *Python dependencies*. Vendoring GuardDog's YARA/metadata **files** imports none of that. It would only bite if RepoGate adopted GuardDog's runtime or SkillSpector's Semgrep integration (`src/skillspector/semgrep_tokens.py`) as a dependency — the plan does neither (RepoGate stays stdlib-only; Semgrep is also the engine GuardDog itself dropped in v3).
4. **GuardDog test fixtures are archive-invisible** (`/tests export-ignore`). Not a license problem — a sourcing rule: pin a git commit and clone, don't rely on release tarballs, or the fixtures silently won't be there.
5. **Sigil `api/data/threat_signatures.json`** — hosted-service intel with no stated per-file provenance. Skip rather than guess.
6. **ScanRepo's scam database** (scanrepo.dev/scams) — website data with no license grant and no repo. Scraping it into RepoGate would be unclear-provenance republication. Link to it; don't ingest it.

---

## 4. License obligations of the merge, and the compliant layout

RepoGate is MIT (its `README.md`). MIT + Apache-2.0 + MIT components combine cleanly: the combined work can stay MIT-licensed for RepoGate's own code, while vendored components **retain their own licenses in place** — vendoring never relicenses the vendored files.

**Per-license duties:**
- **MIT (CloneGuard, repo-guard):** include the copyright notice + MIT license text with the copied material. That's all. (§ permission notice in all copies/substantial portions.)
- **Apache-2.0 (SkillSpector, GuardDog, Sigil core):**
  - §4(a) include a copy of the Apache license for each source.
  - §4(b) mark modified files with prominent change notices (matters for *ported* code: a ported file should carry "Ported from X, Apache-2.0, changes: …").
  - §4(c) retain copyright/attribution notices in the copied material (keep SPDX headers — SkillSpector files already carry them; GuardDog YARA meta blocks name Datadog as author — keep them).
  - §4(d) if the source ships a NOTICE file, its attribution contents must be included in RepoGate's NOTICE/docs. **GuardDog has one** ("Copyright [2022-Present] Datadog, Inc.") → goes into RepoGate's `NOTICE`. SkillSpector and Sigil core ship no root NOTICE (Sigil's only NOTICE is the GPL lolbin one — another reason that pack stays out).
  - §3 patent grant: Apache-2.0 components come with an express patent license from NVIDIA/Datadog/NOMARJ — a genuine plus of merging these vs. MIT-only sources; it also means RepoGate's NOTICE/attribution hygiene is what keeps the grant clean.
- **DRL-1.1 (SkillSpector YARA files):** keep attribution headers; list Neo23x0/signature-base in the manifest.
- **Vendored data keeps its license:** JSON packs and YARA files are copied *as data under their own license files* placed beside them — the engine that loads them is RepoGate's own MIT code. (This is the same separation Sigil uses, minus the GPL part.)

**Compliant vendoring layout:**

```
repogate/
  LICENSE                  # MIT — RepoGate's own code (unchanged)
  NOTICE                   # NEW: attribution roll-up (Datadog NOTICE text,
                           #   NVIDIA, NOMARJ, signature-base/DRL credit)
  SOURCES.md               # NEW: manifest — per component: upstream repo URL,
                           #   pinned commit SHA, license, what was taken,
                           #   verbatim vs ported, local modifications
  third_party/
    sigil-core-packs/      # verbatim JSON packs
      LICENSE              # Apache-2.0 (Sigil's)
      SOURCE.md            # -> NOMARJ/sigil @ <sha>, files unmodified
    guarddog-yara/         # verbatim .yar files
      LICENSE              # Apache-2.0 (GuardDog's)
      NOTICE               # GuardDog's NOTICE, verbatim
    guarddog-metadata-data/  # top_*_packages.json
      LICENSE
    skillspector-yara/     # .yar files, headers intact (DRL-1.1 attribution)
      LICENSE              # Apache-2.0 + DRL note in SOURCE.md
    fixtures/
      skillspector/        # 33 fixture skills + pattern samples, LICENSE
      sigil/               # 36-case fixture tree + MANIFEST.json, LICENSE
      repo-guard/          # flexpay_mock + clean_repo, LICENSE (MIT)
  src/ (repogate code)     # ports live here as RepoGate code; each ported
                           # file header cites upstream + license + changes
```

Rules of the house: (1) vendored files are **never edited in place** — updates are re-vendors from a newer pinned SHA, recorded in `SOURCES.md`; local adaptations happen in RepoGate-side adapter code. (2) Every port (not vendor) gets a file header: upstream path, license, "ported from", date. (3) Pin exact upstream commit SHAs — all five upstreams move (SkillSpector pushed 2026-11-19; Sigil's HEAD has been static since ~Oct, repo-guard's since May).

---

## 5. What is NOT reusable

| Item | Why |
|---|---|
| **ScanRepo engine** | **Confirmed: no public source exists.** No engine repo under the operator's GitHub account (100 public repos listed for `rubenmarcus`, checked 2026-11-20 — none is the scanner), none linked from scanrepo.dev; prior audit found only a third-party Chrome extension. The engine is a hosted service (v10) behind `POST /api/scan`. Nothing to vendor or port — ideas only (coverage accounting, INCONCLUSIVE verdict), which RepoGate already absorbed. |
| **ScanRepo scam/IOC database** | Website-only data, no license grant (§3.6). Link, don't ingest. |
| **Sigil LOLBin pack** | GPL-3.0 copyleft (§3.1). Excluded, or separate opt-in GPL bundle only. |
| **Sigil `api/data/threat_signatures.json`** | Unclear provenance (hosted-service intel). Skip. |
| **GuardDog's Datadog malicious-packages dataset** | External to the repo (evals harness references it); not Datadog's to give via this repo / not bundled. RepoGate's eval corpus comes from SkillSpector + Sigil fixtures instead. |
| **SkillSpector's LLM stage & Semgrep integration** | Not assets: the LLM stage is a design RepoGate explicitly rejects (non-determinism — Checkmarx), and Semgrep is an LGPL-2.1 third-party engine, not SkillSpector content. |
| **Anything from the tools' hosted/paid tiers** (Sigil Pro LLM phase, ScanRepo service, Datadog SIEM content pack) | Closed by definition; also unnecessary. |

**Copyleft census, final:** across all five open-source tools, the *only* copyleft material found is the Sigil lolbin pack (GPL-3.0, already segregated upstream) and other projects' *dependencies* (Semgrep LGPL-2.1) that a file-level merge never touches.

---

## 6. Concrete merge plan — vendor / port / skip, with effort

Effort = focused engineer-days for one developer + the agent fleet, including tests against fixtures. Ordered by value-per-day.

### Phase 1 — Vendor verbatim (data + fixtures) · ~2–3 days total
| # | Component | Work | Effort |
|---|---|---|---|
| 1.1 | **Sigil core packs** (19 JSON, ~400 rules) → `third_party/sigil-core-packs/` | Copy at pinned SHA; write the pack loader in RepoGate's engine (JSON → internal rule objects; map Sigil phases → RepoGate categories, severities → RepoGate bands); dedupe against RepoGate's existing ~70 rules (expect real overlap in creds/exfil/injection — keep both IDs, Sigil rule keeps its ID + source tag) | 1–1.5 d |
| 1.2 | **GuardDog top-packages data** (4 JSON) | Drop-in replacement for RepoGate's hand-typed list; wire typosquat check to it | 0.25 d |
| 1.3 | **Eval corpora**: SkillSpector 33 fixture skills + 9 pattern samples; Sigil 36-case fixture tree + MANIFEST; repo-guard `flexpay_mock`/`clean_repo`; CloneGuard `demo/` | Vendor under `third_party/fixtures/…` with LICENSEs; extend `tests/run_tests.py` to assert expected verdict band per fixture (SkillSpector/Sigil fixtures carry labels; Sigil's MANIFEST carries expected phase+severity) | 0.5–1 d |
| 1.4 | `NOTICE`, `SOURCES.md`, per-dir LICENSE/SOURCE.md files | Paperwork from §4 templates | 0.25 d |

**Effect:** RepoGate's rule count goes ~70 → ~450+, and it gains a labeled eval corpus — the two things it most lacks — for ~3 days, zero license risk.

### Phase 2 — Port (code → RepoGate code, headers citing upstream) · ~5–8 days total
| # | Component | Work | Effort |
|---|---|---|---|
| 2.1 | **GuardDog YARA → RepoGate rules** (55 rules) | RepoGate is stdlib-only (no YARA runtime — deliberate invariant). Most GuardDog rules are regex-string sets + simple conditions: write a one-time transpiler that extracts `strings:` regexes + meta (`identifies`, severity, mitre) into RepoGate pack JSON; hand-review the ~10 rules using hex strings / complex conditions (skip or approximate those, logged in SOURCES.md). Alternative — optional `yara-python` extra — rejected: breaks the zero-dependency invariant that makes the agent skill portable. | 2–3 d |
| 2.2 | **CloneGuard rules** (20 line rules + scopes) | Regexes port 1:1 into a RepoGate pack; adopt its `scope` + `suppresses` fields into RepoGate's rule schema (small engine change) | 0.5 d |
| 2.3 | **repo-guard modules** | `vscode_scanner` + `hook_scanner` → RepoGate structural checks (RepoGate has regex-level versions; these are structured parsers — strictly better); `ioc_extractor` → new RepoGate module (URLs/domains/crypto addrs/base64 inventory in reports); `trust_score` → extend the GitHub-API stage (suspended contributors, force-push signals). Python→Python, MIT | 1.5–2 d |
| 2.4 | **GuardDog metadata detectors (local subset)** | Port `typosquatting` (with 1.2 data), `direct_url_dependency`, `bundled_binary`, `metadata_mismatch` (manifest vs tree). Defer the history-dependent ones (`new_install_script`, `provenance_regression`, `risky_new_dependency`, email-domain pair) to a later "registry mode" — they need version history a repo scan doesn't have | 1–2 d |
| 2.5 | **SkillSpector YARA** (20 rules + malware set) | Same transpiler as 2.1 (regex-extractable subset); DRL attribution headers preserved in the generated pack's metadata | 0.5 d |

### Phase 3 — Port selectively, later · ~4–6 days, optional
| # | Component | Work | Effort |
|---|---|---|---|
| 3.1 | **SkillSpector pattern families** (71 patterns in ~33k LOC) | Extract per-category regex/logic into RepoGate packs category by category, FP-tuned against the Phase-1.3 corpus. Priority order: prompt_injection (6), data_exfiltration (5), supply_chain subset, tool_misuse subset. This is the long tail — the patterns are entangled with NVIDIA's AST/taint machinery, so it's re-implementation guided by their regexes, not extraction | 3–5 d |
| 3.2 | **SkillSpector taint chains** (`behavioral_taint_tracking.py`) | RepoGate's chains are category co-occurrence; real source→sink taint is an engine upgrade. Independent of the merge question; schedule as RepoGate roadmap, using their chain definitions as the spec | (roadmap) |
| 3.3 | GuardDog history-dependent metadata detectors | Only with a registry/version-history mode | (deferred) |

### Skip (no effort)
ScanRepo engine + scam DB · Sigil lolbin pack (GPL) · Sigil `api/` + threat_signatures.json · Sigil Rust engine code (behavior already absorbed) · SkillSpector LLM stage + Semgrep glue · GuardDog evals dataset (external) · repo-guard IOC_FEED data (1 replicated entry — take the format only, 0 effort, fold into 2.3's IOC module as an empty starter file).

### What this does to the Python/Rust question
The merge makes the language question mostly moot: **the merged assets are language-agnostic data** (JSON packs, YARA-derived regex packs, JSON reference lists, fixture trees) that load identically from Python today or Rust tomorrow. The only code-level ports (Phases 2.3, 2.4) are Python→Python because both source and target are Python. If RepoGate later goes Rust, Phases 1–2 assets carry over untouched and only RepoGate's own engine (~1 file) is rewritten — the merge *reduces* the cost of a future Rust port instead of raising it. Recommendation: merge in Python now; revisit Rust after the rule corpus stabilizes.

---

## 7. Verification notes

- All license claims were read from the live repos on 2026-11-20 (GitHub API `license.spdx_id` + raw LICENSE file heads), not from the earlier audits.
- Counts are from the actual trees on 2026-11-20: GuardDog 55 `.yar` files / 55 `rule` declarations / 2,354 lines; Sigil 19 core pack files with per-file rule counts summed from the JSON; SkillSpector 15 `static_patterns_*.py` modules / 32,950 lines and 33 `tests/fixtures/**/SKILL.md`; CloneGuard 20 `id:` entries in `rules.go`; repo-guard module byte sizes from the Contents API; repo-guard `IOC_FEED.md` read in full (1 entry).
- GuardDog fixture sourcing caveat (`.gitattributes`: `/tests export-ignore`) verified in the extracted tree.
- Sigil GPL finding is documented by Sigil itself in `packs/lolbin/v1/NOTICE.md` (read in full) — including their reasoning that distilled regex signatures are treated as derivative of the GPL corpora.
- SkillSpector DRL-1.1 derivation is declared in the YARA files' own headers (read directly: `webshells.yar`, and `malware.yar.b64` after base64 decode).
