# Tool Audit — NVIDIA SkillSpector & DataDog GuardDog

**Date of verification:** 2026-11-20 (all live checks performed this date)
**Method:** Source verification only — GitHub repo/release/commit pages, official NVIDIA docs, Datadog Security Labs, PyPI, and named third-party research. Neither tool was installed or run.
**Freshness rule applied:** Claims are judged against sources from the past ~2 months where possible; anything older or superseded is flagged **stale**.

**Headline:** The summary the owner received is unusually accurate on SkillSpector (the eye-catching "~27k stars" is literally true today) and mostly accurate on GuardDog, with two material corrections: (1) GuardDog's "Semgrep" era is over — v3 (June 2026) is YARA-only, so "YARA/Semgrep-style" is half-stale; (2) GuardDog's release cadence has gone quiet — latest release is v3.2.0 from **2026-08-12**, over 3 months ago, even though automated commits continue. SkillSpector's Checkmarx blind-spot claim is true and, if anything, understated — there are at least three independent bypass research efforts, not one.

---

## 1. NVIDIA SkillSpector

### 1.1 Fact sheet (live, 2026-11-20)

| Field | Value | Source |
|---|---|---|
| Repo | https://github.com/NVIDIA/SkillSpector | GitHub repo page, crawled 2026-11-20 |
| Exists / owner | Yes, official `NVIDIA` org, public, not a fork, not archived | Same |
| Stars / forks / watchers | **27,006 stars / 2,401 forks / 97 watchers** | Same |
| Created | 2026-03-21 | Same |
| Commits | 3,109 on `main`; current commit `48e0f942ea1f5fdb7aa096a6f65a0adeda2ecc4e` | Same |
| Last push | 2026-11-19 ("yesterday") | Harness Hub project page, checked against GitHub 2026-11-20: https://www.harness-hub.org/projects/skillspector |
| Latest release | **v2.13.6, published 2026-11-16T21:16:12Z** (maintenance release; 12 releases in the last 90 days) | GitHub releases: https://github.com/NVIDIA/SkillSpector/releases ; release signal: https://www.onlylabs.fyi/signals/3fa970d2-3290-4161-8eb0-84cd1a97b3fe |
| License | Apache-2.0 | Repo page |
| Language / runtime | Python ≥3.12, <3.16 (prebuilt YARA wheels only for 3.12/3.13; 3.14/3.15 need a native build) | README, repo page |
| Distribution | GitHub releases (wheel + sdist) and `uv tool install git+https://github.com/NVIDIA/skillspector.git`; current workflow explicitly does **not** publish to PyPI | Release notes for v2.13.3–v2.13.6 |

### 1.2 Claims table

| # | Claim (as received) | Verdict | Evidence + URL + date |
|---|---|---|---|
| S1 | Official NVIDIA scanner | **True** | Repo lives in the `NVIDIA` org; README: "SkillSpector is part of the NVIDIA Verified Skills pipeline." https://github.com/NVIDIA/SkillSpector (2026-11-20) |
| S2 | ~27k stars | **True** (exact, today) | 27,006 stars on the live repo page, 2026-11-20. Note the growth curve is extreme: 17,905 on 2026-09-20 (GitHub API-verified gist), 23,960 in early-Nov comparisons, 27,006 today — any star count older than ~2 weeks is already stale. Same URL |
| S3 | Very active, releases into late 2026 | **True** | Latest release v2.13.6 on 2026-11-16; v2.13.5 also 2026-11-16; v2.13.4 on 2026-11-04; last push 2026-11-19; 12 releases in 90 days. https://github.com/NVIDIA/SkillSpector/releases (2026-11-20) |
| S4 | Detects vulnerabilities, malicious patterns, prompt injection, data exfiltration, supply-chain risks in AI agent skills (Claude Code, Codex, MCP) | **True** | Repo tagline + README pattern catalog: 71 patterns / 17 categories including Prompt Injection, Data Exfiltration, Supply Chain, MCP Least Privilege, MCP Tool Poisoning. https://github.com/NVIDIA/SkillSpector (2026-11-20) |
| S5 | Accepts Git repos, URLs, zips, directories | **True** (understated) | README: "Multi-format input: Scan Git repos, URLs, zip files, directories, or single files" — also `.skill`/archive members, MCP Registry snapshots, and recursive collections of skills. Same URL |
| S6 | Part of NVIDIA's Verified Skills pipeline | **True** | README Overview: pipeline "scans, evaluates, and signs agent skills before publication" to the NVIDIA skills catalog; SkillSpector is also the security tier inside SkillEvaluator. Same URL; hosted docs: https://docs.nvidia.com/skills/scanning-agent-skills |
| S7 | Checkmarx research noted a "Safe" verdict does not always mean safe; known blind spots | **True** (and broader than stated) | Checkmarx Zero, published 2026-11-11: three concrete bypasses against versions through 2.2.3 (see §1.5). https://checkmarx.com/zero-post/nvidia-skillspector-safe-verdicts-dont-mean-the-skill-is-safe/ . Plus Trail of Bits (2026-06-03) and Air Security (2026-06-22) bypasses summarised by CSA/OWASP (see §1.5) |
| S8 | (Implied by older coverage still circulating) 64 patterns / 16 categories | **Stale** | That was the mid-2026 count. Current README says **71 patterns / 17 categories**; NVIDIA's own hosted docs page still says 68/17 — NVIDIA's docs disagree with each other, README is newest. https://github.com/NVIDIA/SkillSpector vs https://docs.nvidia.com/skills/scanning-agent-skills (both read 2026-11-20) |

### 1.3 What it actually detects (from its own README, 2026-11-20)

71 patterns across 17 categories. Category sizes: Prompt Injection (6: instruction override, hidden instructions, exfiltration commands, behavior manipulation, harmful content, whitespace padding), Anti-Refusal (3), Data Exfiltration (5: external transmission, env harvesting, FS enumeration, context leakage, cloud-storage exfil), Privilege Escalation (3), Supply Chain (10+: unpinned deps, `curl|bash`, obfuscation, live OSV.dev CVE lookup (SC4), abandoned deps, typosquatting, **shipped Python bytecode (SC8)**, concealed executable artifacts (SC9), dependency source redirection (SC10)), Excessive Agency (5), Output Handling (3), System Prompt Leakage (3), Memory Poisoning (3), Tool Misuse (3), Rogue Agent (2: self-modification, cron/startup persistence), Trigger Abuse (3), Behavioral AST (9: exec/eval/`__import__`/subprocess/`os.system`/compile/dynamic getattr/dangerous chains/**reflective `getattr(os,'system')` sink AST9**), Taint Tracking (5: source→sink flows incl. credential→network, file→network, external-input→exec), YARA Signatures (4: malware, webshell, cryptominer, hack tool), MCP Least Privilege (4: declared-vs-actual capability diffing), MCP Tool Poisoning (4: hidden instructions in metadata, unicode/homoglyph deception, parameter-description injection, description–behavior mismatch (LLM-powered TP4)).

**Pipeline:** Stage 1 static (regex + Python AST + taint + YARA + OSV lookups; self-described "high recall, moderate precision"). Stage 2 optional LLM semantic analysis (discovery + meta-analyzer passes; confirmed findings can gain confidence, deterministic findings are never deleted, unconfirmed ones are tagged `llm-unconfirmed`). LLM stage supports OpenAI/Anthropic/Bedrock/Gemini/Azure/Ollama/any OpenAI-compatible endpoint, plus local CLI providers; default provider is NVIDIA Build.

### 1.4 How it runs

- **Install:** `uv tool install --python 3.13 git+https://github.com/NVIDIA/skillspector.git` (add `[mcp]` extra for the MCP server), or clone + `make install`, or build the bundled Docker image (python:3.12-slim). No PyPI publication for current releases.
- **Inputs:** local dir, single `SKILL.md`/file, Git URL, zip/archive, URL, MCP Registry snapshot; `--recursive` collection scanning (default cap 32 skills); opt-in `--inspect-dependencies` fetches locked npm tarballs, verifies SHA-512 integrity, and inspects them in a disposable seccomp-isolated Linux worker without executing them.
- **Ingest safety limits:** 100 MiB per-ingest cap, 10,000 zip-member cap, 1 MB per-file analysis cap; breaches fail closed.
- **Outputs:** terminal, JSON, Markdown, SARIF 2.1.0. Risk score 0–100 (CRITICAL +50, HIGH +25, MEDIUM +10, LOW +5; 1.3× multiplier if executable scripts present) → 0–20 SAFE, 21–50 CAUTION, 51+ DO_NOT_INSTALL.
- **Exit codes (documented contract):** `0` = completed and score ≤50 with no strict gate fired; `1` = score >50, or `--fail-on-findings` / `--fail-on-incomplete` / `--min-coverage` tripped; `2` = error/bad input. Note the default collapses SAFE and CAUTION into exit 0.
- **Baseline system:** `skillspector baseline` snapshots accepted findings (fingerprint- or glob-based, version-bound); re-scans surface only new findings.
- **Trust model (its own words):** "defense-in-depth, not a sandbox"; it never executes the scanned skill; with LLM on, analyzer-eligible file contents are sent to the configured provider (use `--no-llm` to keep contents local); SC4 sends dependency coordinates to OSV.dev even in `--no-llm` mode.

### 1.5 Known limitations and critiques (concrete)

**Checkmarx Zero (2026-11-11, researcher Alon Lerner; tested through v2.2.3; NVIDIA closed the reports as outside its threat model):** https://checkmarx.com/zero-post/nvidia-skillspector-safe-verdicts-dont-mean-the-skill-is-safe/

1. **LLM non-determinism.** Byte-identical skill scored 6/100 SAFE in one run and 32/100 CAUTION one minute later. CI gates keyed on the verdict can pass and fail the same artifact on different runs.
2. **Excluded-path hiding (complete bypass of both stages).** The file walker explicitly excludes dotfiles (e.g. `.envrc`) and vendored dirs (`node_modules`, `venv`). A payload in `node_modules/devtools-core/index.js` was never opened by any analyzer, scored 6/100 SAFE, and executed at runtime when the agent loaded the skill's Node code.
3. **Reflective-call obfuscation vs the static stage.** `getattr(os, "system")(cmd)` evaded name-based AST detection and scored 13/100 SAFE in static-only mode. The LLM stage caught it (84/100, DO_NOT_INSTALL). NVIDIA later added AST9 (reflective getattr sink) — Checkmarx notes this appears fixed as of v2.5.0 — so this specific hole is closed, but the class lesson stands: **static-only mode is materially weaker**, and NVIDIA's current SC8 rule likewise only *flags the presence* of shipped `.pyc` bytecode (HIGH) — discovery still skips it, so bytecode content itself is not analyzed.

**Trail of Bits, "The Sorry State of Skill Distribution" (2026-06-03), via CSA research note (2026-06-10) and OWASP Agentic Skills Top 10 AST08:** https://labs.cloudsecurityalliance.org/research/csa-research-note-ai-agent-skill-scanner-bypass-20260610-csa/

4. **Whitespace/context truncation.** ~100,000 leading newlines pushed the payload past scanner context limits (SkillSpector now has an explicit P9 whitespace-padding pattern and bounded-parsing diagnostics, but its own release notes through v2.13.6 repeatedly concede parser/coverage limits remain).
5. **Precompiled bytecode.** Env-var exfiltration hidden in a `.pyc` next to a benign skill went unscanned by source-focused scanners; SkillSpector's README still lists "Encrypted/binary code: Cannot analyze compiled or encrypted content" under Limitations.
6. **Document-archive indirection.** Malicious instructions inside a `.docx` (a ZIP of XML) — partially mitigated since (SC9 concealed-executable + bounded TAR/ZIP/Office inspection), with omissions explicitly reported as incomplete rather than silently passed.
7. **LLM-judge manipulation.** Persuasive prose ("corporate standards", "VPN access") talked LLM scanner layers into rating a malicious npm-registry redirect benign; conversely, explanatory comments talked a judge into rating a legitimate `LD_PRELOAD` shim LOW — the judge can be social-engineered in both directions.

**Air Security (2026-06-22), via OWASP AST08:**

8. **External-content rug pull.** A skill whose payload lived at an external documentation URL — content scanners never fetch — was vetted safe by Cisco's, NVIDIA's, and skills.sh's scanners; the attacker-controlled page later switched to malicious install instructions. A point-in-time scan cannot see mutable remote content. (SkillSpector's newer MCP-registry snapshot *comparison* mode is a partial answer for registry entries, not for arbitrary URLs a skill references.)

**False-positive critiques (independent hands-on tests):**

9. **Keyword rules fire on benign prose.** A November 2026 head-to-head run (SkillSpector 2.12.0, 22 real workspace skills) produced a 100/100 DO_NOT_INSTALL driven by the word "arsenic" in a protein-powder ad example (harmful-content pattern), flagged "always respond" in a cold-email framework as anti-refusal, and yielded 60 combined findings across two scanners with exactly one actionable item (an unpinned `npx` package). https://mlh.forem.wtf/vestival/i-ran-two-skill-scanners-on-my-own-agent-skills-one-said-do-not-install-59hk
10. **Score collapses signal.** A Towards Data Science audit (2026) found ~80% of static findings on a legitimate GitHub-automation skill were the skill doing its advertised job (16/20 findings were GitHub API calls), and the single 0–100 integer hid which findings mattered.
11. **Vendor-acknowledged limits (README "Limitations"):** non-English content may be missed; text in images not analyzed; no runtime/dynamic analysis; offline SC4 falls back to a small static CVE list. Release notes for v2.13.4/v2.13.6 repeat: "A warning or incomplete assessment is not proof that a skill is safe."

### 1.6 Ideas worth absorbing from SkillSpector

- **Agent-native pattern taxonomy** — prompt injection, anti-refusal, trigger abuse, memory poisoning, system-prompt leakage, excessive agency: categories no package scanner has. Steal the category system wholesale.
- **Declared-vs-actual diffing (LP1–LP4 + TP4)** — compare the manifest's stated purpose/permissions against capabilities found in code; flag both under- and over-declaration.
- **Taint chains as first-class findings** (env/file/network source → exec/network sink), not isolated pattern hits.
- **Coverage accounting** — every scan reports what was *not* inspected (excluded files, truncated files, unsupported formats), partial coverage blocks a SAFE verdict, and `--fail-on-incomplete` / `--min-coverage` make it gateable. This is the direct antidote to the Checkmarx excluded-path bypass: you may exclude, but you must confess.
- **Fail-closed ingest caps** (download size, zip members, per-file size) against zip bombs and scanner DoS.
- **Baseline/fingerprint suppression** so re-scans surface only *new* findings; baselines are version-bound so a scanner upgrade forces re-review.
- **Stable machine contract** — documented 0/1/2 exit codes, JSON schema, SARIF 2.1.0 output, and an explicit gate-mapping table (SAFE→allow, CAUTION→warn, DO_NOT_INSTALL→block).
- **Live OSV.dev lookup with offline fallback** for dependency CVEs (SC4), plus typosquat and dependency-source-redirection checks (SC6/SC10).
- **Opt-in locked-dependency inspection** — fetch the exact locked tarballs, verify integrity hashes, scan contents in an isolated worker, never execute.
- **Anti-jailbreak hardening of the LLM stage** and the rule that LLM review can annotate but never silently delete deterministic findings (`llm-unconfirmed` tagging).

---

## 2. DataDog GuardDog

### 2.1 Fact sheet (live, 2026-11-20)

| Field | Value | Source |
|---|---|---|
| Repo | https://github.com/DataDog/guarddog | GitHub repo page, crawled 2026-11-20 |
| Exists / owner | Yes, official `DataDog` org, public, not archived. **Default branch is unusually named `v3`** | Same |
| Stars / forks / watchers | **1,260 stars / 130 forks / 14 watchers** | Same |
| Created | 2022-06-14 (v0 internship project; 1.0 Feb 2023; 2.0 Aug 2024; 3.0 Jun 2026) | Same; Datadog Security Labs |
| Commits | 1,476; current commit `5da9538eb05b8c2710db60541ec9732557687f8b` | Repo page |
| Last commits | 2026-11-16 on the `v3` branch — but Nov/Oct commits are almost entirely automated dependency-vuln bumps; last substantive feature work was 2026-10-24/26 (PyPI `.pth` attack detection, npm install-script metadata detector was 2026-08-19) | https://github.com/DataDog/guarddog/commits/v3/ (2026-11-20) |
| Latest release | **v3.2.0, 2026-08-12** (66 releases / 74 tags total). No release in Sep, Oct, or Nov 2026 | PyPI release history via https://data.safetycli.com/packages/pypi/guarddog/changelog ; https://github.com/DataDog/guarddog/releases |
| License | Apache-2.0 | Repo page |
| Language / runtime | Python ≥3.10 (Poetry/uv); Windows supported only via Docker | README |

### 2.2 Claims table

| # | Claim (as received) | Verdict | Evidence + URL + date |
|---|---|---|---|
| G1 | ~1.3k stars | **True** | 1,260 stars live, 2026-11-20. https://github.com/DataDog/guarddog |
| G2 | Actively maintained, releases through 2026 | **Inflated / partially stale** | Releases through 2026 is literally true (3.0.0 Jun 23, 3.1.0 Jul 8, 3.2.0 **Aug 12, 2026**) but the latest release is 100 days old today — outside the ~2-month freshness window. Commit activity continues (2026-11-16) yet is dominated by automated vuln/dependency bumps; last feature commits late Oct 2026. Verdict: maintained, but release cadence has stalled since August. https://data.safetycli.com/packages/pypi/guarddog/changelog ; https://github.com/DataDog/guarddog/commits/v3/ (2026-11-20) |
| G3 | CLI for malicious packages across PyPI, npm, Go, Rust, RubyGems | **True** (understated, with a caveat) | Current README lists PyPI, npm, Go modules, Rust crates, RubyGems, **plus GitHub Actions and VSCode extensions**. Caveat: Rust crates support only landed in v3.2.0 (2026-08-12, PR #827) — any description of GuardDog from before August that includes Rust is wrong for its version. https://github.com/DataDog/guarddog (2026-11-20) |
| G4 | YARA/Semgrep-style rules + metadata analysis | **Half stale** | Semgrep was the v1/v2 engine. GuardDog 3.0 (2026-06-26) replaced it with a **YARA-based rules engine**; current README: "runs static analysis on package source code (through YARA rules) and analyzes package metadata." Metadata detectors are Python. Anyone describing current GuardDog as Semgrep-based is describing a superseded architecture. https://securitylabs.datadoghq.com/articles/guarddog-3-0-release/ ; https://github.com/DataDog/guarddog |
| G5 | Correlates findings into risk chains | **True** | Core v3 model: a finding is a *capability* or a *threat*; capability + threat in the same file forms a **risk** (cross-file matches form risks at downgraded severity). Score 0–10 weighted: severity 30%, attack-chain completeness (MITRE ATT&CK early→mid→late) 20%, specificity 30%, sophistication 20%. 0 = none, 0.1–3 low, 3.1–7.5 medium, 7.6–10 high ("near-certainty of compromise"). README, https://github.com/DataDog/guarddog (2026-11-20) |

### 2.3 What it actually detects (from its own RULES.md, branch `v3`, 2026-11-20)

Full catalog: https://github.com/DataDog/guarddog/blob/v3/RULES.md

- **Capability rules (11, YARA):** browser credential/cookie access, FS delete/read/write-executable, network download / LOLBAS tools (curl, wget, nc) / outbound, install hooks, scheduled-task creation, process spawn, clipboard access.
- **Threat rules — source (40+):** autostart persistence, FS destruction, sensitive-file reads, DNS exfiltration, messaging-webhook exfil (hardcoded Discord/Telegram-style tokens), sysinfo+network exfil, suspicious-domain/C2 URLs, shady links (shorteners, file-sharing), reverse shells, npm dependency confusion, npm HTTP dependencies, npm preinstall scripts, cryptomining, download-and-execute, install-hook LOLBAS, DLL/process injection, process-memory scraping, encoded PowerShell, silent process spawn, keylogging, screencapture, worm self-propagation (package rewrites its own manifest and republishes), `.pth` autostart files, and a deep obfuscation family: base64+exec, `chr()`-exec, dynamic eval over self-decoding wrappers, JS `_0x` mangling, PyArmor, steganography+exec, unicode homoglyphs, hidden code via whitespace/aliasing, log suppression, import-exec chains, setup.py-specific threats (suspicious imports, network-in-setup, import aliasing).
- **Threat rules — metadata (11, Python detectors):** typosquatting vs top packages, bundled binaries, deceptive author (disposable email), direct-URL dependencies, registry-vs-manifest metadata mismatch, **new install script appearing on a previously script-free package**, potentially compromised maintainer email domain, unclaimed maintainer email domain, **provenance regression (npm attestation disappears)**, repository integrity mismatch (package contains files not in its linked GitHub repo), risky new dependency (recursively scores newly added deps; default flag threshold 5.0).

### 2.4 How it runs

- **Install:** `uvx guarddog …` (zero-install), `uv tool install guarddog`, `pip install guarddog`, or Docker image `ghcr.io/datadog/guarddog` (only option on Windows).
- **Commands per ecosystem** (`pypi`, `npm`, `go`, `crates`, `rubygems`, `github_action`, `extension`): `scan <name|archive|dir|s3://…> [--version X] [--rules …] [--exclude-rules …]` and `verify <manifest>` (requirements.txt, package.json, go.mod, Cargo.lock, Gemfile.lock, workflow YAML) to scan every dependency in a manifest. Also `list-rules`.
- **Inputs:** registry package names (downloaded from PyPI/npmjs/crates.io/rubygems/GitHub/VSCode marketplace), local archives, local directories, S3 prefixes/objects. It is a *package* scanner — it does not scan arbitrary GitHub repos except Go modules and JS GitHub Actions that are themselves hosted on GitHub, and it has no agent-skill/prompt-injection concept.
- **Sandboxed scanning (v3 headline feature):** kernel-level sandbox via `nono` (Landlock on Linux, Seatbelt on macOS). Three phases: download + metadata run unsandboxed (need network); archive extraction runs sandboxed; YARA source analysis runs sandboxed. **Sandbox is required by default — if unavailable, the scan fails**; `--no-sandbox` is an explicit opt-out. Built to mitigate extraction-time CVEs (CVE-2022-23530/23531, CVE-2026-22870/22871). Archive limits: 2 GB max uncompressed, 100:1 max compression ratio, 100,000 max files.
- **Outputs:** human console, JSON (all commands), SARIF (**`verify` only**, for GitHub code scanning). 
- **Exit codes:** the current README publishes **no exit-code table** (unlike SkillSpector's documented contract). CI gating historically relies on the `--exit-non-zero-on-finding` flag and/or parsing JSON/SARIF; treat the exit-code surface as under-documented and verify against the installed version before wiring it into a gate.
- **Also shipped:** Datadog Agent integration + Cloud SIEM content pack; a bundled Claude skill for writing GuardDog rules (`.claude/skills/writing-guarddog-rules`); an evals suite benchmarked against Datadog's malicious-packages dataset.

### 2.5 Known limitations and critiques

1. **Not a repo scanner.** Despite appearing in "scan before you clone" roundups, GuardDog's unit of analysis is a published package in a supported registry (or a manifest of them). Pointing it at an arbitrary GitHub repo, an agent skill, or a random tarball of source only exercises a subset of rules, and all 11 metadata detectors — its most original layer — need registry metadata and version history, so local/directory scans silently lose them.
2. **YARA exclusion blind spot.** By default YARA scanning skips a long extension list (`GUARDDOG_YARA_EXT_EXCLUDE`: md, rst, txt, lock, json, yaml, yml, toml, xml, html, csv, sql, pdf, office docs, d.ts, …). Payloads living in those file types are invisible to the source-code engine — the same excluded-surface failure class Checkmarx demonstrated against SkillSpector, here by configuration.
3. **No semantic/LLM layer and no prompt-injection detection.** Pure pattern + metadata analysis: novel obfuscation that doesn't match a YARA rule, and anything malicious expressed as natural-language instructions (the entire agent-skill threat class), is out of scope by design.
4. **Correlation cuts both ways.** Requiring capability + threat co-location suppresses false positives, but a capability in one package/file and the threat indicator in another is downgraded, and metadata-only or single-stage findings cap at medium — a patient attacker who splits the chain across files/dependencies gets a structurally lower score.
5. **Fail-closed sandbox friction.** If Landlock/Seatbelt is unavailable (older kernels, some CI runners, Windows without Docker), scans error out unless the operator explicitly weakens the posture with `--no-sandbox`.
6. **Release staleness (see G2).** Rules freshness is the product in malware detection; a 100-day-old latest release with mostly automated commits since is a real caveat for a tool whose value is current attacker TTPs — even though Datadog continues to ship detection content through its commercial Agent/SIEM integration.

### 2.6 Ideas worth absorbing from GuardDog

- **Capability × threat correlation → risk chains.** The single best FP-reduction idea in either tool: never score a pattern alone; score the *combination*, mapped to MITRE ATT&CK stages (early/mid/late), with cross-file chains downgraded rather than dropped.
- **Transparent, weighted scoring.** Publish the four factors and weights (severity/specificity/sophistication/chain completeness) instead of an opaque integer — answers the "score collapses signal" critique of SkillSpector.
- **Metadata/history diffing detectors** — new install script on a previously script-free package, provenance attestation regression, registry-vs-repo integrity mismatch, compromised/unclaimed maintainer email domains, risky *new* dependency (recursive scoring of just-added deps). These catch account-takeover and rug-pull patterns that pure content scanning cannot.
- **Sandbox the scanner itself.** Scan untrusted archives as hostile input: kernel-level sandbox (Landlock/Seatbelt), privilege-split phases (network only for download), fail-closed by default, explicit opt-out flag, hard archive limits (size/ratio/file count) — plus rejecting crafted ZIPs that "scan empty but unpack code."
- **Deterministic rule execution** — v3.2.0 explicitly fixed YARA rules to run in deterministic order to avoid non-deterministic scan output; the deterministic core must be bit-for-bit reproducible (the anti-Checkmarx-Problem-1 property).
- **Ecosystem breadth via one rule model** — the same capability/threat rule catalog compiled across PyPI/npm/Go/crates/RubyGems/Actions/VSCode, with per-ecosystem applicability marked in one reference table.
- **Rules as data + a rule-writing skill** — RULES.md/WRITING_RULES.md plus a bundled agent skill for authoring new rules lowers the cost of keeping detections current.

---

## 3. Steal these ideas — consolidated list for the merged scanner

**Detection model**
1. Two-axis findings: *capabilities* and *threat indicators*, correlated into scored risk chains mapped to ATT&CK stages (GuardDog) — layered under an agent-native category taxonomy (prompt injection, anti-refusal, trigger abuse, memory poisoning, tool poisoning, excessive agency) for skill/MCP targets (SkillSpector).
2. Declared-vs-actual diffing everywhere: manifest purpose/permissions vs code capabilities (SkillSpector LP/TP), registry metadata vs package contents vs linked repo (GuardDog integrity mismatch), and version-over-version diffs (new install scripts, provenance regression, risky new dependencies).
3. Taint tracking for the classic chains: secrets/env/file → network, external input → exec.

**Trustworthiness of the verdict (the lessons of the bypass research)**
4. **Coverage accounting as a first-class output:** enumerate everything not inspected (excluded paths, binaries, oversize files, encrypted content, external URLs) and make partial coverage block a clean verdict; `--fail-on-incomplete` equivalent on by default for gates.
5. **Never silently exclude what the runtime will execute:** dotfiles, vendored dirs, `.pyc`/bytecode, archives-within-archives, and document containers are either scanned, decompiled/unpacked, or flagged as uninspected — presence of shipped bytecode is itself a finding (SkillSpector SC8/SC9).
6. **Deterministic core, advisory LLM:** the gateable verdict must be reproducible byte-for-byte; any LLM stage is a second, clearly-labelled opinion that can annotate but never silently override deterministic findings, and is itself hardened against prompt injection from the scanned content.
7. **Anti-truncation design:** chunk-and-cover whole files regardless of padding/whitespace inflation; report per-file byte coverage.
8. **Mutable-external-content handling:** record hashes of referenced external resources at scan time and support snapshot-diff re-scans (SkillSpector's MCP-registry compare) so post-approval rug pulls are detectable; a scan verdict carries the content hash it was issued for.

**Scanner self-protection**
9. Treat the target as hostile *to the scanner*: sandboxed extraction/analysis (Landlock/Seatbelt-style), privilege-split phases, fail-closed defaults, ingest caps (size, compression ratio, file/member count), crafted-archive rejection.

**Scoring & workflow**
10. Transparent weighted scoring with published factors and per-finding evidence, not a lone integer; severity bands mapped to explicit gate actions.
11. Stable automation contract: documented exit codes (0/1/2), JSON + SARIF output, `--rules`/`--exclude-rules` selection.
12. Version-bound baselines so re-scans show only new findings and scanner upgrades force re-triage.
13. Live threat data with offline grace: OSV.dev CVE lookups, typosquat lists, maintainer-domain checks — cached, with a bundled fallback.
14. Rules as versioned data with a documented authoring format (and an agent skill for writing rules), plus a public eval corpus of known-malicious and known-benign packages/skills to measure FP/FN rates before any release.

**Bottom line for the build:** SkillSpector is the real deal and current (27,006 stars verified today; v2.13.6 four days ago) — absorb its taxonomy, coverage accounting, and gate contract, but design explicitly against its three proven bypass classes (excluded paths, binary/bytecode opacity, LLM non-determinism/judge manipulation). GuardDog contributes the better *scoring* idea (capability×threat correlation) and the metadata-diffing detectors, but quote it as YARA-based v3, note Rust support is only three months old, and flag that its release cadence has been quiet since 2026-08-12.
