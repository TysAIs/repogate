# RepoGate v2 — Unified Architecture

**Date:** 2026-11-20 · **Status:** Design only (no product code) · **Inputs:** `repogate.py` v0.1.0,
`docs/DESIGN.md`, `research/tool-audit-nvidia-datadog.md`, `research/tool-audit-specialized.md`,
`research/best-practices-2026.md`

**The founding demand:** "one big thing, not just an aggregator." This document designs RepoGate as a
**platform** — a small, stable core (acquisition → inventory → normalized views → analyzers →
correlation → scoring → policy → reporting) where everything that changes fast (rules, IOCs,
language analyzers, upstream detections) is **data or a plugin**, and everything that must never
change silently (the verdict contract, the gate semantics, the offline guarantee) is **core**.

The aggregator failure mode is a script with 200 regexes pasted from six tools. The platform
alternative has exactly three load-bearing ideas:

1. **Scan and gate are separate programs.** Scanning produces findings (facts about content,
   cached by content hash). Gating applies a policy to findings *for a specific intended action*.
   SkillSpector, GuardDog, CloneGuard, Sigil, repo-guard, and ScanRepo all fuse these into one
   score; that is why none of them can answer the only question an agent actually has:
   *"I am about to do X with this repo — is that OK?"* (§4)
2. **Rules are a portable data format (RRF), not code.** One YAML schema expresses regex,
   structural, AST, and metadata-diff detections, and ships with converters from Semgrep, YARA,
   and GuardDog formats. The converters — not copy-paste — are the merge vehicle for upstream
   detection corpora (§3).
3. **Every stage boundary is a versioned, JSON-serializable intermediate representation (IR).**
   That is what makes the engine decomposable, testable, and progressively replaceable —
   including by Rust components — without touching the CLI or the verdict contract (§2).

## 0. What does not change (the contract)

These v1 properties are frozen. Any v2+ component that violates one is defective by definition:

| Contract | v1 form | v2 form |
|---|---|---|
| Never executes scanned code | design invariant | invariant + enforced by analyzer sandboxing (§2.5) |
| Quarantine-first acquisition | temp dir, tarball via API | content-addressed snapshot store (§2.2) |
| Clean = "nothing found", never "safe" | printed in report | printed in every renderer, incl. SARIF + MCP |
| Deterministic verdict path | no LLM anywhere | no LLM in scan or gate; optional advisory annotations live outside both (§5.2) |
| Coverage accounting | scanned/partial/skipped counts | per-file coverage states in the Inventory IR; INCONCLUSIVE semantics kept (§2.3) |
| Exit codes | 0 CLEAN / 1 REVIEW·INCONCLUSIVE / 2 BLOCK / 3 error | kept for the default action (`install`); per-action exits via `--action` (§4.5) |
| Local-only | no network except target fetch | offline is a tested guarantee, not a promise (§6.3) |
| Zero-dependency core | Python stdlib only | core stays stdlib-only; heavy engines (Semgrep, YARA) are optional out-of-process plugins (§2.5) |

## 1. Design principles

1. **Facts before verdicts.** Analyzers emit findings with evidence. Scoring weighs them. Policy
   decides. No analyzer may emit a verdict; no policy rule may invent a finding.
2. **Two-axis findings.** Every rule is typed `capability`, `threat`, or `context` (GuardDog v3's
   one genuinely better idea). Correlation (§2.6) — not raw pattern count — produces chains.
3. **Data over code.** If a detection can be expressed in RRF, it must be. Hand-coded checks
   (v1's `check_package_json` etc.) are a backlog of un-converted rules, not a pattern to repeat.
4. **Confess, don't exclude.** Any content the engine cannot inspect is enumerated in the
   Inventory IR with a reason and caps the verdict (Checkmarx/SkillSpector excluded-path lesson).
5. **The target is hostile to the scanner.** Archives, parsers, and analyzers treat input as an
   attack on RepoGate itself (GuardDog's Landlock/Seatbelt lesson; crafted-ZIP rejection).
6. **Approvals bind to content hashes and actions.** Approving `install` of tree-hash X approves
   nothing about tree-hash Y, and nothing about action `run` (Sigil's trust ledger, hardened
   against the Air Security rug-pull class).
7. **Boring core, exciting edges.** The core changes slowly and is heavily golden-tested. Rules,
   feeds, and analyzers change daily and are independently versioned and signed (§6).

---

## 2. Engine decomposition

### 2.1 Component diagram

```
                          ┌────────────────────────────────────────────────────┐
   target spec            │                    repogate core                    │
  (dir | archive |        │                                                    │
   github URL |           │  ┌───────────┐   Snapshot    ┌───────────────┐    │
   registry pkg) ───────► │  │ ACQUIRE   │──IR──────────►│ INVENTORY     │    │
                          │  │ providers │  repogate.    │ classify, hash│    │
                          │  └───────────┘  snapshot/1   │ coverage state│    │
                          │        ▲                     └──────┬────────┘    │
                          │        │ offline gate               │ Inventory │
                          │        │ (no-egress)                │ IR        │
                          │  ┌─────┴─────┐   Views     ┌────────▼────────┐    │
                          │  │ NORMALIZE │──IR────────►│ ANALYZERS       │    │
                          │  │ raw/fold/ │  repogate.  │ regex-pack      │    │
                          │  │ decode/   │  views/1    │ structural      │    │
                          │  │ unicode   │             │ AST (py, js…)   │    │
                          │  └───────────┘             │ manifests       │    │
                          │        ┌───────────────────│ metadata/diff   │    │
                          │        │ plugin protocol   │ ioc match       │    │
                          │        │ (JSONL, §2.5)     │ binary/artifact │    │
                          │   ┌────▼─────┐             └────────┬────────┘    │
                          │   │ external │                      │ Findings  │
                          │   │ analyzers│                      │ IR        │
                          │   │ semgrep/ │             ┌────────▼────────┐    │
                          │   │ yara/…   │             │ CORRELATE       │    │
                          │   └──────────┘             │ chain engine    │    │
                          │                            └────────┬────────┘    │
                          │                            ┌────────▼────────┐    │
                          │                            │ SCORE           │    │
                          │                            │ weighted, capped│    │
                          │                            └────────┬────────┘    │
                          └─────────────────────────────────────┬───────────────┘
                                                                │ Findings IR
                          ┌─────────────────────────────────────▼───────────────┐
   action intent ───────► │  GATE (policy layer, §4)                            │
   (clone|open|install|   │  findings × action × policy profile × trust ledger  │
    run|import-skill)     │  → per-action decision + verdict ladder             │
                          └─────────────────────────────────────┬───────────────┘
                                                                │ Report IR
                          ┌─────────────────────────────────────▼───────────────┐
                          │  REPORT: text · JSON · SARIF · MCP result           │
                          └─────────────────────────────────────────────────────┘
```

Everything left of the Gate is **the scanner** (pure function of content). Everything from the
Gate right is **the decision** (function of content × intent × policy). The scanner's output is
cacheable forever by content hash; the gate is re-evaluated per action at zero rescan cost.

### 2.2 Stage contracts

**Acquire** — one provider per target kind, all producing the same output: an immutable
**Snapshot** in a content-addressed store (`~/.cache/repogate/snapshots/<tree-sha256>/`).

- Providers: `local-dir`, `archive` (zip/tar with v1's path-escape checks + ratio/member caps),
  `github-tarball` (API, never `git clone`), `github-api-metadata` (metadata-only snapshot for
  the `inspect` action — repo-guard's zero-footprint stage), `registry` (npm/PyPI/crates:
  **wheels/tarballs only, never build an sdist pre-scan** — Sigil's 1.3.7 lesson, as a rule of
  the provider, not a hope).
- A Snapshot is: the extracted tree (symlinks recorded, never materialized outside the tree),
  plus `snapshot.json`: target spec, resolved commit/version, per-file sha256, tree hash,
  acquisition timestamp, provider, and the pack/feed versions the snapshot was first scanned
  with. The tree hash is the identity everything else keys on: scan cache, baselines, ledger.
- Acquisition is the *only* stage allowed network access, and only to the target's own host
  (plus opt-in lookups, §6.3). In `--offline` mode only `local-dir`/`archive` providers load.

**Inventory** — walks the Snapshot once and classifies every entry (v1 `classify()` categories,
extended): `code:<lang>`, `doc`, `config`, `manifest:<ecosystem>`, `bytecode`, `binary`,
`archive` (nested — unpacked one level into the inventory, or marked uninspected), `symlink`,
`other`. Each entry carries a **coverage state**: `pending → scanned | partial | uninspected`,
with a machine-readable reason (`oversize-head-tail`, `binary`, `nested-archive-depth`,
`unsupported-format`, `parse-error`). Inventory is where "confess, don't exclude" is enforced:
analyzers may only downgrade a state to `scanned`/`partial` by actually processing the file.

**Normalize** — produces, per text file, the named **views** analyzers match against:
`raw`, `folded` (v1 `normalize()`: literal-concat constant folding), `decoded:<n>` (base64/hex/
Tags-block decode-and-rescan layers, v1 `decoded_variants()`, depth-capped at 2), `unicode`
(NFKC + confusable skeleton + Tags-decoded, for agent-text rules), `lines` (per-line geometry:
length, leading/trailing space runs — the Contagious Interview whitespace checks become view
metadata instead of a special-case pass). Views are derived data: regenerable from the Snapshot,
never stored long-term, and every finding records which view produced it (evidence provenance —
v1 already tags `[normalized]`/`[decoded]`; v2 makes it structural).

**Analyzers** — see §2.4/§2.5. Input: Inventory + Views + Snapshot metadata. Output: findings
only. Analyzers are pure, parallelizable per file, and individually disable-able.

**Correlate** — the chain engine. Chains are **data** (§3.5), evaluated over the finding graph:
nodes are findings; edges are scope relations (`same-file`, `same-package`, `reachable-from:
<entrypoint>`, `same-workflow`). Output: chain findings (axis `chain`) with member finding IDs.
This generalizes v1's `run_chains()` (seven hand-coded category-pair checks) into pack-defined
chains, and adds the scope v1 lacks: entrypoint reachability (a stealer in `scripts/postinstall.js`
is not the same as one in `examples/demo.js`).

**Score** — v1's model kept initially (severity weights info 1 / low 3 / medium 8 / high 20 /
critical 45, per-category cap 60, chains uncapped, clamp 100) because the fixture corpus is
calibrated against it. The Scoring stage is versioned (`scoring: 1`) and the Report IR records
which scoring version produced a number, so the planned move to GuardDog-style four-factor
transparent scoring (severity / specificity / sophistication / chain completeness) is a scoring
v2 rollout with an eval-corpus comparison, not a silent behavior change.

**Gate** — §4. **Report** — §2.7.

### 2.3 Intermediate representations (the real API)

IRs are JSON documents with a `schema` field (`"repogate.findings/1"` etc.). They are the
contract between stages, between languages, and between the CLI and every integration surface
(MCP, CI, shims all consume Findings/Report IRs — none re-implements scanning).

**Findings IR** (extends v1's `Finding` dataclass; new fields marked `+`):

```json
{
  "schema": "repogate.findings/1",
  "snapshot": {"tree_hash": "sha256:…", "target": "github.com/owner/repo", "commit": "…"},
  "engine": {"version": "2.0.0", "packs": {"core": "1.4.0", "agent": "0.9.1"}, "scoring": 1},
  "coverage": {"files_total": 812, "scanned": 790, "partial": 9, "uninspected": 13,
               "uninspected_reasons": {"binary": 11, "oversize-head-tail": 2}},
  "findings": [{
    "id": "f_01J…",                      "rule_id": "core/cred-env-serialize",
    "rule_version": 3,                   "pack": "core",
    "category": "credential-access",     "axis": "threat",
    "severity": "high",                  "confidence": "high",
    "path": "scripts/setup.js",          "line": 14, "view": "folded",
    "evidence": "JSON.stringify(process.env)",   "evidence_sha256": "…",
    "note": "Bulk environment serialization",
    "actions": ["install", "run", "import-skill"],
    "triggered_by": "install",
    "chain_ids": [],                     "dampeners": [],
    "fingerprint": "sha256:…"            
  }],
  "chains": [{"id": "c_01J…", "chain_id": "core/chain-stealer", "severity": "critical",
              "scope": "same-file", "members": ["f_01J…", "f_01K…"], "path": "scripts/setup.js"}]
}
```

`fingerprint` (hash of rule id + normalized evidence + path) is what baselines and the trust
ledger key on — Sigil/SkillSpector baseline semantics, made content-based rather than
line-number-based so unrelated edits don't resurrect suppressed findings.

### 2.4 Built-in analyzers (in-core, stdlib-only)

| Analyzer | v1 origin | v2 change |
|---|---|---|
| `regex-pack` | `apply_rules()` + `ALL_RULES` | rules loaded from RRF packs (§3); matches over named views |
| `structural` | `STRUCTURAL` dispatch + `check_*` functions | checks re-expressed as RRF `structural` rules over parsed manifests (§3.3); the Python functions are deleted as each manifest type converts |
| `manifests` | `check_package_json` dep logic | one parser per ecosystem (npm, PyPI, Cargo, Go, RubyGems) emitting a normalized `Manifest` IR (deps, scripts/hooks, entrypoints) consumed by structural + metadata analyzers |
| `ast-python` | — (new) | stdlib `ast`: call-graph-lite for exec/eval/getattr-reflection, import-time execution (RG-HOOK-004), taint-lite source→sink within a function |
| `ast-js` | — (new) | tree-sitter if present, else a token-level fallback analyzer; reflective-call and fetch→exec shapes |
| `agent-text` | prompt-injection regex rules | operates on the `unicode` view of docs/SKILL.md/MCP manifests; declared-vs-actual diffing (frontmatter purpose vs body capabilities — SkillSpector LP/TP idea) |
| `metadata` | `acquire()` GitHub `trust` dict | repo/package/maintainer signals + **diff detectors** (needs two snapshots or registry history, §3.4) |
| `ioc` | — (new) | matches deps, domains, URLs, hashes against the local IOC DB (§6.2) |
| `binary` | `struct-binary-present` | magic-byte typing, nested-archive inventory, bytecode presence (SkillSpector SC8 semantics) |
| `ci` | `check_workflow` | workflow YAML parsed structurally; zizmor-class checks as RRF structural rules (§3.3) |

### 2.5 External analyzers (plugin protocol) — the engine-level merge vehicle

Some upstream value is an *engine*, not rules (Semgrep's taint tracking, YARA's byte matching).
Vendoring that code is a license and maintenance trap (§7.2). Instead: **any executable that
speaks the analyzer protocol is an analyzer.**

- Transport: the core spawns the analyzer with a JSONL stream on stdin: one
  `{"type":"file","path":…,"views":{…}}` message per file (or `{"type":"snapshot",…}` for
  whole-tree analyzers), reads `{"type":"finding",…}` messages on stdout. A manifest
  (`analyzer.toml`: name, version, capabilities, required views, license) declares the contract.
- Shipped plugin wrappers (optional installs, never required for a core scan): `semgrep`
  (runs a converted ruleset with real Semgrep semantics where RRF's AST subset is insufficient),
  `yara` (runs YARA rule files directly), `osv` (live OSV.dev lookup when `--online-lookups`).
- Plugins run **sandboxed by default**: no network, read-only snapshot access, CPU/time budget,
  findings capped and schema-validated on ingest. A plugin crash degrades coverage
  (`uninspected: analyzer-error`) — it never fails the scan open.
- This is also the Rust on-ramp: a Rust analyzer is just a plugin that happens to be fast,
  until/if it is promoted in-core (§2.8).

### 2.6 Correlation and entrypoints

The Inventory marks **entrypoints**: files an action can cause to execute or be loaded —
lifecycle hook targets, `main`/`bin` fields, editor task commands, workflow files, SKILL.md and
the scripts it references, MCP server entrypoints, `__init__.py` of the top package, `build.rs`,
devcontainer commands. Chains evaluate scope against entrypoints:

- `same-file` — v1 semantics, strongest.
- `reachable-from-entrypoint` — the two findings are in files connected by import/include/
  reference edges from one entrypoint (import graph built by the AST/manifest analyzers).
- `same-package` — v1 package-wide semantics, weakest; chain severity downgraded one band
  (GuardDog's cross-file downgrade rule).

### 2.7 Reporting

One **Report IR** (`repogate.report/1`): the Findings IR + gate decision(s) + coverage +
provenance (engine/pack/feed versions, scoring version, snapshot hash, timestamps). Renderers
are dumb formatters over it: `text` (v1 format, kept), `json` (the IR itself), `sarif`
(SARIF 2.1.0 for GitHub code scanning — rules become `reportingDescriptors`, chains become
`codeFlows`-annotated results, fingerprints become `partialFingerprints`), `md` (PR-comment
summary). No renderer may add, drop, or re-severity a finding.

### 2.8 Progressive replacement, including Rust

The migration is a strangler process guarded by **golden tests**: the eval corpus (§7.4) plus
v1's fixtures must produce identical Findings IRs (modulo IR version) before and after each
extraction. Order of operations:

| Step | Move | Guard |
|---|---|---|
| 1 | Extract rules from `repogate.py` into `packs/core/*.yaml`; monolith loads them | fixture verdicts byte-identical |
| 2 | Split monolith into the `repogate/` package along stage lines (§7.3); `repogate.py` becomes a 20-line compat shim | golden corpus |
| 3 | Freeze IR schemas at `/1`; all integrations consume IRs | schema tests |
| 4 | First Rust component: `repogate-inventory` (walk + hash + classify — CPU-bound, zero logic risk) as a plugin-protocol process, then in-core via the same IR | differential run vs Python on the full corpus: IR diff must be empty |
| 5 | Rust `repogate-regex` (pack runner over views) — the hot loop on large trees | differential + benchmark gate (≥5× on the 8,705-file corpus class) |
| 6 | Scoring/correlation stay Python until their semantics settle (they are policy-adjacent and change with research); revisit at v3 | — |

Rule for promotion: a component is rewritten in Rust only when (a) its IR contract has been
stable for a full minor release, and (b) profiling shows it in the top-2 hot spots. Everything
else stays Python — portability (DESIGN invariant 4) beats uniformity.

---

## 3. The rule-pack format (RRF) — the merge vehicle

### 3.1 Survey: how the incumbents express rules

| | Semgrep | YARA | GuardDog v3 | OPA / Rego | SkillSpector |
|---|---|---|---|---|---|
| Form | YAML per rule | text files | YARA (source) + **Python code** (metadata) | Rego policy modules | Python code + pattern catalog |
| Match power | AST patterns, metavariables, boolean composition (`patterns:`/`pattern-either:`/`pattern-not:`), **taint mode** (sources/sinks/sanitizers) | literals, regex, hex strings; boolean/count conditions over matches | YARA for code; arbitrary Python for metadata/history | arbitrary logic over JSON input | regex + AST + taint + YARA, all in code |
| Scope | per-language, file | file bytes | file (YARA) / registry metadata (code) | any JSON | skill tree |
| Cross-file / chains | no (taint is intra-file) | no | **yes — in the risk engine, not the rules** | yes (it's a policy engine) | partial (taint) |
| Metadata carried | severity, CWE/OWASP, confidence, likelihood/impact | free-form `meta:` | capability/threat typing by convention | n/a | category, score weight |
| Weakness for us | needs the Semgrep engine (heavy, non-stdlib); LGPL ecosystem licensing care (§7.2) | no structure, no manifests, no diffs | two disjoint formats; metadata detectors are un-auditable code | wrong layer for pattern rules; a second runtime to ship | not data at all — nothing is importable without running their code |

**Conclusions.** (1) No incumbent format covers all four detection shapes RepoGate needs
(regex, structural, AST, metadata-diff) — that gap is precisely why v1 has hand-coded `check_*`
functions, and why "merge" has so far meant copy-paste. (2) Semgrep's YAML ergonomics and
YARA's string/condition model are the two worth being *convertible from*. (3) OPA is the right
shape for the **gate** layer (§4.4), not for pattern rules. (4) GuardDog's capability/threat
typing must be a first-class field, because correlation depends on it.

### 3.2 RRF schema (`pack_format: 1`)

A pack is a directory of YAML files plus `pack.yaml`. YAML is parsed with a stdlib-only
restricted loader in the core (packs are data, and data must not require a dependency — the
loader accepts the YAML subset RRF uses; full YAML is a plugin-side concern).

```yaml
# packs/core/pack.yaml
pack_format: 1
pack:
  name: core
  version: 1.4.0
  license: MIT
  min_engine: ">=1.1.0"
  description: Lifecycle hooks, credential access, exfil, execution, obfuscation, supply chain.
  signature: "minisig:…"          # §6.1; absent in a working tree, required in a release
```

```yaml
# one rule (schema sketch; fields marked * are required)
rules:
  - id*: core/cred-env-serialize        # <pack>/<slug>, globally unique, never reused
    version*: 3                          # bump on any semantic change; baselines key on it
    title*: Bulk environment serialization
    severity*: high                      # info|low|medium|high|critical
    category*: credential-access
    axis*: threat                        # capability|threat|context
    confidence: high                     # rule precision estimate; feeds scoring v2
    attack: [T1552.001]                  # optional ATT&CK mapping
    actions*: [install, run, import-skill]   # actions this finding is relevant to (§4.2)
    triggered_by*: install               # earliest action that activates the surface
    match*: { …one of the four kinds, §3.3… }
    unless:                                # dampeners (best-practices §4.4), each logged
      - path-in: [test/**, fixtures/**]    #   when applied
      - literal-only-args: true
    message*: "Serializes the entire process environment — the shape of secret harvesting."
    remediation: "Read individual variables by name."
    references: [https://…]
    source:                                # provenance, mandatory for converted rules (§7.2)
      upstream: DataDog/guarddog
      upstream_rule: npm-serialize-environment
      license: Apache-2.0
      url: https://github.com/DataDog/guarddog/blob/v3/RULES.md
      converted: 2026-11-20
    tests*:                                # rules ship their own tests (CloneGuard lesson)
      - {given: "const e = JSON.stringify(process.env)", expect: match}
      - {given: "const e = JSON.stringify(process.env.NODE_ENV)", expect: no-match}
```

Non-negotiables: every rule has tests; every converted rule has `source:`; `id` and `version`
are immutable once released (a changed detection is a version bump, so baselines and ledger
entries can reason about exactly what changed).

### 3.3 The four match kinds

**`regex`** — over named views, with YARA-style match logic:

```yaml
    match:
      kind: regex
      views: [folded, decoded]           # never raw-only for keyword rules (§5 evasions)
      languages: [javascript, typescript] # optional; omit = all text files
      paths: {include: ["**/*.js"], exclude: ["**/*.min.js"]}
      any: ["…", "…"]                    # any | all | at_least: n
```

**`structural`** — assertions over a *parsed* document. This kind deletes v1's `check_*`
functions: the manifest/workflow/config parsers produce documents; rules assert over paths in
them (`jsonpath`-lite: dotted keys + `[]` wildcard + key-regex).

```yaml
    match:
      kind: structural
      document: vscode-tasks             # package.json | vscode-tasks | gh-workflow |
                                         # devcontainer | claude-settings | pyproject | …
      where:
        - path: "tasks[].runOptions.runOn"
          equals: "folderOpen"
        - path: "tasks[].command"
          matches: "(curl|wget|powershell|bash|sh)\\b"
```

**`ast`** — a deliberate subset: Semgrep-style `pattern:` with metavariables for the common
shapes (call, attribute, import), compilable to the Python `ast` analyzer, the JS token
analyzer, or a tree-sitter query. Anything outside the subset is flagged by the converter as
`needs-plugin: semgrep` rather than silently weakened.

```yaml
    match:
      kind: ast
      language: python
      pattern: |
        getattr($OBJ, $NAME)(...)
      where:
        - metavar: $NAME
          in: ["system", "popen", "exec", "eval"]
```

**`metadata`** — assertions over repo/package/maintainer metadata, including **diffs** between
two snapshots (or a snapshot and registry history). The detector vocabulary is a finite,
parameterized set — this is how GuardDog's Python-code detectors become auditable data:

```yaml
    match:
      kind: metadata
      subject: package                   # repo | package | maintainer
      diff:
        field: "manifest.scripts"        # normalized Manifest IR path
        change: key-appeared             # key-appeared|value-changed|value-removed|appeared
        key_regex: "^(pre|post)?install$|^prepare$"
        baseline: registry-history       # registry-history | previous-snapshot
```

Plus **`ioc`** as a degenerate fifth kind (list membership against the IOC DB) — expressed as
data files, not rules (§6.2).

### 3.4 Converters (`repogate rules convert`)

| From | Mapping | Lossy edges (must be reported, never silent) |
|---|---|---|
| Semgrep YAML | `pattern-regex:` → `regex`; single `pattern:` in subset → `ast`; `patterns:` boolean tree → nested `any/all/not` in either kind; `severity:` ERROR/WARNING/INFO → high/medium/low; `metadata.category` → `category` seed | taint mode → chain definition (§3.5) + `needs-plugin: semgrep` for full fidelity; metavariable-regex constraints outside subset → manual queue |
| YARA | literal/regex strings → `regex` kind (`strings:` become `any:` entries); hex strings → `regex` over a `bytes` view (core) or `needs-plugin: yara`; `condition:` `any/all/N of them` → match logic; `meta:` → fields | offset/offset-arithmetic conditions (`$a at 0`, `uint16(0)==0x5A4D`) → plugin; file-size conditions → `structural` on Inventory |
| GuardDog | its YARA rules → YARA path above, with `axis` set from RULES.md's capability/threat tables; its metadata detectors → `metadata` kind templates (the 11 detectors in audit §2.3 map to the finite vocabulary in §3.3) | detectors using live registry state (maintainer-domain status) → `metadata` with `requires: online-lookups` |
| SkillSpector | no machine format exists — conversion is **manual, one pattern at a time**, into RRF with `source:` attribution; the taxonomy (17 categories) is adopted as RRF category seeds for the `agent` pack | its LLM-stage detections (e.g. TP4 description–behavior mismatch) are **not convertible** — recorded in the pack as `advisory-only` notes, never as rules |

Every conversion run emits a **conversion report**: converted / converted-with-loss / rejected,
with reasons. A rule that cannot be converted faithfully is rejected, not approximated —
a weakened rule that keeps the upstream name is worse than no rule (it manufactures confidence).

### 3.5 Chains as data

```yaml
chains:
  - id*: core/chain-stealer
    title*: Stealer (credential access + exfiltration)
    severity*: critical
    when*:
      scope: same-file                   # same-file|reachable-from-entrypoint|same-package
      all:
        - {category: credential-access, axis: threat, min_severity: medium}
        - {category: network-exfil, axis: threat, min_severity: medium}
    downgrade_if: scope-widened          # same-package instance drops one band (§2.6)
    references: [best-practices §4.3 C1]
```

The eight canonical chains from best-practices §4.3 (Stealer, Dropper, Auto-run Dropper, Hook
Dropper, Prompt-Injection Exfil, CI Token Theft, Persistence Implant, Agent LOTL) ship as chain
definitions in `packs/core/chains.yaml`; v1's seven hand-coded chains map onto six of them
(v1 has no Agent LOTL chain — new in v2 via RG-EXEC-003 + RG-CRED rules).

### 3.6 Worked conversions

*Source renderings below are faithful reductions of the published detections (GuardDog RULES.md
catalog; SkillSpector README pattern catalog, both as verified 2026-11-20 in the audits), not
verbatim upstream source. The RRF side is complete and loadable as designed.*

**Example 1 — GuardDog `npm-serialize-environment` → RRF `regex` (threat axis).**
GuardDog's detection (Semgrep-era heuristic name; v3 ships the equivalent as a YARA threat
rule): flag bulk serialization of the whole environment — `JSON.stringify(process.env)` —
as opposed to reading one named variable.

```yaml
  - id: core/cred-env-serialize
    version: 3
    title: Bulk environment serialization
    severity: high
    category: credential-access
    axis: threat
    actions: [install, run, import-skill]
    triggered_by: install
    match:
      kind: regex
      views: [folded, decoded]
      languages: [javascript, typescript]
      any:
        - 'JSON\.stringify\(\s*process\.env\s*\)'
        - 'Object\.assign\(\s*\{\s*\}\s*,\s*process\.env\s*\)'
        - 'structuredClone\(\s*process\.env\s*\)'
    unless:
      - path-in: [test/**, fixtures/**, examples/**]
    message: "Serializes the entire process environment — the shape of secret harvesting
      (GuardDog npm-serialize-environment)."
    source: {upstream: DataDog/guarddog, upstream_rule: npm-serialize-environment,
             license: Apache-2.0, converted: 2026-11-20}
    tests:
      - {given: "body: JSON.stringify(process.env)", expect: match}
      - {given: "const env = {...process.env}", expect: match}   # via folded-view variant rule below
      - {given: "JSON.stringify(process.env.NODE_ENV)", expect: no-match}
```
(The spread form `{...process.env}` is a sibling rule in the same file — RRF prefers two
precise rules over one clever regex; the converter emits both from the one upstream heuristic
and links them with `related:`.)

**Example 2 — SkillSpector AST9, reflective `getattr` sink → RRF `ast`.**
SkillSpector's Behavioral-AST category added AST9 after Checkmarx showed
`getattr(os, "system")(cmd)` evading name-based AST checks in static-only mode. In RRF this is
a pattern rule, not code — and because it is data, the JS analogue ships in the same pack
release (`Reflect.get` / bracket-access forms):

```yaml
  - id: core/exec-reflective-getattr
    version: 1
    title: Reflective call to a dangerous sink
    severity: high
    category: execution
    axis: capability
    actions: [install, run]
    triggered_by: install
    match:
      kind: ast
      language: python
      pattern: |
        getattr($OBJ, $NAME)(...)
      where:
        - metavar: $NAME
          in: [system, popen, exec, eval, __import__]
    message: "Calls a dangerous function reflectively, by name — the shape that evaded
      name-based AST scanning (SkillSpector AST9 class)."
    source: {upstream: NVIDIA/SkillSpector, upstream_rule: "AST9 reflective getattr sink",
             license: Apache-2.0, converted: 2026-11-20}
    tests:
      - {given: "getattr(os, 'system')(cmd)", expect: match}
      - {given: "getattr(obj, 'render')(x)", expect: no-match}
```

**Example 3 — GuardDog metadata detector "new install script" → RRF `metadata` (diff).**
GuardDog's most original detector class is not a code pattern at all: an install script
*appearing* in a package version that previously had none is a takeover/rug-pull signal
(audit §2.3). As Python code in GuardDog it is un-auditable; as RRF it is five lines, and the
same definition works for PyPI (`setup.py`/`pyproject` hooks) and Cargo (`build.rs` appeared)
via the normalized Manifest IR:

```yaml
  - id: core/meta-new-install-script
    version: 2
    title: Install script appeared where none existed
    severity: critical
    category: supply-chain
    axis: context
    actions: [install]
    triggered_by: install
    match:
      kind: metadata
      subject: package
      diff:
        field: "manifest.lifecycle_hooks"
        change: appeared                 # was empty/absent in baseline, non-empty now
        baseline: registry-history
    message: "This version introduces an install-time hook; every previous version had none.
      First-appearance hooks are a documented account-takeover pattern."
    source: {upstream: DataDog/guarddog, upstream_rule: "new-install-script metadata detector",
             license: Apache-2.0, converted: 2026-11-20}
    tests:
      - {given: "baseline hooks=[] ; current hooks=[postinstall]", expect: match}
      - {given: "baseline hooks=[prepare] ; current hooks=[prepare]", expect: no-match}
```

**Example 4 (compact) — SkillSpector SC8, shipped bytecode → RRF `structural`.**
SC8 flags the *presence* of shipped `.pyc` (HIGH in skills) because bytecode content is
unanalyzable by source scanners (Trail of Bits bypass). No pattern is needed — the Inventory
already knows:

```yaml
  - id: agent/bytecode-shipped
    version: 1
    severity: high            # in the agent pack; core pack carries the same rule at medium
    category: obfuscation
    axis: context
    actions: [import-skill, install, run]
    triggered_by: import-skill
    match:
      kind: structural
      document: inventory
      where:
        - path: "files[].class"
          equals: "bytecode"
    message: "Compiled bytecode shipped in the tree; its content cannot be source-scanned."
    source: {upstream: NVIDIA/SkillSpector, upstream_rule: SC8, license: Apache-2.0,
             converted: 2026-11-20}
```

---

## 4. Action-aware gating — the feature package scanners don't have

### 4.1 The insight

Every scanner in the audits answers "is this artifact bad?" with one number. But risk is not a
property of the artifact; it is a property of **(artifact × action)**. A repo with a malicious
`postinstall` is harmless to *clone* and dangerous to *install*. A skill with a prompt-injection
payload is inert as bytes on disk and live the moment an agent *imports* it. World-bat is
dangerous to *open in an editor* and does nothing if never opened. One verdict for all four
moments is simultaneously too strict (blocks legitimate cloning for inspection) and too lax
(a CAUTION that an agent reads as "proceed" right before `npm install`).

RepoGate v2 therefore makes the **gate a separate stage** (§2.1) whose inputs are the Findings
IR, the intended action, a policy profile, and the trust ledger — and whose output is a
**verdict ladder**: the decision for the requested action plus the decisions for every other
action, so an agent can degrade gracefully ("install is blocked; clone-and-read is allowed")
instead of facing a binary wall.

### 4.2 The action ladder

Actions are ordered by the execution/trust surface they activate. Performing an action exposes
every surface at or below its rung.

| # | Action | What it activates | Canonical trigger surfaces |
|---|---|---|---|
| 0 | `inspect` | nothing local — API metadata only | repo age, grafted history, maintainer signals (metadata analyzer only) |
| 1 | `clone` | bytes on disk; archive extraction in *our* tooling | crafted archives, symlink escapes, bytecode/binaries present (inventory facts, not yet risks) |
| 2 | `open` | editor/workspace machinery | `tasks.json` folderOpen, devcontainer prompts, workspace settings, `.envrc` on `cd`, agent reading SKILL.md/README as context |
| 3 | `install` | lifecycle hooks, build scripts, dependency resolution | `pre/postinstall`, `prepare`, `setup.py`, `build.rs`, Makefile targets, dependency confusion, new-hook diffs |
| 4 | `run` | the code itself, with the user's credentials and network | everything below, plus stealer/dropper chains, C2, persistence writes |
| 5 | `import-skill` | the content gains *standing instructions* to an agent, persistently, across future sessions | prompt injection, tool poisoning, excessive agency, memory poisoning, referenced scripts (which are then gated at `run`) |

`import-skill` sits at the top not because it executes code but because it is the only action
whose payload is *trusted natural language with a future* — Mini-Shai-Hulud's SessionStart
persistence and SANDWORM_MODE both live on this rung. (A deployment may reorder 4/5 via policy;
the default order is as above.)

### 4.3 Finding relevance model

Each rule declares (§3.2):

- `triggered_by` — the **earliest** action that activates the surface the rule detects.
  A folderOpen rule has `triggered_by: open`; a lifecycle-hook rule, `install`; a stealer
  chain's members, `run` (the chain itself inherits the minimum of its members).
- `actions` — the actions the finding is *relevant* to: always `triggered_by` and above.
  Below `triggered_by` the finding is reported as context but cannot influence the decision.

Gate evaluation for action *A*:

```
relevant   = findings where triggered_by ≤ A
decision(A) = BLOCK   if any relevant chain with severity ≥ profile.chains_block_at
           = BLOCK   if any relevant finding severity > profile.max_severity[A]
           = BLOCK   if weighted score over relevant findings > profile.max_score[A]
           = REVIEW  if any relevant finding severity == profile.max_severity[A]
                        or score > profile.review_above[A]
           = ALLOW   otherwise
coverage gate: if coverage < profile.require_coverage[A] and decision < BLOCK → INCONCLUSIVE
```

Worked intuition: the World-bat snapshot under the default profile yields
`inspect: REVIEW` (young grafted history), `clone: ALLOW-WITH-NOTES`,
`open: BLOCK` (folderOpen + pipe-to-shell chain, `triggered_by: open`),
`install: BLOCK` (prepare hook chain), `run: BLOCK`, `import-skill: BLOCK`.
The same scan, five different correct answers. v1 would have printed one BLOCK — right for
install, wrong for the analyst who only wanted to read the code.

### 4.4 Policy layer

Policies are data (`policy.yaml`, `policy_format: 1`), layered: built-in `default` ← user
(`~/.config/repogate/policy.yaml`) ← per-project (`.repogate/policy.yaml`, itself scanned as
content before it is honored — a hostile repo must not be able to lower its own gate) ←
explicit CLI flags.

```yaml
policy_format: 1
profile: default
actions:
  clone:        {max_score: 60, max_severity: critical, chains_block_at: null,     require_coverage: 0.80}
  open:         {max_score: 30, max_severity: high,     chains_block_at: critical, require_coverage: 0.90}
  install:      {max_score: 20, max_severity: high,     chains_block_at: high,     require_coverage: 0.95}
  run:          {max_score: 15, max_severity: medium,   chains_block_at: high,     require_coverage: 0.98}
  import-skill: {max_score: 15, max_severity: medium,   chains_block_at: high,     require_coverage: 0.98,
                 packs_required: [core, agent]}
overrides:
  ledger: ~/.local/share/repogate/ledger.jsonl   # §4.5
  allow_rule_suppression: false                  # suppressions come from baselines, not policy
```

For organizations, an optional **Rego backend** (OPA as a plugin analyzer of the gate stage)
can replace the YAML evaluator: input is the Findings IR + action, output is the decision.
The YAML evaluator remains the reference implementation; Rego is for shops that already run
OPA. The decision semantics above are the contract either way.

### 4.5 Trust ledger and approvals

Sigil's ledger, hardened per the rug-pull research:

- An approval is a record `{tree_hash, action, rule_ids waived | "all", approver, timestamp,
  expiry, note}` appended to an append-only local ledger. It authorizes **that action on that
  exact tree** — nothing else. A changed tree (new commit, re-pointed tag, mutated registry
  tarball) has a different hash and needs a new approval; `repogate diff` shows what changed
  since the approved snapshot (this is also the MCP `tools/list_changed` rug-pull answer for
  skills: re-gate on definition-hash change).
- Approvals for `run`/`import-skill` default to 30-day expiry; `clone`/`open` approvals do not
  expire (the surfaces are weaker and re-prompting trains users to rubber-stamp).
- Baselines (finding suppressions, §3.2 fingerprints) are distinct from approvals: a baseline
  says "this finding is known and accepted *in this repo*"; it is version-bound to the rule
  version, so a rule upgrade re-surfaces it (SkillSpector semantics). The scanner never
  auto-baselines a critical finding or a chain.

### 4.6 CLI surface

```
repogate scan  <target> [--packs …] [--offline] [--json out] [--sarif out]
repogate gate  <target> --action install            # decision for one action
repogate gate  <target>                              # the full verdict ladder
repogate approve <target> --action install --note "reviewed postinstall, it only runs tsc"
repogate diff  <target-a> <target-b>                 # snapshot diff (rug-pull / update review)
```

Exit codes: `gate --action A` exits with A's decision mapped to the v1 ladder
(ALLOW 0, ALLOW-WITH-NOTES 0, REVIEW/INCONCLUSIVE 1, BLOCK 2, error 3), preserving v1's
contract for the default action. Bare `scan` exits 0 whenever the scan itself succeeded —
scanning is not gating, and conflating them is v1's one contract wart (kept in v1.x for
compatibility, corrected in v2 with a `--fail-on` compatibility flag).

---

## 5. Agent-native integration

### 5.1 SKILL.md contract (v2)

The skill is the distribution form agents actually consume, so it is specified like an API:

- **Frontmatter:** `name: repogate`; a `description` that states trigger conditions in the
  imperative-free, descriptive register RG-AGENT rules require (the skill must pass its own
  `agent` pack — enforced in CI, §7.5); `allowed-tools` scoped to exactly: read files, run the
  `repogate` binary, write reports to a named output dir. No network tools, no generic shell.
- **Body contract** (what the skill instructs the hosting agent to do):
  1. Before any clone/install/open/run/import of third-party content, run
     `repogate gate <target> --action <the action you are about to take>`.
  2. Present the verdict ladder verbatim-ish; never summarize a BLOCK as "some concerns".
  3. On BLOCK: stop, show the chain(s) and evidence, offer the lower rungs that are allowed.
  4. On REVIEW/INCONCLUSIVE: read the flagged files yourself, then re-present; never
     self-approve above `clone` — approvals are the user's, recorded via `repogate approve`.
  5. Say "nothing found", never "safe" (v1 wording rule, kept).
- **Install targets** (one canonical `SKILL.md`, thin shims per host): Hermes
  (`~/.hermes/skills/repogate/`), Muse (`~/.claude/skills/repogate/`), and a generic
  `AGENTS.md` snippet for other hosts. Shims differ only in install path and the host's
  tool-name mapping; a conformance test renders each shim and diffs the contract section.

### 5.2 MCP server mode (`repogate mcp`)

For agents that consume tools rather than skills, the same engine is exposed over MCP (stdio
by default; no network listener unless `--transport http` with an explicit bind):

| Tool | Input | Output | Notes |
|---|---|---|---|
| `scan_target` | target spec, packs? | Findings IR (or a handle to it) | never returns raw file contents |
| `gate_action` | target spec **or** scan handle, action | decision + ladder + top evidence | the primary tool; agents call this pre-action |
| `explain_finding` | finding id | rule message, remediation, chain membership | evidence excerpts capped at 200 chars, unicode-escaped |
| `diff_snapshots` | two targets/hashes | changed files + finding delta | rug-pull / update review |
| `list_packs` | — | installed pack/feed versions + staleness | makes §6 staleness visible to the agent |

Poison-resistance requirements (the server is itself an MCP surface and is held to RG-AGENT
rules): tool descriptions are descriptive, not imperative; scanned content is **never**
returned as free text an agent might obey — findings carry rule-authored messages, and
evidence excerpts are escaped and fenced as data; the server exposes no write/execute tools;
an optional advisory LLM annotation (SkillSpector-style stage 2) may be attached to a report
as `annotations` — it is outside the Findings IR, cannot alter severities, and is labelled
non-deterministic in the output.

### 5.3 CI mode

- `--sarif report.sarif` emits SARIF 2.1.0 (§2.7) → GitHub code scanning; chains surface as
  results with `properties.chain`, member findings linked via `codeFlows`.
- A first-party GitHub Action (`TysAIs/repogate/action.yml` in the release repo) wraps the CLI:
  inputs `target`, `action` (default `install`), `baseline`, `fail-on` (default `block`).
  PR mode: scan the PR head snapshot, diff findings against the base snapshot's baseline,
  fail only on **new** BLOCKs (diff-mode default, best-practices §4.4.3) and post the `md`
  renderer output as a PR comment.
- Determinism is a CI feature: same snapshot + same pack versions ⇒ byte-identical Findings
  IR (GuardDog v3.2.0's deterministic-order fix, adopted as a tested property — findings are
  sorted by (path, line, rule_id) at emission).

### 5.4 Pre-clone interception (the shim layer)

Three interception points, in increasing strength:

1. **`git` shim** — `repogate shim install` places a `git` wrapper earlier in `PATH`. It
   intercepts only `git clone <url>`: runs `gate --action clone` (and pre-computes the
   `install` decision so the user sees the ladder before the bytes land), then either execs
   the real `git clone` or stops with the report path. All other subcommands pass through
   untouched. Bypass: `REPOGATE_BYPASS=1` — honored, but the bypass is *logged to the ledger*
   (Sigil's escape hatch, with the audit trail Sigil leaves implicit).
2. **Agent hooks** — a Claude Code `PreToolUse` hook and a Hermes equivalent that match
   `git clone`, `npm install`, `pip install`, `curl … | sh` in the agent's own tool calls and
   route them through `gate` with the matching action. This is Sigil's plugin pattern,
   generalized from clone-only to the full action ladder.
3. **Package-manager wrappers** (v3, §8) — `npm`/`pip` shims that gate `install` on the
   *resolved dependency set* (metadata analyzer + IOC), closing the gap where the repo was
   clean but a dependency is not.

The shim layer never silently rewrites commands: it allows, blocks with a report, or stands
aside (non-clone commands, bypass). Anything smarter becomes a man-in-the-middle users learn
to disable.

---

## 6. Update & trust

### 6.1 Signed, versioned packs

Rules and IOC data change faster than the engine and ship separately:

- A pack release is a tarball: `pack.yaml` + rule files + a `MANIFEST.sha256` over every file,
  signed with **minisign** (Ed25519; chosen over Sigstore/cosign because verification is
  fully offline and dependency-free — no identity infrastructure, no transparency-log
  round-trip at verify time). The release public key is published in the repo, in the SKILL.md,
  and in release notes; key rotation is a signed-by-old-key announcement pack.
- The engine verifies signature + manifest before loading any pack not in a source checkout.
  Local/working-tree packs load with `trust: local` in the report provenance; downloaded packs
  that fail verification are refused, and the refusal is a hard error (exit 3), not a warning.
- `pack_format` is versioned independently of the engine: an engine refuses a pack whose
  `pack_format` major exceeds its own, and a pack declares `min_engine` (§3.2).
- Engine releases pin **known-good pack versions** (a lockfile in the release), so a fresh
  install is reproducible; `repogate update` moves the pin deliberately, never silently.

### 6.2 IOC feed

- Contents: known-bad packages (name + version ranges, distilled from OSV `MAL-*`), known-bad
  domains/URLs (ScanRepo-style scam DB, community-contributed with maintainer review),
  known-bad file hashes, typosquat watchlist seeds.
- Format: JSONL files in `packs/ioc/`, versioned and signed with the same mechanism as packs,
  with per-entry `source` + `first_seen` (an IOC without provenance is not accepted).
- Matching is local against the downloaded feed. Live OSV lookup is an opt-in plugin (§2.5)
  for freshness-critical gates, never a default — defaults must work on a plane.

### 6.3 Offline guarantees and telemetry

- **Telemetry: none.** No analytics, no scan reporting, no update checks in the background.
  This is a stated feature (the anti-ScanRepo clause from DESIGN): what you scan is nobody's
  business, and for a security tool the claim must be verifiable — the offline test (below)
  plus a `NETWORK.md` documenting every code path that can open a socket (acquisition
  providers, the OSV plugin, `repogate update`) and how each is disabled.
- `--offline` is a hard mode, not a hint: acquisition providers that need network are not
  loaded; lookups are skipped; the report header prints pack/feed ages
  (`rules core@1.4.0 (2026-11-18) · ioc@2026.11.15 — 5 days old`) so staleness is a visible
  property of every verdict rather than a silent decay.
- **Egress test in CI:** the test suite runs a full scan of the local corpus inside a network
  namespace with no route out; any attempted connection fails the build. Offline-ness is
  thereby a regression-tested property, on the same footing as the fixture verdicts.

---

## 7. Open-source release: layout, merge plan, contribution model

### 7.1 Repository layout

```
repogate/
├── README.md  SKILL.md  LICENSE  SECURITY.md  CONTRIBUTING.md  CODEOWNERS  NETWORK.md
├── repogate.py                  # v1 compat shim (20 lines → repogate.cli) until v3
├── repogate/                    # Python package (the core)
│   ├── cli.py  gate_cli.py  mcp_server.py  shim.py  update.py
│   ├── acquire/      github.py  archive.py  local.py  registry.py  api_metadata.py
│   ├── inventory/    walk.py  classify.py  magic.py
│   ├── normalize/    views.py  folding.py  decoding.py  unicode.py
│   ├── analyzers/    regex_pack.py  structural.py  manifests/  ast_python.py
│   │                 ast_js.py  agent_text.py  metadata.py  ioc.py  binary.py
│   ├── plugins/      protocol.py  semgrep.py  yara.py  osv.py
│   ├── correlate/    chains.py  graph.py
│   ├── score/        scoring_v1.py
│   ├── policy/       evaluate.py  policy_yaml.py  ledger.py  baseline.py
│   └── report/       ir.py  text.py  json.py  sarif.py  md.py
├── packs/
│   ├── core/         pack.yaml  *.yaml  chains.yaml        # converted v1 rules + §3.6
│   ├── agent/        pack.yaml  *.yaml                     # SKILL/MCP/agent-text rules
│   ├── ci/           pack.yaml  *.yaml                     # workflow structural rules
│   └── ioc/          packages.jsonl  domains.jsonl  hashes.jsonl  MANIFEST.sha256
├── third_party/                 # §7.2 — provenance, not a code dump
│   ├── guarddog/     UPSTREAM.md  converted/  (RRF output of the converter, with source:)
│   ├── skillspector/ UPSTREAM.md  converted/
│   ├── semgrep-rules/ UPSTREAM.md  converted/  LICENSE-note
│   └── yara/         UPSTREAM.md  converted/
├── crates/                      # Rust workspace (populated per §2.8, steps 4–5)
│   ├── repogate-inventory/
│   └── repogate-regex/
├── eval/
│   ├── corpus/       benign/  malicious/  skills-benign/  skills-malicious/  evasions/
│   ├── expectations.yaml        # per-sample: expected chains, max allowed verdict per action
│   └── run_eval.py              # FP/FN report; budgets enforced in CI
├── fixtures/                    # v1 fixtures, kept verbatim (golden compatibility)
├── tests/          unit/  golden/  integration/  offline/ (network-namespace egress test)
├── docs/           DESIGN.md  architecture.md (this doc, promoted)  rule-format.md
│                   policy.md  threat-model.md  merge-log.md
└── .github/workflows/  ci.yml (tests + eval gate)  dogfood.yml (§7.5)  release.yml (signing)
```

`rules/` and `src/` (empty placeholder dirs in v1) are removed; their intent is realized by
`packs/` and `repogate/` respectively.

### 7.2 The merge plan — three legal/technical routes, kept separate

The owner's "take the code from all of them, merge them into one" decomposes into three routes.
Conflating them is how projects inherit license contamination and unmaintainable vendored code.

| Route | What moves | Applies to | Conditions |
|---|---|---|---|
| **A. Convert detections (data)** | rules/patterns/detectors re-expressed in RRF via §3.4 converters | GuardDog (Apache-2.0), SkillSpector (Apache-2.0), CloneGuard (MIT), repo-guard (MIT), zizmor-class CI checks, best-practices RG-* taxonomy | every converted rule carries `source:` (upstream, rule id, license, URL, date); `third_party/<x>/UPSTREAM.md` records the upstream commit the conversion was made from; NOTICE file aggregates attributions |
| **B. Wrap engines (plugins)** | nothing copied; the upstream engine runs as a §2.5 plugin | Semgrep (engine LGPL-2.1 — run, don't embed), YARA (BSD-3; plugin keeps the boundary clean anyway), OSV.dev (API) | plugin is optional; core scan is complete without it; plugin manifest declares its own license |
| **C. Vendor code (rare)** | actual source files copied into `third_party/` with their LICENSE intact | only small, permissively-licensed, high-value units (e.g. a self-contained Go heuristic from CloneGuard, if ever needed) | license must be MIT/Apache-2.0/BSD; per-directory LICENSE + UPSTREAM.md with commit pin; vendored code is *not* edited in place — changes go upstream or into a wrapper |

Explicit non-route: **Sigil and ScanRepo contribute ideas, not artifacts** — Sigil's workflow
design (Apache-2.0 code, but a Rust codebase with no separable detection corpus worth
vendoring) and ScanRepo (engine closed/unlocated per the audit; its scam DB is data under its
own terms — mirrored only via the IOC contribution process with provenance, §6.2). Semgrep's
*community rules* are LGPL-licensed: Route A conversion of individual rules proceeds only for
rules whose license posture is confirmed, recorded per-rule in `source.license`, with the
`semgrep-rules` UPSTREAM.md carrying the caveat — when in doubt, the rule is re-derived from
the underlying technique (documented in best-practices) rather than converted.

`docs/merge-log.md` is the running ledger: every upstream absorption, its route, its license,
its date. If it isn't in the merge log, it isn't in the product.

### 7.3 Contribution model (rules-first)

The project's center of gravity is the packs, so contribution is optimized for rule authors:

- A rule PR = one YAML rule + its inline `tests:` + (for conversions) the `source:` block.
  CI runs: schema validation, the rule's own tests, the full eval corpus, and a **false-positive
  budget check** (below). No engine change is needed for the overwhelming majority of
  contributions — that is the platform payoff.
- Review bar: critical-severity rules and new chain definitions require two maintainer
  reviews and a corpus sample demonstrating the detection. New categories require an
  architecture note (categories are taxonomy, and taxonomy is forever).
- Deprecation: a rule is never deleted in a minor pack release; it is marked
  `deprecated: true` with a pointer, and removed in the next major pack version, so baselines
  referencing it degrade loudly instead of silently.
- DCO sign-off on commits; SECURITY.md defines disclosure for *scanner bypasses* as security
  issues (a bypass of RepoGate is a vulnerability in RepoGate — the Checkmarx precedent
  applies to us).

### 7.4 Eval corpus — the platform's immune system

- **Composition:** benign (popular real repos/skills, snapshotted at pinned commits — the FP
  side is as important as the FN side; SkillSpector's "arsenic" 100/100 is the cautionary
  tale), malicious (OSV `MAL-*` samples, Contagious Interview lures, SANDWORM_MODE-style
  skills — stored defanged: payloads neutralized to inert markers that still match the
  *detection shapes*, so the corpus is safe to clone), evasions (one directory per published
  bypass class: excluded-path hiding, bytecode, whitespace truncation, Tags-block smuggling,
  string-split, LLM-targeting comments — each named after its source writeup).
- **Expectations:** per sample, the expected chains and the *maximum allowed verdict per
  action* (a benign repo may REVIEW for `run` but must ALLOW `clone`/`open`).
- **Budgets, enforced in CI:** 0 benign samples BLOCKed at their expected actions; 100% of
  malicious samples BLOCKed at `triggered_by` action and above; every evasion sample detected
  by at least one rule or explicitly listed as a known gap in `eval/known-gaps.md` (a gap is
  allowed; a *silent* gap is not).
- Rule or engine changes that move any corpus verdict require the eval diff in the PR
  description. This is what lets the engine be refactored — and partially rewritten in Rust —
  without fear.

### 7.5 Dogfooding

RepoGate's own repo is scanned in CI (`dogfood.yml`): the `agent` pack over its own SKILL.md
and docs (a scanner's repo is full of attack strings as signatures/tests — the dampener rules
of best-practices §4.4.1 exist precisely for this, and their application is printed, not
hidden), the `core` pack over its own tree at action `install`, and the offline egress test.
A release cannot ship with the dogfood gate red.

---

## 8. Phased roadmap

### v1.1 — "Same scanner, honest structure" (no verdict changes)

1. Rules extracted from `repogate.py` into `packs/core/*.yaml` (RRF schema + stdlib YAML-subset
   loader); structural checks remain Python but are registered as analyzers.
2. SARIF renderer; `--format` flag; findings sorted deterministically.
3. Baseline support (fingerprint files) + `repogate baseline` command.
4. `--action` flag: static relevance filtering using each rule's `actions`/`triggered_by`
   (hand-annotated during extraction) — the policy layer in embryo, default profile only.
5. Eval corpus v0: v1 fixtures + 10 benign + 10 malicious samples, expectations, CI gate.
   *Acceptance:* fixture + corpus verdicts identical to v0.1.0 except where an eval expectation
   documents a deliberate change.

### v2.0 — "The platform"

1. Package decomposition per §7.1; IR schemas frozen at `/1`; `repogate.py` shim.
2. Gate stage: policy YAML, verdict ladder output, trust ledger + `approve`/`diff` commands.
3. Chain definitions as data (`chains.yaml`); entrypoint/reachability scopes in correlation.
4. AST analyzers (Python in-core; JS token-level), metadata diff detectors (registry-history
   baseline), IOC analyzer + first signed IOC feed.
5. Converters: `rules convert --from semgrep|yara|guarddog` + conversion reports; the
   GuardDog/SkillSpector conversions land in `third_party/*/converted/` and, after review,
   in `packs/core` + `packs/agent`.
6. MCP server mode; SKILL.md v2 + Hermes/Claude shims; git shim + agent PreToolUse hooks.
7. Signed pack releases + `repogate update`; offline egress test in CI.
   *Acceptance:* the §4.3 World-bat ladder reproduces on the corpus sample; a third party can
   add a working rule by PR without touching Python; MCP `gate_action` round-trips the CLI's
   decision on the whole corpus.

### v3 — "Depth and speed"

1. Rust `repogate-inventory` + `repogate-regex` behind the IR (§2.8), differential-tested.
2. Scoring v2 (four-factor transparent model) rolled out behind `scoring: 2` with a published
   corpus comparison against scoring v1.
3. Registry metadata analyzers at full strength (maintainer-domain status, provenance
   regression, tarball↔repo integrity), package-manager shims (npm/pip) gating resolved dep
   sets, optional Semgrep/YARA plugin analyzers shipped and signed.
4. Org policy: Rego backend for the gate; shared baseline/ledger distribution for teams.
   *Acceptance:* Rust components byte-identical on the corpus at ≥5× throughput on large
   trees; scoring v2 shows no corpus regressions vs v1 budgets.

---

## 9. Non-goals and risks

**Non-goals.** Runtime/dynamic analysis (a sandbox detonation tier contradicts the
never-execute invariant; if it ever exists it is a separate product, not a RepoGate mode).
A hosted scanning service (ScanRepo's model; violates local-only). An LLM verdict (advisory
annotations only, §5.2). A general-purpose SAST tool (RepoGate detects *malice shapes and
agent surfaces*, not ordinary vulnerabilities — CVE detection enters only via IOC/OSV data).

**Risks, stated plainly.**

- *RRF expressiveness creep.* Every "just one more match feature" pushes RRF toward being a
  programming language. Mitigation: the subset rule — if it needs control flow, it is a plugin
  analyzer, not a rule.
- *Conversion fidelity.* A converted rule that silently weakens the upstream detection is a
  false-confidence machine. Mitigation: conversion reports, `needs-plugin` honesty, per-rule
  tests derived from upstream examples (§3.4).
- *Policy complexity.* Five actions × profiles × ledger could confuse the agents it serves.
  Mitigation: the ladder output is the UX — one line per action, decision + first reason —
  and the default profile is the only one most users will ever meet.
- *Feed trust.* Signed packs move the trust problem to key custody. Mitigation: minisign key
  in cold storage, rotation procedure (§6.1), and the engine's refusal to load unsigned
  downloaded packs.
- *The corpus is the ceiling.* Detection quality will never exceed eval-corpus coverage;
  budget maintainer time for corpus growth ahead of rule growth (§7.4).

---

## Appendix A — v1 → v2 function map (for the engineer starting the extraction)

| v1 (`repogate.py`) | v2 home |
|---|---|
| `acquire()`, `safe_extract_*()`, `GITHUB_RE` | `acquire/` providers → Snapshot |
| `classify()`, `read_for_scan()`, walk in `scan_tree()` | `inventory/` + Inventory IR (coverage states) |
| `normalize()`, `decoded_variants()`, `decode_tags_block()` | `normalize/` → named views |
| `RULES`, `EXTRA_RULES`, `R()` | `packs/core/*.yaml` (RRF `regex`) |
| `STRUCTURAL`, `check_*()` | RRF `structural` rules + `analyzers/manifests/` parsers |
| `apply_rules()` | `analyzers/regex_pack.py` |
| `run_chains()` | `packs/core/chains.yaml` + `correlate/` |
| `score_and_verdict()` | `score/scoring_v1.py` (weights unchanged) + `policy/` (verdict moves to the gate) |
| `render_text()`, JSON dump in `main()` | `report/` renderers over Report IR |
| `trust` dict in `acquire()` | `analyzers/metadata.py` (context axis; never gate-moving alone) |
| `main()` exit-code map | `cli.py` + `gate_cli.py` (§4.6 compatibility rules) |

## Appendix B — Provenance of this design

Every load-bearing claim above traces to the Nov 20, 2026 audits: SkillSpector's taxonomy,
coverage accounting, and its three published bypass classes (Checkmarx, Trail of Bits, Air
Security); GuardDog v3's capability×threat correlation, metadata-diff detectors, sandboxed
scanning, and deterministic ordering; CloneGuard's rule format and exit-code ladder; Sigil's
quarantine/trust-ledger workflow, evidence gating, and PreToolUse interception (plus its
v1.3.7 execution-hole disclosure as the registry-provider rule); repo-guard's API-first stage
and trust signals; ScanRepo's tarball acquisition, coverage honesty, and — by counterexample —
its hosted, publishes-by-default model. The RG-* rule taxonomy, eight canonical chains, and
dampener model are from `research/best-practices-2026.md` §3–§5.
