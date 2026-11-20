# RepoGate: Rust vs Python — feasibility deep-dive

**Date:** 2026-11-20 · **Author:** research subagent · **Scope:** research only, no product code
**Freshness:** sources from Sep–Nov 2026 preferred and dated inline; older material is flagged **[established]**.

## Verdict up front

**Ship a single static Rust binary as the product; keep the detection content as
data (YAML rule packs + YARA-X rules); keep the Python v1 as the reference
implementation and rule-prototyping harness until the Rust build reaches
fixture parity, then retire it to a dev-only role.**

Not "stay Python": The project's hard requirement is *one artifact an agent can
fetch and run with zero install* on heterogeneous hosts (Hermes fleet Linux
ARM/x86, macOS). A Python script is zero-install only where a suitable
interpreter already exists, and RepoGate's own audit trail shows where that
breaks: SkillSpector requires Python ≥3.12 and its prebuilt YARA wheels only
cover 3.12/3.13 (3.14/3.15 need a native build) — the moment a Python scanner
needs a native engine, it inherits the worst portability of both worlds
(see `tool-audit-nvidia-datadog.md`). RepoGate v1 is stdlib-only today, but
the roadmap (YARA, AST) is exactly where Python stops being portable.

Not "big-bang rewrite of everything": the genuinely hard parts in Rust are
narrow and phasable (tree-sitter grammar versioning, YAML crate churn,
hand-rolled taint if it is ever wanted). Everything RepoGate v1 actually
does — acquisition, inventory, regex rules, structural checks, normalization,
co-occurrence risk chains, scoring, reporting — ports mechanically.

One performance point is close to a correctness point: design invariant #1 is
**no excluded surfaces** (node_modules and docs are scanned, because that is
where a proven SkillSpector bypass hid). Scanning whole vendored trees with
Python `re` is slow enough that timeouts and truncation become a real risk,
and RepoGate's own rules convert partial coverage into an INCONCLUSIVE
verdict. Rust's throughput (the `regex` crate is a linear-time automaton
engine; ast-grep benchmarks ~175× Semgrep wall-clock on structural search,
codemod benchmark, Oct 2026) makes the no-exclusions invariant cheap to keep.

---

## 1. Can the whole scanner be one static Rust binary? Capability by capability

| Capability (what v1 does / roadmap needs) | Rust answer | Maturity | Cost / caveat |
|---|---|---|---|
| Regex rule engine (~90 patterns in v1) | `regex` crate (RE2-style automata) | Gold standard; the engine under ripgrep | **No lookahead, no backreferences, no atomic groups** — by design, in exchange for guaranteed linear-time matching. Measured cost to RepoGate: **3 patterns** out of ~90 use `(?!…)` and **zero rules** use backreferences (verified against `repogate.py`, 2026-11-20). All three are rewritable as match-then-post-filter in code (details below). |
| Fancy regex escape hatch | `fancy-regex` 0.20.x (hybrid: delegates to `regex` NFA, backtracks only for lookaround/backrefs) | Maintained, docs.rs current Nov 2026 | Backtracking on **attacker-controlled input text** reintroduces catastrophic-backtracking DoS risk; fancy-regex's own docs warn about exactly this. RepoGate scans hostile repos, so keep this out of the default path; if a future rule truly needs lookahead, cap input size for that rule. |
| YARA rules (GuardDog 3.x capability rules, SkillSpector signature categories) | `yara-x` (VirusTotal's Rust rewrite) | **Production-grade.** 1.0 shipped Jun 2025 **[established]**; v1.22.1 Oct 26 2026, v1.23.0 Nov 5 2026 (lib.rs / AwesomeREA, checked 2026-11-20); VirusTotal runs it in production on Livehunt/Retrohunt "scanning billions of files with tens of thousands of rules". BSD-3-Clause. | See §1.1 — high rule compatibility, new API, a few strictness fixes needed. It is a large dependency (compiler + VM + protobuf); budget binary size for it and put it behind a cargo feature. |
| AST parsing (roadmap: reflective-sink detection, structural rules) | `tree-sitter` + per-language grammar crates; or `ast-grep-core` as a library | tree-sitter is the industry default (GitHub, Zed, ast-grep, zizmor all build on it). Parsers are error-tolerant — malformed/hostile code yields `ERROR` nodes, never a failed parse — which is the right property for scanning adversarial code. | **Grammar version skew is the #1 operational hazard** (see §2). Grammars are generated C compiled via `cc`, which is where C enters the build (cross-compile story in §1.2). |
| Semgrep-style patterns | `ast-grep` (CLI + `ast-grep-core` library) | MIT, ~16.3k stars, v0.51.0 Oct 15 2026 (xerj comparison, checked Oct 2026); YAML rules with patterns + relational operators (`inside`, `has`, `follows`, `precedes`). | It is a *pattern* matcher: **no taint tracking, no dataflow, no inter-procedural analysis.** That matches RepoGate v1 (whose "chains" are co-occurrence correlation, not taint) but is a ceiling, not a floor — see §2. |
| tar / zip / gzip | `tar`, `zip`, `flate2` (with `libz-rs` or `miniz_oxide` backend = pure Rust) | Battle-tested; worked example: the `dra` GitHub-release downloader ships exactly `tar 0.4.44 + zip 6.0.0 + flate2 1.1.5 (libz-rs)` statically linked in one binary (DeepWiki dependency audit). | Path-traversal/symlink checks are RepoGate's own logic in v1 and port directly; keep the same "never trust the archive" checks rather than assuming the crates provide them. |
| HTTP for GitHub API + OSV lookups | `ureq` 3.x + `rustls` (blocking, no tokio) | The standard CLI choice: `dra` uses ureq 3.1.4 with `default-features=false, features=["rustls","json"]` explicitly "chosen over reqwest for smaller binary size and simpler synchronous API". `reqwest` 0.13.x is the fallback if async is ever needed. | rustls + `webpki-roots` keeps TLS pure-Rust → static musl builds and cross-compilation stay clean (no OpenSSL). OSV `/v1/querybatch` and the GitHub API are simple JSON POST/GET — a few hundred lines with ureq + serde_json. |
| JSON | `serde_json` | Gold standard, no caveats. | VS Code `tasks.json`/`settings.json` are **JSONC** (comments, trailing commas) — Python's `json` fails on them too (v1 emits an "unparseable" finding). The Rust build should use a JSONC-tolerant parser (`jsonc-parser` / `json5`) for editor configs; this is a strict improvement over v1. |
| YAML (workflow files, rule packs) | `serde_yaml_ng` (maintained fork) or `noyalib` / `noyalib-serde-yaml` | **Known pothole — pick deliberately.** `serde_yaml` 0.9 was archived by its author in Mar 2024 and carries RUSTSEC-2024-0449 (unsafe-libyaml); the `serde_yml` fork is itself deprecated after RUSTSEC-2025-0068 (unsoundness). As of 2026 the maintained destinations are `serde_yaml_ng` ("the most active fork", 2026 guides), `noyalib` (pure Rust, `#![forbid(unsafe_code)]`, drop-in shim available), and `serde-saphyr` (typed-only, no `Value` DOM). | RepoGate needs *locations* (line/col) in workflow findings, not just values — zizmor had to build its own `yamlpath` crate for span tracking on top of a YAML parser. Budget a thin span-preserving wrapper; do not expect serde-style deserialization alone to give finding locations. |
| Cross-compilation & static linking | `cargo-zigbuild` (zig cc as linker/C compiler) + musl targets; GitHub-hosted macOS runners for darwin | cargo-zigbuild is the community-standard answer (also used by cargo-lambda); it cross-compiles the tree-sitter C grammars as easily as pure Rust, and produces fully static musl binaries for `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` from one Linux CI job. | macOS is the exception: zigbuild *can* target darwin with an SDK, but code signing/notarization needs an Apple Developer account and `codesign` on macOS — use macos-14/15 runners for the two darwin targets. Practical mitigation: binaries fetched with `curl` don't acquire Gatekeeper quarantine (browsers/LaunchServices set it), which is why the osv-scanner/zizmor download-and-run model works unsigned in practice. |
| Binary size | — | Data points: a minimal ureq+rustls CLI is ~1.3–1.9 MB (tiny-update-check size log, Mar 2026); a dra-class tool (ureq+rustls+tar+zip+flate2) lands in the single-digit MB. | **Estimate, to be validated by a spike build:** regex+structural core ≈ 3–6 MB stripped; + yara-x ≈ +4–8 MB; + 5 tree-sitter grammars ≈ +0.5–2 MB each (generated parse tables dominate; one grammar's generated C can exceed 1 MB of source). Realistic full build: **10–25 MB stripped**. That is ~500× the Python script's bytes but zero runtime prerequisites — the trade the zero-install requirement explicitly asks for. |

### 1.1 YARA-X: can it run GuardDog / SkillSpector rules?

- **Rule language:** YARA-X targets rule-level compatibility with YARA 4.x;
  VirusTotal's own positioning and independent testing put ~99% of existing
  rules compiling unmodified (andreafortuna.org YARA-X guide, Apr 2026;
  yararules.org migration guide, updated Nov 17 2026: "across the thousands
  of rules in this library, the vast majority compile with YARA-X 1.20
  without any change").
- **GuardDog 3.x's 11 capability rules** (browser-credential access, network
  download, install hooks, process spawn, …) are plain text/regex patterns
  over package source code (per `tool-audit-nvidia-datadog.md`) — the easiest
  possible port; no binary-format modules involved.
- **SkillSpector's 4 YARA signature categories** (malware, webshell,
  cryptominer, hack tool) are likewise pattern rules; any that use modules
  (`pe`, `elf`, `dotnet`, `math`, `hash`, `string`) are covered — those
  modules all exist in YARA-X. The known gap is the **`magic` module**
  (needs libmagic; feature-gated, absent from the WASM build) and **no
  process/memory scanning** (irrelevant to RepoGate, which scans files).
- **Friction to expect:** YARA-X is deliberately stricter — unescaped `{`
  in regexes, invalid escape sequences, and misspelled module fields are
  compile *errors* where YARA 4.x silently guessed (`--relaxed-re-syntax`
  exists as a transitional crutch). Porting a rule corpus is therefore a
  compile-fix loop, measured in hours, not a rewrite.
- **API stability:** the Rust API is a new `Compiler`/`Scanner` design, *not*
  a drop-in for libyara bindings — but RepoGate has no libyara code to port,
  so this costs nothing. The crate is 1.x with a fast release cadence
  (45 releases, 28 stable, per lib.rs) — pin it and upgrade deliberately.
  Compiled rules can be serialized, which enables shipping a precompiled
  default pack inside the binary.

### 1.2 What the regex limitation actually costs RepoGate (measured, not theoretical)

Grepping `repogate.py` (2026-11-20): ~39 rule definitions, ~90 patterns.

- Lookahead: exactly **3 sites** —
  `os.environ\b(?!\s*\[)` and `process.env\b(?!\.)` (env-dump rule; intent:
  "whole-env access, not single-key lookup") and
  `https?://(?!registry.npmjs.org|registry.yarnpkg.com)` (tarball-dep rule;
  intent: "resolved URL not on the official registry"). Each is a
  *match-then-exclude* shape: with the `regex` crate you match the broader
  pattern and apply the exclusion as a 3-line post-filter on the match's
  following bytes / parsed host. Semantics preserved, linear time kept.
- Backreferences: **zero in rules.** The one backref user is engine code —
  the string-concat folding normalizer
  `(['\"])((?:(?!\1).)*)\1\s*\+\s*(['\"])((?:(?!\3).)*)\3` — which must be
  re-implemented as a small hand-written scanner in Rust (find quote → find
  matching close quote → check for `+` → fold). That is an afternoon of work
  and arguably more robust than the regex.
- Everything else v1 uses (`\b`, alternation, char classes, `\s`/`\d`,
  case-insensitive flags) is fully supported by the `regex` crate.

**Net: the regex-crate limitation costs RepoGate three small rewrites and one
normalizer re-implementation. It does not block anything.** And the linear-time
guarantee is a security property for a tool whose input is adversarial text —
Python `re` (backtracking) can be ReDoS'd by a hostile repo against the
scanner itself; the `regex` crate cannot.

---

## 2. What is genuinely harder in Rust

1. **Rule-authoring ergonomics and iteration speed.** This is the real cost.
   In Python, a new rule is an edit-and-run cycle of seconds. If rules were
   compiled Rust (the zizmor model — each audit is a Rust type implementing
   an `Audit` trait, registered via macro), every rule tweak is a rebuild
   and contributors must write Rust. **Mitigation, and the industry-standard
   one: rules as data.** ast-grep rules are YAML; GuardDog's are YARA files;
   RepoGate's DESIGN.md already specifies `rules/*.yaml` packs. Keep all
   detection content in data packs that the binary loads (embedded default
   pack via `include_str!`, overridable from a rules directory), and the
   iteration loop goes back to edit-and-run — with the Python implementation
   retained as the prototyping harness that consumes the *same* packs.
2. **Semgrep-style matching has no Rust native.** Semgrep's engine is OCaml
   (OpenGrep is the community fork of the same codebase); there is no Rust
   port and none is on a visible roadmap. The serious Rust answer is
   **ast-grep**: code-shaped patterns (`eval($X)`), metavariables, and
   relational rules get you most of what RepoGate would actually write —
   e.g. SkillSpector's AST9 class ("reflective `getattr(os,'system')` sink")
   is a pattern-plus-context rule ast-grep expresses natively. What you
   *don't* get: Semgrep's taint mode and cross-file analysis. Embedding
   `ast-grep-core` as a library (MIT) is viable; the trade is accepting
   ast-grep's pinned tree-sitter version and language set as your constraint.
3. **Taint tracking is hand-rolled, in any Rust design.** No mature
   open-source Rust taint framework exists. Important calibration:
   **RepoGate v1 has no taint to lose** — its risk chains are co-occurrence
   correlation (credential-read ∧ network-send in the same file/package),
   which is a hashmap join and ports trivially. SkillSpector's taint
   (5 source→sink patterns, Python AST) is the *roadmap* item that would be
   genuinely expensive in Rust: a per-language, intra-file dataflow pass over
   tree-sitter CSTs. Scope it honestly as a later phase, Python+JS only,
   and note the Python implementation is not obviously better here — its
   taint is also intra-file and pattern-shaped.
4. **Tree-sitter grammar version skew.** Grammar crates pin different
   `tree-sitter` runtime versions and parser ABIs (ABI 15 requires runtime
   ≥0.25); a stale crate constraint can pull **two incompatible tree-sitter
   versions into one build** and fail with type errors (documented
   tree-sitter-json5 issue, May 2026). Grammars also differ in quality —
   error recovery is universal, but node-type stability across grammar
   releases is not guaranteed, so structural rules need per-grammar snapshot
   tests. This is manageable (pin the whole set, test the set, bump the set
   together) but it is ongoing maintenance Python's `ast` module never asks
   for — for the *one* language Python parses natively. For JS/TS/Go/Rust,
   Python v1 has no AST at all today, so Rust is strictly ahead there.
5. **YAML crate churn** (see table): the obvious crate is archived, the
   obvious fork is deprecated with an unsoundness advisory. Picking
   `serde_yaml_ng` or `noyalib` is a one-time decision, but it is a decision
   a Python porter never faces (`yaml` is just there). Add span/location
   tracking (zizmor's `yamlpath` exists precisely because serde YAML loses
   source positions) and workflow parsing is a small project of its own.
6. **Hostile-input robustness discipline.** Python raises exceptions; Rust
   code with an `unwrap()` on adversarial input panics (fail-closed, but a
   crash, not a finding), and the tree-sitter grammars are C behind FFI —
   the memory-safety story weakens exactly at the parsing boundary.
   Budget: `cargo-fuzz` on the archive extractor and parsers, and a
   no-`unwrap`-on-input lint policy. (Pure-Rust tree-sitter-runtime
   experiments like `yolowsyntax` exist — 41 languages, `#![forbid(unsafe_code)]`,
   resource budgets — but are 0.1.x novelties, not a foundation to build on
   in 2026.)

None of these are blockers. Items 1–3 are the classic shape of the problem
and all three are answered by the hybrid architecture in §3.

---

## 3. Hybrid options, and what serious tools actually ship

| Tool | Language / artifact | Where the detection content lives | Lesson for RepoGate |
|---|---|---|---|
| **yara-x** (VirusTotal) | Rust engine; native binaries + Python/Go/C bindings + a **WASM build** (powers browser-based rule editors) | Data: YARA rule text, compiled at load or precompiled | Engine compiled, content data. WASM is a *distribution variant*, not the architecture. |
| **ast-grep** | Rust single binary (+ napi Node bindings) | Data: YAML rule files (pattern + relational constraints) | A Rust engine whose users never write Rust. Fastest iteration loop in the class. |
| **zizmor** (GitHub Actions scanner) | Rust workspace (10 crates), single binary; v1.32.0 Nov 2 2026 | **Code:** audits are Rust types in a registry — the exception that proves the rule; its domain is one file format, and it still takes YAML config for policy. Notable: it uses tree-sitter (for embedded bash) and custom YAML span tooling. Also distributed **through PyPI** (`uv tool install zizmor`) — a Rust binary riding Python's packaging channel purely for distribution. | Compiled-in audits are survivable for a narrow domain; RepoGate's domain (every language + skills + packages) is too broad — prefer data. Steal the PyPI-wrapper distribution trick instead. |
| **osv-scanner** (Google) | Go single binary, SLSA3-provenance release binaries + checksums; v2.7.0 Oct 2026 | Data lives *server-side* (OSV DB via API) + TOML config locally; extraction logic in the OSV-Scalibr library | The release-engineering bar to copy: signed provenance, checksums, one binary per platform, SemVer-stable JSON output. Also proof a scanner can be a thin local engine + remote data — RepoGate's OSV lookups fit this shape, but its *core* verdict must stay offline/deterministic (DESIGN invariant #3/#7), so remote data stays advisory. |
| **GuardDog 3.x** (DataDog) | Python | Data: YARA rule files + Python metadata detectors | Even the Python incumbent keeps its core detection in data files. Its sandboxing (Landlock/Seatbelt via `nono`, fail-closed) is a reminder that *extraction* is an attack surface — RepoGate's quarantine-first design already answers this; a Rust port should consider Landlock self-sandboxing as a later hardening phase. |
| **SkillSpector** (NVIDIA) | Python ≥3.12 + native YARA wheels | Mixed: patterns in code, YARA files, LLM stage | The cautionary tale for distribution (§0) and for LLM-in-verdict (invariant #3). |

**The pattern across the field: compiled engine, data-driven detection,
single-artifact distribution.** The options for RepoGate:

- **A. Full Rust, rules compiled in (zizmor model).** Simplest distribution,
  worst rule iteration; every community rule contribution is a Rust PR.
  Rejected as the *primary* model (fine for the few structural checks that
  are already code in v1 — package.json lifecycle, tasks.json, workflows).
- **B. Rust engine + rules as data (ast-grep / YARA model).** YAML packs for
  regex+structural rules, YARA-X for signature rules, engine in Rust.
  Contributors write YAML/YARA, never Rust. **Recommended.**
- **C. Rust core + Python shell via PyO3/maturin.** Keeps Python ergonomics
  for orchestration, Rust for hot paths — but reintroduces the interpreter+
  wheel matrix that breaks zero-install (SkillSpector's 3.14/3.15 wheel gap
  is this architecture's failure mode). Rejected as the shipped form;
  acceptable as an internal dev harness.
- **D. WASM-first.** yara-x and tree-sitter both compile to WASM, so a
  browser/edge build is *possible* later from the same Rust core (option B
  doesn't foreclose it). As the primary artifact it fails the project's use case:
  agent hosts need a local executable with filesystem access, not a sandbox
  component. Defer.
- **E. Stay Python.** Fails the zero-install requirement the moment YARA/AST
  land, and makes the no-exclusions invariant expensive. Rejected as the
  end-state; retained as the migration reference (below).

---

## 4. Recommendation and phased migration plan

**Architecture (option B):**

```
repogate (single static binary, Rust)
├── acquire/     GitHub API tarball + local/zip/tar via ureq+rustls, tar, zip, flate2(libz-rs)
├── inventory/   walk, classify, coverage accounting (port of v1 semantics)
├── engines/
│   ├── regex pack runner   (regex crate; YAML packs; match+post-filter for the 3 ex-lookahead rules)
│   ├── structural checks   (the v1 code checks: package.json, tasks.json [JSONC], workflows [YAML+spans],
│   │                        setup.py, build.rs, .claude/settings.json)
│   ├── yara-x              (feature-gated; GuardDog-derived capability pack + signature pack)
│   └── ast (phase 5)       (ast-grep-core or tree-sitter directly; py/js reflective-sink rules)
├── normalize/   string-concat folding (hand-written), base64 decode-and-rescan, unicode checks
├── chains/      co-occurrence correlation + scoring (port of v1 semantics)
└── report/      text + JSON (+ SARIF-shaped findings per DESIGN #10); exit 0/1/2/3
```

**Migration path — the Python fixtures/tests are the spec throughout:**

- **Phase 0 — Freeze the spec (Python-side, do first).** Extract v1's rules
  from `repogate.py` into the YAML pack format both implementations will
  consume; grow `fixtures/` to one fixture per rule category and per risk
  chain; record golden JSON reports. Exit criterion: Python v1 passes the
  enlarged suite from data-driven rules with identical verdicts.
- **Phase 1 — Rust skeleton at parity for the boring 80%.** CLI, acquisition
  (dir/zip/tar/GitHub tarball), inventory + coverage accounting, JSON/text
  report, exit codes. Exit criterion: identical coverage numbers and file
  inventories to Python on every fixture.
- **Phase 2 — Regex engine.** Pack runner on the `regex` crate; the three
  lookahead patterns converted to match+post-filter; concat-folding
  normalizer re-implemented as a hand-written scanner; base64/unicode
  normalization ported. Exit criterion: identical findings (rule id, file,
  severity) on all fixtures; differential run against Python on a corpus of
  real repos (e.g. the six audited tools' own repos) with every diff
  explained.
- **Phase 3 — Structural checks.** package.json (serde_json), tasks.json
  (JSONC parser), workflows (serde_yaml_ng or noyalib + span wrapper),
  setup.py/build.rs/settings checks. Exit criterion: fixture parity,
  including location accuracy.
- **Phase 4 — YARA-X pack (feature-gated).** Port GuardDog's 11 capability
  rules and a starter signature pack; fix YARA-X strictness compile errors;
  measure binary-size delta and keep the feature optional at build time.
  Exit criterion: capability rules fire on the malicious fixtures; Python
  remains able to run the same packs' regex subset.
- **Phase 5 — AST structural rules.** ast-grep-core (evaluate first) or raw
  tree-sitter for Python + JavaScript: reflective-exec sinks, dynamic
  import of decoded strings — the SkillSpector AST9 class. Pin the grammar
  set as one unit with snapshot tests. Exit criterion: new fixtures for the
  AST classes pass; no verdict regressions on the corpus.
- **Phase 6 — Release engineering.** cargo-zigbuild matrix:
  `x86_64/aarch64-unknown-linux-musl` from Linux CI; darwin arm64+x86_64
  from macOS runners. Checksums + build provenance à la osv-scanner;
  a PyPI wrapper package (`uv tool install repogate`) à la zizmor as a
  second distribution channel; SKILL.md updated to fetch-and-verify the
  binary. Exit criterion: an agent on a clean Linux ARM host and a clean
  Mac fetches, verifies, and runs RepoGate with no toolchain present.
- **Retirement rule for Python:** it stays the reference implementation and
  the rule-prototyping harness (new rules are drafted against the Python
  runner for speed, then required to pass under Rust before merge) until
  Phase 5 parity holds for two consecutive releases; after that it is
  dev-only tooling, never shipped.

**Explicit non-goals for the Rust build:** no LLM anywhere in the verdict
path (invariant #3 — Rust makes this *easier* to keep, since there's no
convenient LLM SDK gravity), no process scanning, no attempt at full
Semgrep-grade taint in v1 of the port (Phase 5 is pattern-level; a narrow
intra-file taint for py/js is a Phase 7 candidate, specced separately).

## Risks / open questions

- **yara-x dependency weight and cadence:** 45 releases in ~2.5 years is a
  fast-moving 1.x; pin exactly, bump deliberately, keep it feature-gated so
  a bad bump never blocks the core scanner.
- **Grammar set governance:** someone owns the pinned tree-sitter/grammar
  version set; budget a recurring (quarterly) bump-and-snapshot-test task.
- **Binary size creep:** enforce a size budget in CI (e.g. warn >30 MB) so
  feature additions pay rent visibly.
- **macOS signing:** if the project later wants notarized binaries (Finder-launched
  use), that needs an Apple Developer account ($99/yr) — not needed for the
  agent/curl distribution model; flag, don't buy preemptively.

## Sources

- lib.rs crate pages for yara-x (v1.22.1, Oct 26 2026) and yara-x-fmt (v1.22.0, Oct 20 2026); AwesomeREA YARA-X entry (v1.23.0, Nov 5 2026; data as of Nov 20 2026).
- VirusTotal YARA-X docs: "Differences with YARA" and "YARA-X vs YARA" (virustotal.github.io/yara-x) — strictness, module fields as errors, no process scanning, incompatible APIs.
- yararules.org, "YARA-X: install, yr CLI and YARA differences" (updated Nov 17 2026) — rule-corpus compatibility with 1.20, `magic` module caveat.
- A. Fortuna, "Threat hunting with YARA-X" (Apr 22 2026) — ~99% rule compatibility claim, 1.0 in Jun 2025, WASM build.
- ast-grep: Stack Gems review (checked Oct 21 2026; MIT, 16.3k★, last push Oct 21 2026); xerj grep-alternatives comparison (updated Nov 19 2026; ast-grep 0.51.0, Oct 15 2026); codemod AST-tool benchmark (ast-grep vs Semgrep speed/memory).
- zizmor: DeepWiki core-architecture doc (10-crate workspace, Audit trait + registry, tree-sitter-iter, yamlpath); hysenlabs project profile (v1.32.0, Nov 2 2026; 7,096★); rezmoss supply-chain report (scanned Nov 16 2026).
- osv-scanner: google/osv-scanner README + supported-artifacts docs; samarthya.me walkthrough of v2.7.0 (Oct 12 2026) — single binary + SHA256SUMS verification flow.
- Regex flavour matrix (trydevtools, Nov 2026) and fancy-regex docs.rs (0.20.2) — regex-crate limitations, fancy-regex hybrid design + DoS warning.
- YAML ecosystem: serde_yml lib.rs deprecation notice (0.0.13, May 27 2026; RUSTSEC-2025-0068); noyalib-serde-yaml crates.io page (serde_yaml archived Mar 2024; drop-in shim); 2026 Rust YAML guides (serde_yaml_ng / serde-saphyr / yaml-rust2 as maintained destinations).
- tree-sitter ABI issue: tree-sitter-json5 #9 (May 2026) — ABI 15 vs 0.20 runtime pin, duplicate-version failure mode.
- Cross-compilation: cargo-zigbuild README (rust-cross/cargo-zigbuild); cargo-lambda precedent.
- HTTP/stack precedent: DeepWiki dependency audit of `dra` (ureq 3.1.4 + rustls, tar 0.4.44, zip 6.0.0, flate2 1.1.5/libz-rs, static linking rationale); tiny-update-check size log (rustls build ≈1.3–1.9 MB, Mar 2026).
- Local: `~/workspace/repogate/repogate.py` (rule/pattern census, 2026-11-20), `docs/DESIGN.md`, `research/tool-audit-nvidia-datadog.md` (GuardDog 3.x YARA architecture, SkillSpector pipeline/wheel constraints).
