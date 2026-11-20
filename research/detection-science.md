# RepoGate — Detection Science: What the Next Levels Are and Which Are Worth It

**Date:** 2026-11-20. **Scope:** RepoGate v1 is regex + structural checks +
category-correlation chains, zero-dependency Python stdlib, deterministic,
local-only, never executes its target. This document researches the five
candidate "next levels" — AST analysis, taint tracking, behavioral/sandbox
execution, external intelligence, scoring/eval science — and gives a
build/skip verdict for each for v2/v3. It builds on `best-practices-2026.md`
(threat taxonomy, chains, dampeners) and the two tool audits; it does not
repeat them.

**Freshness:** evidence is weighted to Sep–Nov 2026 (Checkmarx's SkillSpector
bypass study, 2026-11-11; the PRETEXT paper, NeurIPS 2026; Adversa's
eight-scanner bypass test; Cisco's Skill Scanner evaluation; the ASE '26
npm-detector study; a Nov 2026 analysis of all 232,930 OSV MAL- records).
Pre-2026 material is flagged **[STALE/ESTABLISHED]** and used only for
mechanism, never as current threat evidence.

**The one-sentence conclusion:** the highest-value next step is not a new
detection level at all — it is the **evaluation harness (§5)**, because every
published measurement in 2026 says tools in this class cannot currently state
their own false-positive/false-negative rates, and the second-highest is the
cheapest detection upgrade available: **Python-stdlib AST + entry-point
reachability + taint-lite (§1–§2)**, which costs zero new dependencies.
Detonation (§3) is the only level that breaks a v1 invariant, and the
evidence says to buy its data (from OpenSSF) rather than build it.

---

## 1. AST-based analysis

### What it adds over regex

Four concrete capabilities, in descending order of value to RepoGate:

1. **Reachability.** Regex cannot tell code that *runs* from code that merely
   *exists*. An AST pass can build the entry-point set (install hooks →
   their target files, `__main__`/bin entries, the script a `tasks.json`
   folderOpen command invokes, a skill's declared entry script) and walk
   imports/requires from it. Everything in `best-practices-2026.md` §4.4
   already says "reachability beats path" for dampening test/example code —
   AST is how you actually compute it. This is also Socket's production
   model: "Parse every file, resolve imports and `require` calls against the
   platform's built-in modules, record each call site" (Socket glossary,
   updated Nov 2026).
2. **Alias and indirection resolution.** `from subprocess import run as r;
   r(...)` is invisible to a regex looking for `subprocess`, and visible to
   an AST pass with an import-alias map. This is not hypothetical:
   SkillSpector's own PR #115 (merged 2026) exists because its AST *and*
   taint analyzers "resolved call names purely syntactically, so dangerous
   calls imported under an alias were missed" — `import subprocess as sp;
   sp.run(secret)` evaded both until the fix.
3. **Argument sensitivity.** Regex sees `eval(`; AST sees whether the
   argument is a string literal (usually benign), a variable (unknown), or
   the return value of a network call (the dropper shape). The ASE '26
   study (Guo et al., 11 tools, 6,420 malicious + 7,288 benign npm packages)
   found precision/recall are "structurally determined by how [a tool]
   resolves the ambiguity between code capability and malicious intent" —
   argument/dataflow context is exactly that resolution mechanism.
4. **Comment/string discrimination.** Regex fires on dangerous words in
   comments, docs, and string literals — including a scanner's own rule
   definitions (RepoGate scanning any security tool's repo, or itself,
   trips this today). An AST knows whether a match is code, comment, or
   data. This is a pure false-positive reduction with no recall cost.

### Where AST loses to regex (the vice versa is real)

- **Language coverage.** SkillSpector's AST pass is Python-only. A skill
  whose payload is JavaScript, shell, or Rust gets nothing from it; regex
  reads all text uniformly. RepoGate's targets are multi-language by
  definition (repos, not just Python skills).
- **Parse failure = blindness.** Minified, transpiled, syntax-extended
  (JSX/TS), or deliberately malformed-but-executable code can fail or
  mis-parse; a file the parser rejects is a file the AST layer scores as
  silent. Regex still sees the strings. Any AST layer must therefore treat
  *parse failure of an executable file* as a coverage event (RepoGate's
  INCONCLUSIVE machinery already has the slot for this), never as a pass.
- **Reflection beats syntactic AST too.** Checkmarx (2026-11-11) hid
  `os.system` behind `getattr(os, "system")(cmd)`: the *deterministic half*
  of SkillSpector — regex and AST alike — scored the skill 13/100 SAFE;
  only the LLM stage caught it (84/100). NVIDIA later added AST9 to resolve
  `getattr` with a *literal* argument (commit 2026-06-23, shipped ~v2.5.0).
  Lesson: the specific, cheap upgrade is **constant propagation for
  reflective calls with literal arguments**, not "AST" in the abstract.
  Non-literal reflection stays invisible to both regex and AST — it should
  be its own finding ("unresolvable dynamic execution present"), which
  SkillSpector's AST7 already does for non-constant attribute access.
- **The payload may not be code at all.** PRETEXT (NeurIPS 2026) moved the
  payload entirely into natural-language skill prose, framed as the skill's
  legitimate purpose and split across files: up to 97% attack success
  against a frozen SkillSpector, 77% against a co-adaptive one. No AST or
  taint layer sees a prose payload. Adversa's eight-scanner test (2026)
  reached the matching conclusion from the other side: "every scanner
  matches the bytes in the file, not the bytes that execute. None decodes
  an encoded payload and re-runs its full ruleset over the plaintext, and
  none normalizes Unicode before its command bank runs." RepoGate v1
  already does decode-and-rescan and Unicode normalization — that text
  pipeline is worth more, per dollar, than AST for the skill target class.

### Implementation routes under RepoGate's constraints

| Route | Cost | Coverage |
|---|---|---|
| Python stdlib `ast` | **Zero deps, exact parser** (it is the runtime's own grammar) | Python files only — but Python is the highest-risk skill language and the one with a free exact parser |
| Hand-rolled JS tokenizer/regex-plus | Zero deps, approximate | Fragile; good enough for import extraction and call-site spotting, not real AST |
| tree-sitter (via a vendored binary or the Rust rewrite) | Breaks zero-dep Python; natural fit if RepoGate goes Rust (ast-grep is Rust/tree-sitter) | 100+ grammars, error-tolerant parsing |
| Shell out to Semgrep CE if present | Optional dependency; CE taint is intra-procedural/intra-file only, inter-procedural is the paid Pro engine | 30+ languages, YAML rules; advisory layer only |

Mondoo's xgrep (Semgrep-compatible, tree-sitter + cross-file taint, marketed
to AI agents, live Nov 2026) is proof the "embed an existing engine" route
exists — but it is a platform binary, incompatible with the zero-dep skill
form factor.

### Verdict — AST

- **BUILD (v2):** Python stdlib-`ast` pass: import-alias resolution,
  dangerous-call inventory with argument classification (literal / variable /
  call-result), `getattr`-with-literal resolution, and an **entry-point
  reachability graph** (hooks/tasks/skill entries → files) used to weight
  and dampen *all* layers' findings, regex included. Parse failures recorded
  as coverage gaps.
- **BUILD (v2, cheap):** import/require extraction for JS via tokenizer-lite
  for the reachability graph only (not full AST claims).
- **SKIP (v2):** a general multi-language AST engine in Python. Revisit only
  as part of the Rust question, where tree-sitter/ast-grep make it cheap.

---

## 2. Taint tracking

### How deep is SkillSpector's, really?

From its docs, secondary analyses, and its own PR history (Nov 2026 audit +
PR #115), SkillSpector's taint is **TT1–TT5: five named source→sink flow
patterns** (credential→network, file→network, external-input→exec, etc.),
implemented over the Python AST with:

- syntactic call-name resolution, extended mid-2026 with a **module-level
  import-alias map** (PR #115) — explicitly *no per-scope shadowing
  analysis* ("can over-detect in contrived cases, which errs on the safe
  side");
- **reflection explicitly out of scope** — `getattr(os, "system")` is not
  resolved by the taint analyzer (AST7 flags non-constant attribute access
  as a pattern instead);
- a taint path is scored CRITICAL (50 pts before multipliers) — i.e., taint
  is used as a *severity escalator for known flow shapes*, not as a general
  dataflow engine. There is no published evidence of inter-procedural
  summaries, field sensitivity, or cross-file flow; the test suite is
  46 taint tests, consistent with a pattern catalog, not a framework.

That is the right depth for this product class, and it is copyable. Nobody
in the open field is running CodeQL-grade dataflow at the pre-clone gate;
Semgrep's free engine is intra-procedural only, and the ASE '26 study's
best conventional tool (GuardDog, F1 93.32%) does capability correlation,
not dataflow — while its headline chain result (SAP_DT's collect-and-
exfiltrate detection rising 3.2% → 79.3% with behavioral coupling) shows
even *co-occurrence with coupling* captures most of the value taint would.

### What a credible lightweight taint layer looks like

"Taint-lite": intra-file, assignment-ordered flow over a per-language
source/sink catalog, with three honesty rules — (1) a flow finding requires
an actual variable path, not mere co-presence (that is what distinguishes
it from v1's chains); (2) unknown indirection (getattr with non-literal,
`eval` of a variable, dynamic import) emits an *unresolvable-flow* finding
rather than silence; (3) flows are reported with their path (source line →
assignments → sink line) so a human can verify in seconds.

**Source catalog (per language, shared semantics):**
- Environment: `os.environ`/`process.env`/shell `$ENV`, argv, stdin
- Sensitive files: reads of `~/.ssh`, `~/.aws`, `~/.gnupg`, `.env`, browser
  stores, `/etc/passwd` — i.e., v1's credential-access patterns *as sources*
- Network input: response bodies of fetch/requests/urllib/socket recv
- Skill/agent context (skill-specific source class nobody else has):
  content the agent is instructed to read — files the SKILL.md names, tool
  outputs, clipboard

**Sink catalog:**
- Network send: requests/urllib/fetch/http.request/socket send, webhook
  POSTs
- Execution: eval/exec/subprocess/os.system/child_process, `node -e`
- Persistence writes: writes to agent/editor/OS config paths (v1 PERSIST set)
- File write outside the tree, or write+chmod+exec (dropper completion)

**Sanitizers:** almost none for exfil flows (base64/JSON encoding is
*transport*, not sanitization — treating it as one is a classic taint bug);
for exec sinks, `shlex.quote`/parameterized APIs downgrade but do not clear.
This asymmetry is why exfil taint is tractable: the sink is damning
regardless of transformations on the path.

**Language plan:** Python gets real taint-lite on stdlib `ast` (assignments,
returns within a file, simple function summaries). JS gets token-flow: track
`const x = <source>` and simple reassignments textually, confirm `x` (or a
template literal containing it) reaches a sink argument in the same file —
strictly weaker, and labelled as such in output. Shell gets the same
token-flow treatment for `$VAR` pipelines, which happens to cover the
`curl $URL | sh` family well.

### Verdict — taint

- **BUILD (v2):** taint-lite for Python (real, on stdlib `ast`) + token-flow
  approximation for JS/shell, emitting path-carrying flow findings that
  *replace* v1's same-file category co-occurrence for the C1 Stealer and C2
  Dropper chains where a flow is found (co-occurrence remains as the
  lower-confidence fallback). Expected effect per ASE '26: chain precision
  up sharply; recall roughly neutral (80.3% of 2026 malware uses **no**
  evasion at all — v1 already catches the plain shapes; taint's job is
  killing false chains, not finding hidden ones).
- **SKIP:** inter-procedural/cross-file dataflow, field sensitivity, and
  any framework dependency (CodeQL/Semgrep Pro class). Cost is an order of
  magnitude above everything else in this document combined, for the
  marginal slice of malware that is both multi-file *and* flow-obfuscated.

---

## 3. Behavioral / sandbox layer

Two different things are called "sandbox" in this field, and conflating
them is how bad decisions happen.

### 3a. Sandboxing the *scanner* (GuardDog/nono) — self-protection

GuardDog 3.x runs its **static** analysis inside a kernel sandbox (Landlock
on Linux, Seatbelt on macOS, via Datadog's `nono`): three privilege-split
phases — download+metadata unsandboxed (needs network), archive extraction
sandboxed (no network, FS restricted), YARA analysis sandboxed. The sandbox
is **required by default; if unavailable the scan fails** (`--no-sandbox`
is an explicit opt-out). Its purpose is defensive: it mitigates
path-traversal/code-execution CVEs *in the extraction path itself*
(CVE-2022-23530/23531, CVE-2026-22870/22871 class bugs).

RepoGate needs this thinking even without Landlock: **RepoGate's own
tarfile/zip extraction is its largest attack surface.** A hostile archive
aimed at the scanner (zip bombs, tar-slip, symlink chains, the Python
tarfile filter-bypass class addressed by PEP 706 **[STALE/ESTABLISHED —
mechanism]**) attacks every user who scans it. Current v1 mitigations
(path-escape checks, size/ratio/file-count caps per the design doc) are the
right shape; the upgrade path is: extraction filters on (Python 3.12+
`tarfile` data filter, mandatory not default-dependent), decompression in a
subprocess with rlimits (CPU/mem/output bytes), and — where available —
Landlock via a tiny helper, failing closed to INCONCLUSIVE rather than
running unprotected. Sigil's marketing said "behavioral"; its own FAQ
confirms all phases are static (audit, Nov 2026) — a reminder to describe
this layer honestly as *scanner hardening*, not behavior analysis.

### 3b. Detonation — actually running the target (package-analysis model)

OpenSSF's package-analysis is the reference implementation: every new
release on PyPI/npm/RubyGems/Packagist/crates.io is **installed and imported
inside a gVisor sandbox**, recording files touched, sockets opened, DNS
queries, and commands executed; results are public (BigQuery, surfaced via
deps.dev). What detonation adds that no static layer can:

- Ground truth for the install/import window — exactly where postinstall
  and import-time attacks live (its first month surfaced ~200 malicious
  packages, e.g. an npm package that exfiltrated host details and opened a
  reverse shell *during install*, invisible until it ran).
- Immunity to obfuscation of *behavior* (the code can hide its strings; it
  cannot hide its syscalls) — for the fraction of payloads that fire
  unconditionally at install/import.

What it costs, and why the costs are structural:

- **It breaks RepoGate invariant #1** ("never executes scanned code") and
  the skill form factor with it. Detonation cannot ship inside a
  zero-dependency Python file an agent runs on a laptop; it needs gVisor/
  Firecracker-class isolation, a disposable network (sinkholed DNS/egress
  or the "sandbox" becomes a C2 participant), no credentials anywhere in
  reach, snapshot-revert, and a host you are willing to treat as
  compromised-by-design. The scanner stops being a gate and becomes an
  execution surface that itself needs a security model: sandbox-escape
  bugs, resource exhaustion, and malware that fingerprints the sandbox
  (package-analysis's own docs concede env-gated, date-gated, or
  function-call-gated payloads "will appear behaviourally clean during
  analysis and only misbehave later" — detonation has a false-negative
  shape shaped exactly like modern droppers).
- **Coverage mismatch:** package-analysis covers registry releases in five
  ecosystems. RepoGate's primary targets — arbitrary GitHub repos and agent
  skills — have no "install and import" semantics to detonate (a skill's
  payload fires inside a victim *agent*, not an installer).

### Verdict — behavioral/sandbox

- **BUILD (v2):** scanner self-hardening per §3a (mandatory extraction
  filters, subprocess+rlimit extraction, caps enforced before any parse,
  fail-closed INCONCLUSIVE). Cheap, pure win, protects every future layer.
- **SKIP detonation in the skill (v2 and v3).** Instead, **consume**
  OpenSSF's results: for registry dependencies, query deps.dev/
  package-analysis behavior data ("has this exact name+version already been
  detonated, and what did it touch?") as an external-intelligence source
  (§4). If true detonation is ever wanted, it belongs on isolated fleet infrastructure
  as a separate, opt-in, network-isolated service — a v3+ project with its
  own threat model, never a mode of the gate skill.

---

## 4. External intelligence

RepoGate's invariant #7 says *local only* (the anti-ScanRepo rule: nothing
about a scan leaves the machine). External intel creates a real tension:
SkillSpector's SC4 sends dependency coordinates to OSV.dev **even in
`--no-llm` mode**. Resolution: default to **downloadable snapshots**
(intel comes to the machine, queries never leave), with live lookup as an
explicit opt-in. Per source:

| Source | What it catches | Live vs cacheable | False-negative / false-positive shape |
|---|---|---|---|
| **OSV MAL-\*** (OpenSSF malicious-packages) | Known-malicious name+version across 8 ecosystems; 232,930 records as of 2026-11-12 | **Cacheable**: the source repo is OSV-format JSON in git — snapshot it, ship a name+version index (bloom filter + exact set). Live API (`querybatch`) as opt-in refresh | **Lag is the FN shape.** Nov 2026 analysis of the full corpus: harmful npm packages stayed up a median **35 days**; in **71%** of cases the registry removed the package *before* the OSV record appeared. Even fast 2026 cases show a 50 min – 1 h 44 min publish→advisory gap. A MAL- lookup can only ever catch yesterday's malware. **FP shape is real too:** on 2026-05-26 OSV withdrew **157** MAL- records after automated Amazon Inspector reports false-flagged mainstream packages (FastAPI 0.136.3, MAL-2026-4750, flagged for a "suspicious dependency" with no payload identified). A MAL- hit should BLOCK (per best-practices §4.2) but the report must carry the record's source/provenance so a human can spot an automated-source record |
| **GitHub Advisory DB (GHSA malware)** | Same corpus, GitHub's mirror of the OpenSSF repo + npm security-team reports | Cacheable the same way (public git repo) | Same lag profile as OSV (it largely *is* OSV); adds nothing over OSV except GHSA aliasing — consume one, not both |
| **Registry metadata diffing** (GuardDog "repository integrity mismatch") | The tarball-only payload: code in the npm/PyPI artifact that is **not in the linked GitHub repo** (the event-stream / Shai-Hulud shape); also version-line anomalies, maintainer changes, provenance regression | **Live-only** (registry JSON + tarball + repo tree), but RepoGate already fetches GitHub tarballs — for npm/PyPI-named targets the registry tarball is one more fetch, and the diff is a file-list + hash comparison | FN: attacker controls both repo and tarball (then content rules are the only line — fine); packages with no `repository` field (common in the long tail) return "cannot diff" → coverage note, not a pass. FP: legitimate build-generated files in tarballs (compiled output, generated parsers) — diff must be *asymmetric*: files present in the tarball's executable set but absent from the repo are the signal; missing files are noise |
| **Sigstore provenance** (npm attestations, PyPI PEP 740) | Binds an artifact to the workflow/repo that built it; catches repo-vs-artifact substitution and, in diff form, **provenance regression** (a version line that had attestations loses them — GuardDog ships this detector) | Live-only (registry attestation endpoints, small JSON) | **Absence proves nothing — coverage is thin:** ~17% of PyPI uploads carried attestations as of Mar 2026 **[recent-established]**; one measurement of the Sigstore project's own dependency tree found 7.2% of npm deps with provenance. So: presence + identity mismatch (attestation names a different repo than the package claims) = strong negative signal; regression vs the package's own history = medium signal; mere absence = context line only, never scored |
| **deps.dev / package-analysis behavior data** | §3b's detonation results, without detonating: files/sockets/commands observed for a specific name+version | Live-only API | Coverage: registry packages in 5 ecosystems only, install/import window only, sandbox-evasive payloads absent. A supplement for dependency targets; irrelevant for skills/repos |

**Net assessment:** external intel is the only layer that can catch a
*known* bad artifact with near-zero ambiguity, and the only layer whose
ceiling is set by other people's reporting speed. It complements content
analysis; the 2026 record (35-day median exposure, 71% registry-first) is
a standing disproof of any "just check the database" design.

### Verdict — external intelligence

- **BUILD (v2):** OSV MAL- snapshot lookup (offline index, `--update-intel`
  fetch, live query opt-in), with record provenance printed on every hit.
  Highest certainty-per-line-of-code in this entire document.
- **BUILD (v2):** registry↔repo integrity diffing for npm/PyPI targets
  (asymmetric, executable-set only).
- **BUILD as context only (v2/v3):** Sigstore provenance presence/mismatch/
  regression lines in the trust-signals section — never scored alone.
- **BUILD (v3):** deps.dev behavior lookup for registry dependencies.
- **SKIP:** GitHub Advisory DB as a separate source (duplicate of OSV).

---

## 5. Scoring science and the evaluation harness

### What the 2026 measurements actually say

- **Nobody's numbers generalize.** Cisco's Skill Scanner evaluation (2026)
  is the most honest public measurement in the field: on MaliciousSkillBench
  (6,594 packages) its modernized engine reached precision 99.16% / recall
  31.43% / F1 47.73% at a 1.05% blocking false-positive rate — and on a
  **source-disjoint** population the same engine fell to F1 13.74% with FPR
  7.71%. Development-corpus numbers overstate field performance by ~3×.
  Any RepoGate accuracy claim must publish a held-out, source-disjoint
  number beside the dev number, or it is marketing.
- **Correlation is the biggest measured lever.** ASE '26: coupling
  co-occurring behaviors raised one detector's collect-and-exfiltrate chain
  detection from 3.2% to 79.3%. This validates v1's chain architecture —
  and says the next scoring investment is *better coupling* (§2's flows
  replacing co-occurrence), not more rules.
- **Diffing beats absolutes for FP control.** Socket's strongest signal is
  "a capability that appears for the first time in a new version" (the
  axios compromise, 2026-03-30: a crypto-js copy that added a postinstall
  hook + shell execution + file deletion was flagged 6.5 minutes after
  publish, with no signature existing). Benign packages have *stable*
  capability sets; scoring the delta removes the standing FP pressure from
  every legit package that uses eval/network/shell for real work. RepoGate
  already plans diff mode (best-practices §4.4); the eval harness should
  treat diff-mode FPR as a headline metric.
- **File-role awareness is the other FP lever**, and it must be
  reachability-aware, not path-naive: test/fixture/doc/demo files dampened
  *unless reachable from an entry point*; scanner/security-tool repos
  (whose rule definitions and test corpora are attack strings by design)
  dampened for pattern-in-data contexts but never for reachable code;
  literal-argument eval/exec treated as a different (weaker) signal than
  variable-argument — all already specified in best-practices §4.4, all
  unmeasured until a harness exists.
- **Vendor head-to-heads are directional only.** Cordon's published page
  (2026) claims 95.2% vs GuardDog's 85.5% on the same 498-sample draw, and
  94.2% detection over 39,328 DataDog/malregistry samples (79.7% "by the
  code alone") — self-measured, unaudited; useful as evidence that
  independent same-corpus comparison is *possible and expected*, not as
  numbers to chase.

### The eval harness RepoGate should build (concrete spec)

**Corpora** (pin revisions; store hashes, fetch samples into quarantine on
demand; never commit live malware to the repo):

| Corpus | Role | Source |
|---|---|---|
| DataDog malicious-software-packages dataset | Malicious recall (registry packages) | GitHub, quarantined samples |
| Backstabber's Knife Collection | Malicious recall, curated real-world attacks (JS/Py/Ruby) **[STALE/ESTABLISHED as a collection; samples remain valid]** | Academic dataset |
| OSV MAL- name+version sample → registry fetch | Known-bad lookup accuracy + lag measurement | OSV snapshot (§4) |
| MaliciousSkillBench | Skill-target classification | Public benchmark (used by Cisco eval) |
| Checkmarx PoCs + Adversa bypass set + PRETEXT outputs | **Evasion suite** — reported separately, never averaged into headline recall | Published PoCs / paper artifacts |
| Top-1000 npm + top-500 PyPI by downloads; top-starred GitHub repos sample | Benign FPR at BLOCK and REVIEW bands | Registry download stats |
| Hard negatives: security tools' own repos (GuardDog, SkillSpector, RepoGate itself), legit install-script packages (node-gyp class), NotInject (benign prose that *looks* like injection) | FP stress — the cases that embarrass scanners in production | GitHub / NotInject corpus |

**Protocol:**
1. **Source-disjoint split.** Partition malicious corpora by campaign/
   maintainer/source *before* tuning; tune on dev, report on holdout,
   freeze the holdout (Cisco protocol). Publish both numbers.
2. **Metrics per verdict band**, not one accuracy figure: BLOCK precision
   and recall; benign BLOCK-FPR (release gate: ≤1%); benign REVIEW rate
   (the human-cost metric); per-chain and per-category recall so a
   regression localizes to a rule family; evasion-suite pass rate as its
   own line.
3. **Diff-mode evaluation:** for packages with a known-good prior version,
   measure capability-delta alerting separately (Socket's claim is that
   this is where FP goes to die — verify it on our corpora, don't inherit
   it).
4. **CI regression gate:** no RepoGate release ships if holdout BLOCK
   recall drops, benign BLOCK-FPR rises, or coverage accounting regresses
   (files silently unscanned). The harness runs the scanner as a black box
   through its CLI/exit-code contract — the same surface agents use.
5. **Safety of the harness itself:** samples are handled under §3a rules —
   extraction-filtered, capped, never executed, stored outside the repo;
   the harness is a static-only consumer of the same quarantine discipline
   it measures.

### Verdict — scoring/eval

- **BUILD FIRST (v2, before any new detection level):** the harness above,
  even at reduced scale (DataDog dataset + top-500 benign + the published
  PoC evasion suite). Every other verdict in this document is a hypothesis
  until this exists; with it, v2's AST/taint work can be accepted or
  rejected on evidence instead of vibes.
- **BUILD (v2):** publish per-band metrics with each release, dev + holdout.
- **SKIP:** ML scoring. The corpora are too small and too
  campaign-clustered to train anything that generalizes (Cisco's
  source-disjoint collapse is what ML would eat first), and a learned
  scorer breaks the deterministic-verdict invariant that the Checkmarx
  non-determinism lesson bought.

---

## 6. Summary — build / skip by level

| Level | What it adds | Cost | Verdict |
|---|---|---|---|
| Eval harness (§5) | The ability to know whether anything else works; per-band FP/FN, source-disjoint | Days; corpora wrangling, no new runtime deps | **BUILD FIRST — v2 gate for all other work** |
| AST, Python-only (§1) | Alias resolution, argument sensitivity, comment/string discrimination, reachability graph that sharpens every other layer | Zero deps (stdlib `ast`); moderate code | **BUILD — v2** |
| Taint-lite (§2) | Real variable-path flows replace co-occurrence for Stealer/Dropper chains; path-carrying evidence | Moderate; Python real, JS/shell approximate | **BUILD — v2** (after harness, so its precision gain is measurable) |
| Scanner self-sandboxing (§3a) | Protects the scanner from hostile archives (its biggest attack surface) | Low–moderate | **BUILD — v2** |
| OSV MAL- snapshot (§4) | Near-zero-ambiguity known-bad verdicts, offline | Low | **BUILD — v2** |
| Registry↔repo diffing (§4) | Catches tarball-only payloads no content scan of the repo can see | Moderate; live fetches | **BUILD — v2** |
| Sigstore provenance (§4) | Substitution/regression signals | Low | **Context only — v2/v3, never scored alone** |
| deps.dev behavior data (§4) | Detonation results without detonating | Low (API) | **BUILD — v3** |
| Multi-language AST engine (§1) | Uniform AST/taint across JS/Go/Rust | High in Python; natural only in a Rust/tree-sitter rewrite | **SKIP in Python — revisit with the Rust decision** |
| Full inter-procedural taint (§2) | Cross-file flow proofs | Very high | **SKIP** |
| Detonation sandbox (§3b) | Install/import ground truth; obfuscation-proof behavior | Very high; breaks invariant #1; needs isolated fleet infra | **SKIP for the skill; optional v3+ fleet service, consume OpenSSF data meanwhile** |
| ML scoring (§5) | — | Breaks determinism; corpora too clustered | **SKIP** |

**Sequencing for v2:** harness → Python AST + reachability → taint-lite →
OSV snapshot + registry diffing → scanner self-hardening throughout.
**v3 candidates:** deps.dev behavior lookup, provenance regression tracking
across re-scans, and — only if the Rust rewrite happens — tree-sitter AST
for JS/TS, which is the single largest remaining detection upgrade and the
only one whose cost is dominated by language choice rather than detection
science.

---

## Sources (with dates)

**Current — Sep–Nov 2026 (weighted primary):**
1. Checkmarx Zero — *NVIDIA SkillSpector: "Safe" Verdicts Don't Mean the
   Skill Is Safe*, 2026-11-11. https://checkmarx.com/zero-post/nvidia-skillspector-safe-verdicts-dont-mean-the-skill-is-safe/
2. PRETEXT: *Defeating Malicious Skill Detection Frameworks for AI Agents*,
   NeurIPS 2026 (arXiv 2609.39607). https://arxiv.org/pdf/2609.39607v1
3. Adversa AI — *AI agent skills security: 8 open source skill scanners
   bypassed*, 2026. https://adversa.ai/blog/agent-skill-scanners-bypass-eight-tested/
4. Poisoned Pipeline — *T0236: Hide the payload in a path the review tool
   skips* (Checkmarx incident record), Nov 2026. https://poisonedpipeline.com/techniques/T0236.html
5. Effycace — *Poisoned dependencies: what 232,930 malicious-package reports
   say*, Nov 2026 (data to 2026-11-12). https://www.effycace.com/research/reports/malicious-packages-2023-2026/
6. Socket — *OSV Withdraws 157 Malware Reports After Automated False
   Positives Hit npm and PyPI*, May 2026 (incident); page current Nov 2026.
   https://socket.dev/blog/osv-withdraws-157-malware-reports
7. FixLane/POPA Recon — *Is my npm package compromised?* (advisory-lag
   table for four 2026 incidents), updated 2026-11-15.
   https://fixlane.poparecon.com/guides/check-npm-packages-for-malware
8. Socket — *Glossary: Behavior-Based Security* (capability extraction
   model; axios compromise timeline), updated Nov 2026.
   https://socket.dev/glossary/behavior-based-security
9. Socket — *FAQ* (capability detection description), updated Oct 2026.
   https://docs.socket.dev/docs/faq
10. Cordon — *Accuracy, measured* (same-corpus GuardDog comparison;
    vendor self-measurement), Nov 2026. https://www.cordonscan.com/accuracy
11. DataDog GuardDog — README / PyPI (nono sandbox phases, fail-closed
    default, CVE list), v3.2.0 Aug 2026, page current Nov 2026.
    https://pypi.org/project/guarddog/

**Recent-established — Mar–Aug 2026:**
12. Cisco AI Defense (via Hugging Face) — *Improving Cisco Skill Scanner
    Across Real-World Agent-Safety Datasets*, ~Sep 2026.
    https://huggingface.co/blog/Vineethsain/tuning-cisco-skill-scanner
13. Guo et al. — *How Effective Are NPM Malicious Package Detectors? A
    Large-Scale Empirical Study*, ASE '26 (Oct 2026).
    https://arxiv.org/pdf/2603.27549
14. NVIDIA SkillSpector PR #115 — *resolve import aliases in AST and taint
    analyzers* (taint implementation depth, stated limitations), 2026.
    https://github.com/NVIDIA/SkillSpector/pull/115
15. Rushi's — *Scanning agent skills before you trust them: a look at
    NVIDIA SkillSpector*, Jun 2026. http://www.rushis.com/scanning-agent-skills-before-you-trust-them-a-look-at-nvidia-skillspector/
16. ExplainX — *NVIDIA SkillSpector: AI Agent Skill Security Scanner —
    2026 Guide* (TT1–TT5, taint scoring), Oct 2026 update.
    https://explainx.ai/blog/nvidia-skillspector-ai-agent-skill-security-scanner-2026
17. OpenSSF Package Analysis — project docs (gVisor detonation model,
    install/import window limits), current Nov 2026.
    https://docs.openvet.org/landscape/package-analysis/ and
    https://github.com/ossf/package-analysis
18. OpenSSF — *Detecting Malicious Packages Using the OSV API*, 2026-05-20.
    https://openssf.org/blog/2026/05/20/detecting-malicious-packages-using-the-osv-api/
19. Zenn/sqer — *Package Registry Provenance Status: 2026 Edition*
    (attestation coverage figures), Mar 2026.
    https://zenn.dev/sqer/articles/e4df3d397f5651?locale=en

**[STALE/ESTABLISHED — mechanism/taxonomy only]:**
20. Backstabber's Knife Collection (Ohm et al., 2020) — corpus provenance.
21. PEP 706 (tarfile extraction filters, 2023) — scanner-hardening mechanism.
22. Semgrep CE vs Pro taint scope (intra- vs inter-procedural) — vendor
    documentation, long-standing.
