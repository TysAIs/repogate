# RepoGate v2 — synthesis of the 7-track research program (Nov 20, 2026)

Sources: research/tool-audit-nvidia-datadog.md, tool-audit-specialized.md,
best-practices-2026.md, code-merge-feasibility.md, rust-vs-python.md,
yara-merge-path.md, detection-science.md, evasion-catalog.md,
unified-architecture.md, moat-and-positioning.md.

## The answer to "one big thing, not an aggregator"

Three load-bearing ideas, none of which any incumbent has together:

1. **Scan and gate are separate programs.** Scanning is a pure function of
   content → a Findings IR (cacheable by tree hash). Gating is findings ×
   intended action × policy. Every audited tool fuses them into one score,
   so none can answer the agent's actual question: "may I *open* this? may I
   *install* it? may I *import it as a skill*?" RepoGate's verdict is a
   ladder over six actions (inspect < clone < open < install < run <
   import-skill); the same tree can be ALLOW for clone and BLOCK for open.
2. **The merge is data, and data is the moat.** The field's detection
   content — Sigil's ~400 JSON rules, GuardDog's 55 YARA rules and
   top-package lists, SkillSpector's 33 labeled fixture skills, CloneGuard's
   20 rules — is almost entirely Apache-2.0/MIT and vendoring-legal. Merged
   into one portable rule format (RRF, YAML), RepoGate goes from ~70 rules
   to ~450+ plus a labeled eval corpus, and the corpus is
   language-agnostic: it survives any engine rewrite.
3. **Zero egress, agent-native.** Socket uploads snapshots, Snyk's scanner
   phones home, SkillSpector's default stage sends file contents to an LLM
   provider. RepoGate sends nothing, needs no token, and ships *as* a skill:
   the protected agent carries its own gate. Anthropic's native scanning is
   Enterprise-only and excludes MCP-delivered skills — the consumer/agent
   surface is unguarded (Snyk ToxicSkills: 36.8% of 3,984 registry skills
   flawed, 13.4% critical).

## Decisions (each traced to a brief)

| Question | Verdict | Why |
|---|---|---|
| Merge their code? | Merge **data** verbatim; port code selectively | Licenses verified clean (Apache-2.0/MIT, no copyleft in the tools' own code). Best assets are rule packs and fixtures, not engines. |
| Rust or Python? | **Hybrid converging on Rust** | One static Rust binary is the product (zero-install on agent hosts); Python stays as reference/prototyping until fixture parity. Only 3 of ~90 patterns use lookahead, none use backrefs — the Rust regex engine loses ~nothing and its linear-time guarantee kills ReDoS-by-hostile-repo. YARA-X is Rust-native — the strongest single argument. |
| YARA the engine? | **A layer, not the engine** | YARA-X (v1.23, production at VirusTotal) runs GuardDog's rules nearly as-is, but YARA cannot express correlation, structural checks, metadata, or prompt-injection semantics. Native code keeps those. |
| Vendor YARA-Forge / signature-base? | **No** | YARA-Forge mixes Elastic License 2.0 rules (bars hosted use); signature-base is DRL-1.1 — attribution required *in match output*. Clean-room or skip. SkillSpector's own YARA is partly DRL-derived — same handling. |
| Sigil's LOLBin pack? | **Excluded from core** | GPL-3.0 (GTFOBins-derived). At most a separate opt-in bundle, never in the MIT core. |
| ScanRepo? | **Nothing to take** | No public engine source exists (verified across the operator's 100 repos); its scam DB has no license grant. Link, don't ingest. Ideas already absorbed. |
| Sandbox/detonation stage? | **Skip** | Breaks the never-executes invariant and still misses env/date-gated payloads. Instead: scanner self-hardening (extraction filters, fail-closed INCONCLUSIVE) and, later, *consuming* OpenSSF package-analysis results via deps.dev. |
| ML/LLM scoring? | **Skip** | Breaks determinism — the exact failure Checkmarx proved against SkillSpector (same skill scored 6, then 32). |
| OSV lookups? | **Vendor the MAL- snapshot offline** | Highest certainty per line of code; hits carry record provenance (OSV has false-flagged before — FastAPI, May 2026). Live queries would break zero-egress. |
| Name? | **Check before launch** | `repoguard-py` already exists on PyPI; "RepoGate" needs an availability pass on PyPI/npm/GitHub/ClawHub. |

## v2 build sequence (ordered; acceptance criteria in the briefs)

1. **Eval harness first.** Vendor SkillSpector's 33 labeled fixtures +
   DataDog's malicious-packages dataset + Backstabber's Knife for recall;
   top-1000 npm / top-500 PyPI + hard negatives (scanner repos, NotInject)
   for false positives; the published bypass PoCs as an evasion suite.
   Publish FP/FN budgets and gate CI on them. (Cisco's eval showed a
   scanner's F1 collapsing 47.7% → 13.7% on a source-disjoint holdout —
   nobody in this field knows their real rates. We will.)
2. **Phase-1 data merge** (~2–3 days): `third_party/<source>/` layout with
   per-dir LICENSE + `SOURCES.md` (upstream URL, pinned SHA, verbatim vs
   ported) + root NOTICE. Sigil core packs + a loader, GuardDog data,
   CloneGuard rules, fixture corpora. ~70 → ~450+ rules.
3. **RRF rule format + converters** from YARA/Semgrep/GuardDog meta, with
   lossy conversions *rejected and reported*, never approximated. Structural
   rules as data delete v1's hand-coded `check_*` functions.
4. **Python AST slice + reachability + taint-lite** (stdlib `ast`:
   alias resolution, entry-point reachability from hooks, TT1–TT5-style
   source→sink flows). Its real job: killing false chains — behavioral
   coupling measurement took chain detection 3.2% → 79.3% (ASE '26).
5. **OSV MAL- snapshot + registry↔repo tarball diffing** (catches
   tarball-only payloads that no repo scan can see).
6. **Action-aware gate + trust ledger**: per-action verdicts; approvals
   bound to (tree hash × action) so a rug-pull re-scan invalidates them.
7. **Rust engine**: inventory + normalization + regex/YARA-X hot loop as
   one static binary, differential-tested against Python on the eval
   corpus; scoring/correlation stay Python until semantics settle, then
   port. Watch items: serde_yaml is archived (use serde_yaml_ng),
   tree-sitter grammar ABI skew is the #1 maintenance hazard.
8. **Distribution**: name-availability pass → GitHub release (signed,
   minisign) → SKILL.md to ClawHub + skills.sh → MCP server in the official
   registry → `repogate clone` wrapper + agent PreToolUse hooks → uvx /
   Homebrew.

## What v1.1 already is (shipped during this program)

Deterministic single-file Python scanner: quarantine-first acquisition,
no excluded surfaces, context system (test/corpus/doc/skill-scope),
8 risk chains + cross-file downgrades, coverage accounting with
INCONCLUSIVE, archive self-hardening (the evasion audit found the v1
extractor itself exploitable; fixed and proven), gating/git-surface rules.
Calibration: clean CLEAN 0 · malicious skill BLOCK 100 · cloneguard
REVIEW 31 · scanner-corpus repos BLOCK with named corpus files (disclosed
context case). Independent evasion verification: see
research/evasion-verifier-results.md.

## Owner's calls

- **Name**: keep RepoGate (pending availability) or rename now, cheap.
- **License**: MIT recommended (matches the vendored MIT parts; Apache
  parts keep their license + NOTICE under third_party/).
- **Publish**: repo is built and green locally; pushing TysAIs/repogate
  public is a separate go from the owner.
