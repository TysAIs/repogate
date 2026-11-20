# RepoGate — design (working draft, Nov 20, 2026)

One read-only scanner an agent runs BEFORE cloning, installing, or running any
third-party repository or AI agent skill. Merges the best of: NVIDIA
SkillSpector (AI-skill scanning), DataDog guarddog (package malware rules +
risk chains), cloneguard (read-only static scan), sigil (quarantine-first),
repo-guard (pre-clone GitHub API + trust signals), ScanRepo (tarball snapshot,
nothing executed). Claims about each are being verified live before any idea
is absorbed (see research/).

## Hard invariants
1. NEVER executes scanned code. No install, no import, no hooks. Static only.
2. Acquisition is quarantine-first: GitHub API tarball or local copy into a
   quarantine dir; the scan verdict gates any move out of quarantine.
3. Clean scan = "nothing found", never "safe". The report says so in words.
4. Zero third-party dependencies: Python 3 stdlib only, so any agent host can
   run it with no install step. (Stack note: Rust considered; stdlib
   Python wins on agent portability — rules and fixtures port later.)

## Pipeline
acquire (dir | zip/tar | github URL via API tarball, no git clone needed)
  -> inventory (file list, sizes, binary detection, symlink escape check)
  -> rule engine (rules/*.yaml-style packs, regex + structural checks)
  -> AI-skill pack (SKILL.md / MCP configs / prompt files: injection,
     hidden unicode, tool-poisoning, exfil instructions)
  -> metadata & trust signals (repo age, license, archived — context only,
     never moves the verdict alone)
  -> risk chains (correlation: credential-read + network-send in same file or
     package = critical chain; install-hook + remote fetch = critical chain)
  -> verdict + report (JSON + human text; exit 0 clean / 1 findings / 2 error)

## Rule categories (v1)
- lifecycle-hooks: package.json preinstall/postinstall/prepare, setup.py /
  pyproject build hooks, Cargo build.rs executing commands, Makefile
  install targets with curl, .gitmodules + hooks, husky, lefthook
- autorun-configs: .vscode/tasks.json (auto-run), devcontainer
  postCreateCommand/postStartCommand, .envrc (direnv), GitHub Actions
  (pull_request_target, workflow_run, script injection via ${{ }}),
  .github/workflows curl|bash
- network-exfil: raw-IP URLs, webhook endpoints (discord/telegram/pastebin/
  requestbin), cloud metadata 169.254.169.254, DNS-tunnel patterns,
  curl/wget piping to shell, base64 payload fetch-and-run
- credential-access: reads of ~/.ssh, ~/.aws, ~/.gnupg, .env files, browser
  cookie stores, /etc/passwd scraping, env-dump (printenv, os.environ full
  serialization) — severity escalates when paired with any network call
- obfuscation: long base64/hex blobs decoded into eval/exec, string-split
  evasion, unicode homoglyph/zero-width in code and prompts, minified single
  lines > threshold, entropy outliers in scripts
- prompt-injection (skill pack): "ignore previous instructions", hidden
  instructions in comments/HTML, instructions to exfiltrate files or secrets,
  MCP tool descriptions that instruct the agent, SKILL.md directing network
  calls or shell use unrelated to the stated skill purpose
- supply-chain: dependency names one edit away from popular packages,
  dependencies pinned to git URLs / tarballs instead of registries,
  postinstall in dependencies, lockfile absent on a package that ships code

## Scoring
Per-finding severity (info/low/medium/high/critical) with per-category caps
so one noisy category cannot flood the verdict; chains add their own finding
at the higher severity. Verdict bands: CLEAN / REVIEW (low+med) / BLOCK
(any high or critical, or any completed risk chain).

## Audit-driven requirements (Nov 20, 2026 — from research/tool-audit-*.md)
The scrutiny of the six named tools produced hard requirements; the summary
the owner received had real errors (GuardDog dropped Semgrep in 3.0 and its last
release is Aug 2026; Sigil's "nothing executes first" was false on its pip/npm
paths until v1.3.7; ScanRepo is a hosted service that publishes scan results
publicly by default). Design against the PROVEN bypasses:
1. NO excluded surfaces. node_modules, vendor dirs, and docs are scanned.
   SkillSpector scored a node_modules-hidden payload 6/100 SAFE (Checkmarx).
2. Bytecode is a finding. .pyc/.pyo or bundled binaries = opaque executable
   content, flagged, never trusted (Trail of Bits bypass).
3. Deterministic core. No LLM anywhere in the verdict path (SkillSpector's
   LLM stage scored the same skill 6 then 32 a minute apart).
4. Coverage accounting. Every file counted: scanned / partial / skipped with
   reason. Partial coverage caps the verdict at INCONCLUSIVE (ScanRepo's one
   genuinely best-in-class behavior).
5. Anti-truncation. Oversized files are head+tail scanned and marked partial,
   never silently skipped (whitespace-truncation bypass).
6. Anti-evasion normalization before matching: join split string literals,
   decode base64 runs and rescan, flag (and strip) zero-width/bidi unicode.
   getattr-style indirection is itself a pattern (SkillSpector AST9 lesson).
7. Local only. Nothing about a scan leaves the machine (anti-ScanRepo rule).
8. Fetch-at-runtime is a pattern: code that downloads its real payload from a
   mutable URL at run time gets flagged as un-scannable-by-design (Air
   Security bypass class).
9. Correlation over counts: GuardDog-style capability x threat chains with a
   transparent weighted score; metadata signals (typosquat, new install
   script, git-URL deps) as their own detector family.
10. Gate contract: documented exit codes (0 clean, 1 review/inconclusive,
    2 block, 3 tool error), JSON + text + SARIF-shaped findings.

## v1.1 calibration record (Nov 20, 2026)
Context system: findings carry a `contextual` flag — test/demo trees, signature
corpora (path-named rules/yara/iocs files tripping >=5 distinct rules), and
docs outside a SKILL.md subtree are listed at full detail but never score and
never complete chains. Same-file chains need a >=medium network leg (a bare
fetch primitive is not egress) and skip corpus-density files (>=8 distinct
rules). Auto-run surfaces lose their always-live status at depth >=3 inside
test trees (a nested fixture's tasks.json is a specimen; a root one is live).
Measured: clean fixture CLEAN 0; malicious-skill fixture BLOCK 100 (5 chains);
cloneguard REVIEW 31 (its shipped demo folderOpen task is the top live
finding — correct). Known hard case, disclosed not tuned away: scanner repos
whose own modules carry pattern strings (repo-guard's hook_scanner.py,
sigil's tree) still BLOCK — the findings name the exact files, and a human
sees in one read that they are the tool's own detection corpora. The field
solves this with allowlists; v1.1 ships the disclosure instead.
Evasion-catalog fixes applied in v1.1: archive hardening (containment via
parent-check not string prefix, member/total/ratio caps, tar filter=data,
device members rejected — the pre-fix extractor was itself exploitable),
symlinked-directory coverage denting, environment/timing gating rules,
fetch-primitive chain evidence, .gitmodules/.gitattributes/LFS rules,
decode-on-normalized-text with depth-2 recursion, cross-file chains at
one severity downgrade.

## v1.2 calibration record (Nov 20, 2026, post independent-verification)

An independent agent attacked v1.1 with 10 fresh evasion fixtures; v1.1
caught 4 at the deserved verdict (results:
research/evasion-verifier-results.md). v1.2 fixes, all regression-tested:

- Nested archives and OOXML containers (.zip/.docx/.xlsx/.jar/.whl/...)
  inside a tree are extracted with the hardened path and scanned
  recursively (depth 2, paths prefixed archive!/). Kills the nested-zip
  and docx-PI hard misses.
- Bytecode (.pyc/.class/.wasm) is string-scanned (ASCII + UTF-16LE string
  table) instead of merely inventoried; a URL-in-bytecode rule and
  chain-eligibility for bytecode files complete the stealer shape.
  Coverage no longer claims inspection it did not do.
- Constant propagation: string variables are substituted and re-folded
  before scanning, so payloads split across variables (base64 parts,
  "sys"+"tem" via variables) re-form. Base64 decode threshold lowered
  120 -> 40 chars (printability gate unchanged). eval/exec on a
  non-literal argument is now a high finding on its own.
- Prompt-injection rules also scan code files (agents read comments);
  outside skill scope those hits demote one level as quoted context.
- Cross-file stealer completes on the weakest net leg when the package
  also executes, and on a private-key leg (SSH keys / AWS credentials in
  one file + any egress in another) with no execution at all.
- Findings dedupe per (rule, file) across variants — no double-counting
  when raw and propagated text both match.

Re-verified: verifier set 10/10 BLOCK; bundled fixtures pass;
sigil still BLOCK 100 (scanner-corpus context case, unchanged).
cloneguard and repo-guard could not be re-checked: both GitHub repos
return 404 as of ~04:25 MST (deleted, renamed, or made private since the
v1.1 calibration earlier the same night) — recorded as an external
change, not a scanner result.

## v1.3 calibration record (Nov 20, 2026, FP-baseline response)

v1.2 measured 0 CLEAN / 2 REVIEW / 10 BLOCK on popular benign repos — the
detectors were real, the verdicts unusable. v1.3 is the calibration pass;
full record in research/fp-fixes-1.md. Principles that now govern tuning:
(1) demoted/contextual findings never complete chains; (2) cross-file
correlation requires a credential-STORE leg on an executable surface —
data describing a capability is not the capability; (3) scoring is
diminishing per rule (first finding full weight, repeats +1) and a
score-only BLOCK does not survive bulk (>500 files, no chain, no surface
critical → REVIEW cap); (4) a lone critical forces BLOCK only on an
executable surface, a completed chain, or a live prompt-injection
finding. Result: benign set lands 2 CLEAN / 8 REVIEW / 1 BLOCK
(nuclei-templates, documented true-context), fixture suite fully green,
and the same pass repaired const-propagation (three silent bugs) and
made fixture 09 regress the varcat reflection catch instead of a literal
payload string. Perf on reference trees improved ~2.9x (django 131s →
45s) via the Tags guard, pattern precompilation, and variant gates.
