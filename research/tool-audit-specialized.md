# Tool Audit — Specialized Pre-Clone / Pre-Run Repo Scanners

**Date:** 2026-11-20 · **Method:** live sources only (GitHub repo pages crawled 2026-11-20, vendor sites, npm/PyPI search results). **No tools were installed or run.** Star/commit counts below are from GitHub pages crawled on 2026-11-20 unless noted.

**Bottom line:** All four tools exist at the claimed locations — none are fabricated. CloneGuard's claims are accurate almost to the digit. Sigil is real and the most fully featured, but its "nothing executes before scan" guarantee was **false for its pip/npm paths until v1.3.7** (by its own README's admission), and it appears quiet since ~late Oct 2026. repo-guard is real but tiny (5 stars), and two of its advertised flags are scaffolding, not implementations. ScanRepo is real and live, but it is a **hosted service with a thin CLI client**, not local open-source software; its own pages disagree on whether it has 31+ or 60+ rules, and its advertised MCP package was reported unpublished as of Sep 2026.

---

## 1. tharun208/cloneguard

**Snapshot (GitHub, crawled 2026-11-20):** Public, MIT, created 2026-11-03, 6 commits, 3 releases, **33 stars**, 0 forks. Single maintainer (Tharun Rajendran). Language: Go. URL: https://github.com/tharun208/cloneguard

| Claim | Verdict | Evidence |
|---|---|---|
| Exists at tharun208/cloneguard | ✅ Confirmed | Repo page live, crawled 2026-11-20 — https://github.com/tharun208/cloneguard |
| ~33 stars | ✅ Confirmed, exact | GitHub page shows 33 stars (2026-11-20). HN Showcase (2026-11-06) also listed 33 — https://www.hnshowcase.com/post/50397435/cloneguard-scan-a-repo-for-credential-stealing-tricks-before |
| Active Nov 2026 | ✅ Confirmed, with context | Repo *created* 2026-11-03; all 6 commits / 3 releases are Nov 2026. It is 17 days old in total — "active" is true, "established" would not be. |
| Dependency-free Go CLI | ✅ Confirmed | README: "Requires Go 1.24+. There are no third-party dependencies." Single binary via `go build`. |
| Read-only static scan; never executes scanned code | ✅ Confirmed (by design + docs) | README: "It only reads files. It never runs, installs, or imports anything from the project it scans." Line-by-line regex + per-file structural checks. |
| Detects credential theft, hidden network calls, obfuscated code, auto-run hooks | ✅ Confirmed | README "What it looks for": secret theft (SSH/cloud/browser/wallets/env dumps), suspicious network (raw IPs, Discord/Telegram webhooks, pastebins, tunnels, base64 URLs), download-and-run (eval, curl \| sh), auto-run hooks (npm scripts, `.vscode/tasks.json`, setup.py), obfuscation (`_0x` identifiers, hex escapes), checked-in binaries, and cross-category combination escalation. |
| Scans a URL (clone then scan) or a folder | ✅ Confirmed, one caveat | `cloneguard clone <url>` runs a **plain `git clone`** then scans; `cloneguard scan ./folder` scans local dirs. Caveat: the clone is not hardened (no `--no-recurse-submodules` / hooks-path neutralization documented) — clone-time vectors are a smaller risk than install-time ones, but the claim "before you clone" purists should note the tool itself clones normally. |
| License | MIT (summary didn't claim one) | GitHub repo details, 2026-11-20. |

**Detection model:** line-level regex rules (`internal/scanner/rules.go`: id, title, severity, category, scope, regex, plain-English "why") + per-file checks (package.json install hooks, tasks.json, setup.py, binary detection). Files are classified (code/config/docs/lockfile/binary) and rules apply per class; docs and lockfiles are exempt from text rules. Skips `.git`, `node_modules`, venvs, files >2 MB by default. Verdict ladder maps to exit codes 0/1/2/3 (clean/caution/suspicious/dangerous), 10 = error. Author is explicit that a clean result is not proof of safety.

**Flags / corrections:** None material. The only inflation risk is reading "33 stars, active" as maturity — it is a 6-commit, 17-day-old solo project. Its rule set is small and regex-only by its own admission.

---

## 2. NOMARJ/sigil

**Snapshot (GitHub, crawled 2026-11-20):** Public, **Apache-2.0**, created 2026-02-15, 322 commits, 15 releases / 16 tags, **6 stars**, 3 forks. Maintainer: NOMARK (nomark.ai / sigilsec.ai); roadmap doc names founder/CTO "Reece." Note the naming mess in their own docs: GitHub org is `NOMARJ`, brand is `NOMARK`, and the roadmap variously references `nomark/sigil` and `nomarj/tap`. URL: https://github.com/NOMARJ/sigil · Site: https://sigilsec.ai

| Claim | Verdict | Evidence |
|---|---|---|
| Exists at NOMARJ/sigil; site sigilsec.ai | ✅ Confirmed | Repo + site live, crawled 2026-11-20. |
| Quarantine-first CLI for repos, packages, AI-agent tooling | ✅ Confirmed | README: `sigil clone` downloads into quarantine and scans before approval; `sigil pip` / `sigil npm` fetch into quarantine; `sigil approve` pins a digest in a trust ledger, `sigil reject` deletes. |
| Apache 2.0 | ✅ Confirmed | GitHub repo details + LICENSE, 2026-11-20. |
| 8-phase analysis: install hooks, obfuscation, exfil, credentials, prompt injection | ✅ Confirmed, one word wrong | README phase table lists exactly 8 free phases: Install Hooks, Code Patterns, Network/Exfil, Credentials, Obfuscation, Provenance, Prompt Injection, Skill Security (a 9th, LLM Analysis, is paid Pro). But these are **static** phases — the site FAQ itself says "8-phase static analysis." The summary's word "behavioral" is a mischaracterization; nothing is executed or observed at runtime. |
| "Before anything executes" | ⚠️ **Was false until v1.3.7** | The project's own README: "Up to 1.3.7, `sigil pip` let pip run a source distribution's `setup.py`, and `sigil npm` of a local directory or git spec let `npm pack` run its lifecycle scripts, **before the scan**." Current version downloads prebuilt wheels only (pip) and the registry tarball with integrity check (npm), and refuses path/URL/git specs. Anyone on ≤1.3.7 does not have the advertised guarantee. |
| Actively developed | ⚠️ Partially — no Nov 2026 activity confirmed | v1.2.0 release page was crawled ~2026-10-24 (https://github.com/NOMARJ/sigil/releases/tag/v1.2.0); README references 1.3.x behavior, so development continued past 1.2.0. However, HEAD commit `5b37972` on 2026-11-20 is the same commit pinned in crawls from 26–32 days earlier — the repo appears quiet for roughly the last month. |
| Star count | Not claimed numerically ("lower stars") — actual: **6 stars** | GitHub, 2026-11-20. Far smaller footprint than its marketing surface (multi-channel distribution, IDE plugins, threat-intel stats) suggests. |
| Marketing metrics (site: "293,667 scans"; roadmap: "97.96% detection rate, Azure production dataset"; "314 malicious AI skills, Feb 2026") | ❌ Unverifiable / self-reported | All figures come from Sigil's own site/docs with no independent source. The README's accuracy section is more honest (small 20-package clean control set, static phases only, single run) — credit for that, but treat headline numbers as marketing. |
| MCP server auto-registration | ⚠️ Docs admit a gap | Plugin docs note `@nomark/sigil-mcp-server` v1.3.0 "is not yet published to npm, so the automatic npx-based registration takes effect once the package is published" (and the package name in that doc is spelled `nomark` vs the org `NOMARJ`). |

**Detection model:** Rust CLI (plus a legacy bash prototype), fully offline for the free tier. Weighted phase scoring, but the **verdict is evidence-gated, not score-gated**: LOW findings never raise the verdict; HIGH requires a High/Critical finding in code the package actually runs; CRITICAL requires one standalone-evidence Critical rule or Critical findings from two different rules. Findings carry remediation text; suppression is inline (`# sigil:ignore RULE-ID -- reason`) and remains visible in reports as suppressed. Outputs include table/JSON/SARIF/HTML. Also ships: a Claude Code plugin whose PreToolUse hook intercepts `git clone` / `npm install` / `pip install` / curl-pipe-shell and reroutes through quarantine (with `SIGIL_BYPASS=1` escape hatch), VS Code/JetBrains plugins, a GitHub Action, and a `sigil residue` command that audits what previously installed tooling left on the machine (shell rc edits, cron/launchd/systemd entries, git hooks, credential file permissions) with plan/apply/rollback.

---

## 3. WBChain3/repo-guard

**Snapshot (GitHub, crawled 2026-11-20):** Public, MIT, created 2026-05-17, 25 commits, **0 releases** (1 tag), **5 stars**, 0 forks. Solo maintainer (WBChain3). Language: Python 3.10+. URL: https://github.com/WBChain3/repo-guard — note: it did **not** surface in general web search; it is findable only by direct URL. The name collides with at least four unrelated "RepoGuard" projects (repoguard-py, repoguard-tool, DLR-SC/RepoGuard, etc.).

| Claim | Verdict | Evidence |
|---|---|---|
| Exists at WBChain3/repo-guard | ✅ Confirmed | Repo page live, crawled 2026-11-20. |
| True pre-clone scanner using the GitHub API, no clone | ✅ Confirmed | README: "repo-guard fetches repository metadata via the GitHub API **without cloning**." Detection is deterministic (scored signals, regex, API lookups); "No repository contents are sent to external AI APIs." Scanned code is never executed — nothing is downloaded except API responses (file contents fetched via API for the hook/VS Code scanners). |
| Focus: malicious VS Code tasks, git hooks, IOCs | ✅ Confirmed | Four modules: **VS Code Scanner** (`.vscode/tasks.json` `runOn: folderOpen`, `settings.json` `allowAutomaticTasks`), **Hook Scanner** (`.githooks/` execution patterns, base64 payloads, comment-to-code ratio), **IOC Extractor** (URLs, domains, Ethereum addresses, IPs, base64 payloads; optional VirusTotal enrichment), **Trust Score**. |
| Trust signals incl. account age | ✅ Confirmed | Trust Score module: account/repo age, followers, contributors, suspended contributors, force-push indicators (README "The Gap" + module table). |
| Built after a Lazarus Group-style recruitment scam | ✅ Confirmed (self-reported, consistent) | README "The Story": fake-recruiter LinkedIn approach, `.vscode/tasks.json` auto-run + `.githooks/post-checkout` payload + .env.local private-key social engineering; author reports filings with FBI IC3, RCMP, GitHub, LinkedIn. Repo topics include `contagious-interview`, `lazarus-group`. Consistent with the documented Contagious Interview campaign pattern; the personal incident itself is unverifiable, as expected. |
| "Recent activity" (group claim in the summary) | ⚠️ Not verified — likely stale | Created 2026-05-17; 25 commits; no releases. README lists `--preview` and `--recruiter` as "**scaffolded**, full implementation coming in v0.2.0" — i.e., two advertised features are stubs, and there is no evidence v0.2.0 ever shipped. No Nov 2026 activity could be confirmed. |
| `pip install repo-guard` | ⚠️ As documented; package ownership unverified | README's Quick Start says `pip install repo-guard`. Given the heavy name collision on PyPI (multiple unrelated repoguard packages), I could not independently confirm the PyPI `repo-guard` name maps to WBChain3. Treat the install path with care and verify provenance before use. |

**Context the summary omitted:** the README itself notes VS Code 1.109+ (Feb 2026) disables automatic task execution by default — the VS Code vector is blunted on current editors (still live via `.githooks/`, older VS Code, and workspace-trust social engineering). Also: public repos only unless a GitHub token is supplied; VirusTotal enrichment is rate-limited (500 lookups/day free tier).

**Detection model:** API-first, four independent deterministic modules, color-coded risk report, JSON output. Narrow by design — it does not do general code-pattern scanning of the whole tree; its depth is concentrated on the editor/hook/metadata surface the other tools treat as one category among many.

---

## 4. ScanRepo (scanrepo.dev)

**Snapshot (site live, crawled 2026-11-20):** Hosted web scanner + npm CLI + advertised MCP server. Operator appears to be solo developer Ruben Marcus (his GitHub profile lists ScanRepo as his project: https://github.com/rubenmarcus). Live counters on the homepage claim ~227 scans/day. URLs: https://www.scanrepo.dev · https://www.scanrepo.dev/cli · https://www.scanrepo.dev/about · https://www.scanrepo.dev/scams

| Claim | Verdict | Evidence |
|---|---|---|
| Web + CLI at scanrepo.dev / `npx scanrepo github.com/owner/repo` | ✅ Confirmed | CLI docs live at https://www.scanrepo.dev/cli: `npx scanrepo`, `npm i -g scanrepo`, `--json`, `--token`, exit codes 0/1/2. |
| Static analysis on a tarball snapshot; nothing cloned or executed | ✅ Confirmed — but read the fine print | FAQ: "It downloads a tarball snapshot of one commit and runs static analysis only — nothing is cloned, installed, or executed **on your machine or ours**." The scan runs **server-side on scanrepo.dev**; the CLI is a client of the hosted API (the mkdev-ai Chrome extension's integration doc describes the same `POST /api/scan` contract). Nothing is downloaded to your machine because nothing is scanned on your machine. |
| 31+ rules | ⚠️ Internally inconsistent | Homepage, CLI page, and the owner's profile say "31+ rules, 6 risk categories." The About page and MCP page say "**60+ detection rules**" (About adds entropy analysis + import graph). Both numbers are the operator's own; they cannot both be the current count. The claim quoted the conservative figure. |
| 6 risk categories | ✅ Confirmed | Homepage: credential theft, data exfiltration, obfuscated payloads, supply-chain attacks, injection patterns, known-scam repos/accounts. |
| Curated IoC list for malware/crypto scams | ✅ Confirmed | https://www.scanrepo.dev/scams — public database of Lazarus/DPRK developer-scam infrastructure: 17 accounts, 30 repos, 34 profiles, plus fake-interview platforms and C2/exfil domains, with a report-a-scam intake. |
| Detection corpus is open source | ⚠️ Partially verified | Site FAQ asserts "the detection corpus is open source" and the scams DB is publicly browsable/contributable. However, **no public source repository for the scanning engine was found** — the only GitHub artifacts are the owner's profile and a Chrome extension (mkdev-ai/scanrepo-chrome-extension). "Corpus open, engine closed (or at least unlocated)" is the accurate statement. |
| MCP server for agents | ⚠️ Advertised; availability disputed | https://www.scanrepo.dev/mcp advertises `npx -y scanrepo-mcp` exposing `scan_repo` / `repo_verdict`. The Chrome extension repo's integration notes (verified 2026-09) state the MCP server is "**not** usable… `scanrepo-mcp` is unpublished." Unresolved as of this audit — do not count on it without testing. |
| Privacy posture | ⚠️ Note for adopters | CLI scans are **published to scanrepo.dev's public feeds by default**; `--no-publish` opts out. Results are cached and shared publicly (site FAQ). Fine for public repos; a real consideration for anything sensitive. Private repos are not supported. |
| Coverage honesty | ✅ Credit where due | About page: repos are capped at 3,000 content-scanned files and reports show real coverage. A live scan page (2026-11-16) showed 253/8,705 files scanned (3%) with an explicit **INCONCLUSIVE** verdict rather than a confident score — https://www.scanrepo.dev/scan/github/Comett1225/AbsentMotion |

**Detection model:** server-side static rules across JS/TS, Python, Rust, Go, shell (code execution, exfiltration, credential theft, obfuscation, supply-chain), plus statistical passes (entropy, import graph per About/MCP pages), 0–100 risk score, verdict, per-finding file/line. Engine version "v10" per scan pages. GitHub + Bitbucket, public repos only.

---

## Cross-cutting flags

1. **None of the four is battle-tested.** Combined GitHub stars: 33 + 6 + 5 + (ScanRepo: no public repo). All are solo-maintainer projects; the oldest (Sigil) dates to Feb 2026. The summary's framing ("newer and lower-star… the space is still young") is accurate.
2. **Two of the four have honesty problems in their own materials:** Sigil's pre-1.3.8 execution hole (disclosed, fixed — but it means the headline guarantee has a version asterisk forever) and ScanRepo's 31+ vs 60+ rule-count self-contradiction plus an apparently unpublished MCP package.
3. **Two different architectures hide under the same "pre-clone" label:** CloneGuard and repo-guard run locally (CloneGuard after a normal clone; repo-guard truly pre-clone via API). Sigil downloads into a local quarantine. ScanRepo sends the repo reference to a third-party server and publishes results by default. For a tool whose job is vetting untrusted code, that difference matters.
4. **Activity check (project freshness rule):** CloneGuard — Nov 2026, current. Sigil — active through ~Oct 2026, HEAD unchanged for ~a month. repo-guard — created May 2026, no confirmed recent activity, promised v0.2.0 features still stubbed in the README. ScanRepo — service live and scanning daily as of 2026-11-20.

---

## Steal these ideas (for RepoGate)

**From CloneGuard**
- **Zero-dependency, single-binary, read-only as a design law** — the scanner must be safe to point at hostile input; state the invariant in the README's first paragraph.
- **File classification before rules** (code / config / docs / lockfile / binary) so patterns only fire where they're meaningful — kills whole classes of false positives.
- **Cross-category combination escalation**: one file that touches credentials AND a suspicious network destination AND dynamic execution is escalated to critical — correlation beats any single regex.
- **Rule format**: `{id, title, severity, category, scope, regex, why}` with a plain-English "why" and a test per rule; findings always show file, line, snippet.
- **Verdict→exit-code ladder** (0 clean / 1 caution / 2 suspicious / 3 dangerous / 10 error) designed for hooks and CI from day one.
- **Bundled deliberately-malicious demo repo** as a living test fixture.
- **A "Limits" section that says clean ≠ safe** and recommends a throwaway VM anyway.

**From Sigil**
- **Quarantine-first as the workflow, not a feature**: replace `git clone` / `pip install` / `npm install` entry points with fetch-into-quarantine → scan → human approve/reject, with a **trust ledger** (approval pins the item's digest).
- **Evidence-gated verdicts**: the verdict follows evidence classes, not the raw score — lone Low findings never escalate; CRITICAL requires standalone evidence or two independent Critical rules. This is the best anti-false-positive design in the set.
- **Provenance as a scan phase**: git history depth, author count, binary files, hidden files.
- **Prompt-injection and skill-security phases** for agent artifacts (instruction injection in code/docs/tool descriptions; MCP permission escalation; over-broad tool grants) — the category the other three lack.
- **Inline suppressions that stay visible**: `# sigil:ignore RULE-ID -- reason` keeps the finding in the report marked suppressed instead of silently dropping it.
- **Behavior rollups + letter grade** (exfiltration / persistence / harvests_credentials) on top of raw findings.
- **Safe package fetching**: pip = prebuilt wheels only, never build an sdist pre-scan; npm = registry tarball verified against registry integrity; refuse path/URL/git specs by default. (And publish the version history of this guarantee — Sigil's own 1.3.7 disclosure is the cautionary tale.)
- **Agent-layer enforcement gate**: a PreToolUse-style hook that intercepts clone/install/curl-pipe commands and reroutes them through quarantine, with an explicit, logged bypass.
- **Residue scanning**: audit what already-installed tooling left behind (shell rc edits, cron/launchd/systemd, git hooks, credential file modes) with plan → apply → rollback.

**From repo-guard**
- **A true pre-clone stage via the GitHub API**: metadata + targeted file fetches before anything lands on disk — the only design here with zero local footprint pre-verdict.
- **Trust signals as a scored module**: account age, followers, contributor count, suspended contributors, force-push indicators.
- **A dedicated `.githooks/` scanner** — the vector the generalists underweight — including the **comment-to-code ratio heuristic** (payloads hidden under decoy comments).
- **Editor-auto-run specifics**: `runOn: folderOpen` in tasks.json, `allowAutomaticTasks` in settings.json, checked as structured config, not text patterns.
- **IOC extraction as a first-class module** (URLs, domains, crypto addresses, IPs, base64 blobs) with optional VirusTotal enrichment, and a **community IOC feed file** in-repo fed by real-world scans.
- **Recruiter-context input**: let the scan be informed by the social-engineering pretext (who sent this repo and why). repo-guard only scaffolded it — implementing it properly is an open lane.
- **Deterministic-only detection with a stated privacy property**: no repo contents sent to external AI APIs.

**From ScanRepo**
- **Tarball-snapshot acquisition**: one request, the whole repo at a pinned commit, no clone semantics and no hook surface at all.
- **Coverage accounting in every report**: files scanned / total files, and an explicit **INCONCLUSIVE** verdict when coverage is too low to trust — never let a 3%-coverage scan print a confident score.
- **Statistical passes beyond rules**: entropy analysis and an import graph over the snapshot.
- **A public, browsable known-scam database** (repos, accounts, profiles, C2 domains) with a report-a-scam intake — threat intel as a community asset, separate from the engine.
- **Zero-install entry point**: a web page anyone can paste a URL into, with the CLI/MCP exposing the identical engine and the identical exit-code contract (0/1/2).
- **An honest-limitations page as a first-class page** ("a static scanner sees code, not behavior; LOW means nothing found, never safe").

**Cross-cutting**
- Every tool here converges on the same contract: **score + verdict + per-finding evidence + machine-readable output + CI-friendly exit codes**. SARIF output (Sigil) is worth adding for GitHub Security-tab integration.
- The strongest composite architecture is: repo-guard's API pre-clone stage → ScanRepo's tarball snapshot + coverage accounting → CloneGuard's classified rule engine with combination escalation → Sigil's quarantine/trust-ledger workflow, provenance + prompt-injection phases, and evidence-gated verdicts — all local, unlike ScanRepo's hosted model.
