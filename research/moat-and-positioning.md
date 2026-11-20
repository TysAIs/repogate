# RepoGate — Moat & Positioning Research

**Date compiled:** 2026-11-20
**Freshness rule applied:** Sep–Nov 2026 sources weighted as current and marked **[CURRENT]**.
Feb–Aug 2026 marked **[RECENT-ESTABLISHED]**. Foundational or vendor-claim material flagged where used.

---

## Positioning statement (one line)

> **RepoGate is the pre-flight gate for the agent era: it scans any repo, skill, or zip — locally, offline, in a single zero-dependency file — *before* anything opens, installs, or runs it, and hands your agent a verdict it can act on.**

Every incumbent scans something narrower (a registry package, a lockfile, an installed inventory, a CI pipeline) or somewhere else (their cloud). RepoGate's claim is the **moment** (before first contact), the **input** (anything, from anywhere), and the **consumer** (the agent itself, not a security team's dashboard).

---

## The 3 defensible wedges

### Wedge 1 — The gate moment nobody owns: pre-open, pre-install, pre-read, for arbitrary artifacts

The late-2026 compromise moment is *earlier and weirder* than any incumbent's scan point:

- **Poisoned Coding Assessment (TL-2026-5876, disclosed 2026-06-19, detections updated 2026-11-12) [RECENT-ESTABLISHED → CURRENT]:** a fake recruiter's take-home repo with **no malicious binary, script, or exploit at all** — hidden instructions in `.cursor/rules`, `CLAUDE.md`, README HTML comments, and `.cursor/mcp.json` coerced the victim's own AI agent into running `cat ~/.aws/credentials`, `aws sts get-caller-identity`, and recursive secret greps. Full theft chain in ~1m51s, executed by the agent, not by malware. No package scanner sees this: there is no package, and nothing is "installed" — the repo is merely *opened and read*.
- **SOMBERMEME (Google GTIG, reported 2026-11-16) [CURRENT]:** a suspected North Korea-linked cluster poisoned `.claude/settings.json` inside repositories so that **starting Claude Code** auto-downloaded a backdoor. The execution boundary was opening the project in the agent — exactly RepoGate's pre-open gate, and a file class (agent project settings) that package/CI scanners do not model.
- **FakeGit / AgentBaiting (Island, via CSA research note 2026-07-21) [RECENT-ESTABLISHED]:** ~7,600 malicious GitHub repos from ~6,600 fabricated profiles, 600+ listings across LobeHub, Glama, MCP.so and MCP Market impersonating skills/MCP servers, >14M release-asset downloads. The named technique — **AgentBaiting** — is that Claude Code, Gemini and ChatGPT *independently discover the malicious repos and surface the attacker's install instructions to users*. The scanner therefore has to sit where the agent acts, callable by the agent, at the moment the agent finds something — not in a CI pipeline the victim doesn't have.
- **First-person recruiter cases, Oct–Nov 2026 [CURRENT]:** e.g. Krasavina (2026-11-09): two fake recruiters in one day; payload hidden after **204 spaces in `next.config.js`**; delivery via **Google Drive folder**, not a registry. Drive zips, gists, chat attachments, and random repos with no lockfile are outside every incumbent's input model (Socket/Snyk SCA/OSV-Scanner all key off manifests and registry packages).

**Why it's defensible:** incumbents are architecturally anchored to their scan point — Socket to dependency manifests in repos it has app access to, StepSecurity to GitHub Actions runners, Snyk Agent Scan to *discovering what is already installed on the machine*, OSV-Scanner to lockfiles. Moving to "scan this arbitrary thing before first contact" is a different product, not a feature toggle, and the platforms' own native scanning (below) explicitly excludes the surfaces where these attacks live.

### Wedge 2 — Local-only, zero-egress, zero-dependency: the only scanner that never phones home

Verified egress behaviour of the field, Nov 2026:

| Tool | What leaves the machine |
|---|---|
| Socket | Dependency snapshot (manifests/lockfiles) uploaded to Socket's cloud; GitHub App requires read/write repo access; "Managed Scans" clone your repos onto Socket infrastructure (docs.socket.dev, crawled Nov 2026) |
| Snyk Agent Scan | Full detection `scan` **requires a `SNYK_TOKEN` and sends findings to Snyk's hosted analysis endpoint** (`api.snyk.io/hidden/mcp-scan/…`); only the `inspect` subcommand works token-free (per Snyk's own toxicskills-goof repo notes, crawled Nov 2026) |
| NVIDIA SkillSpector | LLM stage (the default) sends file contents to the configured model provider; even `--no-llm` still sends dependency names/versions to api.osv.dev (README, via aidefensestack 2026-11-03) |
| VirusTotal | Uploaded files are **shared with premium customers, AV vendors and the community dataset — permanent and non-retractable** (GTI docs, updated 2026-11-10); 32 MB default API limit |
| ScanRepo | Hosted service; publishes scan results publicly by default (per RepoGate tool audit, Nov 2026) |
| **RepoGate** | **Nothing. Single Python file, stdlib only, no network calls; known-bad matching can run against a vendored local OSV feed.** |

This matters commercially, not just ideologically: the artifacts most worth scanning are precisely the ones you cannot upload — a client's proprietary repo, an unreleased skill, a recruiter zip you're suspicious of (uploading it to VT *publishes* it), anything on an air-gapped or client-isolated machine (e.g. an air-gapped homelab). It also means RepoGate runs **inside agent sandboxes with no network and no install step** — `python3 repogate.py` is already there. Zero dependencies is also a security property: the scanner adds no supply chain of its own (see Risk 5).

### Wedge 3 — An action-aware verdict built for an agent to consume, not a report built for a human to file

- Incumbent outputs terminate in humans: Socket/Snyk/Aikido dashboards and PR comments, StepSecurity CI annotations, VT web reports, Scorecard numbers. SkillSpector comes closest with exit codes — but its score is demonstrably noisy at the gate: one practitioner's 30 production skills scored **100 / CRITICAL with 52 findings, 8 of 11 HIGHs being structural false positives**, requiring a hand-built "trust manifest" post-filter to become usable (getcommit.dev). A gate an agent hits 10× a day must be *calmer* than a report a human triages once.
- RepoGate's contract is a small action ladder — `CLEAN` (proceed), `REVIEW` (show the human the named chain), `INCONCLUSIVE` (coverage was partial; an unscanned file is never silently clean — re-scan or escalate), `BLOCK` (refuse) — plus **named risk chains** (STEALER, DROPPER, HOOK DROPPER…) that explain *the mechanism*, which is what an agent needs to brief its user in one sentence.
- It ships **as** the thing it protects: a `SKILL.md` (installable by Claude Code / Hermes / OpenClaw via skills.sh or ClawHub) and an MCP server surface, so the protected agent carries its own gate. The precedent that agent-hook distribution works already exists: `osv-guard` (Sep 2026) ships as a Claude Code plugin whose hook checks installs against OSV and *cannot be talked out of the decision by the agent* — RepoGate generalises that pattern from "known-bad package names" to "any artifact, full content, before contact."

---

## Gaps table — what each incumbent does NOT do (verified, Nov 2026)

Legend: ● does it · ◐ partial / gated / different moment · ○ does not do it

| Capability | Socket | Snyk (+ Agent Scan) | StepSecurity | Aikido | OSV-Scanner | VirusTotal | SkillSpector | Anthropic native | **RepoGate** |
|---|---|---|---|---|---|---|---|---|---|
| Local-only, zero egress | ○ snapshot uploaded | ○ token + hosted analysis for detection | ○ cloud/CI service | ○ cloud platform | ◐ API by default; offline DB mode exists | ○ upload = publication | ◐ `--no-llm` still queries OSV | ○ cloud, Enterprise tenant | ● |
| Works offline / air-gapped | ○ | ○ | ○ | ○ | ◐ with downloaded DB | ○ | ◐ static-only, bundled fallback list | ○ | ● |
| Agent skills (SKILL.md) as first-class input | ○ | ● Agent Scan `--skills` (cloud-gated) | ◐ AI Package Analyst covers packages, not skill folders | ○ | ○ | ◐ VT Code Insight (heuristic LLM, known FPs) | ● its home turf | ◐ Enterprise only, exclusions below | ● |
| MCP servers / tool poisoning | ○ | ● (Invariant/mcp-scan lineage) | ○ | ○ | ○ | ○ | ● MCP categories | ○ **MCP servers explicitly excluded** | ● descriptions + configs |
| Pre-OPEN (editor/agent) gating: tasks.json folderOpen, `.claude/settings.json` hooks, devcontainer, direnv | ○ | ○ (post-install inventory) | ○ (CI runtime) | ○ | ○ | ○ | ◐ scans a skill dir; editor-config surfaces not its model | ○ | ● |
| Prompt injection in docs/configs as a verdict input | ○ | ● via LLM (cloud) | ○ | ○ | ○ | ○ | ● patterns + LLM | ◐ pass/warn/fail on upload/edit | ● deterministic + decode-rescan |
| Action-aware verdict for an agent (exit-code ladder + named chains) | ○ dashboard/PR | ◐ report + severity | ○ CI annotations | ○ dashboard | ◐ exit code on known-bad only | ○ web report | ◐ exit codes, noisy score | ◐ admin-facing pass/warn/fail | ● |
| Non-package artifacts: random repo, gist, Drive/chat zip, loose files | ○ manifests only | ◐ local dirs of agent components | ○ | ○ repos via platform | ○ lockfiles/manifests | ◐ single files ≤32 MB API | ● dir/zip/URL/file | ○ uploads inside Enterprise Claude | ● |
| No account, token, or install step | ○ | ○ SNYK_TOKEN for detection | ○ | ○ | ● | ○ API key | ◐ Python pkg install | ○ Enterprise plan | ● single file |

**Notes on the two closest threats:**

- **Snyk Agent Scan** (mcp-scan, from the Invariant Labs acquisition; shipped RSAC Mar 2026) is the strongest incumbent in agent space — tool poisoning, toxic flows, skill scanning. Its gaps are structural: detection is a cloud call with a Snyk token (privacy + offline fail), its moment is *inventory of what's already on the machine* rather than *gate before acquisition*, and Snyk's own position (Feb 2026, "Why Your Skill Scanner Is Just False Security") is that deterministic scanning of SKILL.md is inadequate — they are committed to the LLM-in-cloud architecture RepoGate deliberately is not.
- **Anthropic's native scanning** (announced 2026-08-06; on by default for Enterprise orgs 2026-10-02; beta) **[RECENT-ESTABLISHED, gap analysis CURRENT via IntuitionLabs, ~Nov 10 2026]:** covers only skills/plugins **uploaded or edited inside Claude Enterprise**. It explicitly excludes **MCP servers**, skills delivered via a connected MCP server, skills that existed before enablement, and skills Claude created; tenants on CMEK, ZDR, or HIPAA configurations are excluded entirely. Consumer, Pro/Max, and Claude Code users get nothing. Cursor's native story is run-modes + Workspace Trust + cloud PR security review — no pre-install skill/repo vetting. No native vetting surfaced for Codex or Hermes in Nov 2026 sources. **The platforms are building admin tooling for enterprises; nobody is building the individual agent user's gate.**

**Indie crowding (honesty check):** the wedge is already contested at the small end — **Repo Run Check** (Oct–Nov 2026; free offline CLI + MCP server on Glama, `npx devx-repo-check`, paid full tier via x402), **Flagrix** (pre-clone guide + scanner; checks folderOpen tasks, `.claude` hooks, MCP configs; matches deps against a *locally downloaded* OSV feed — 222,877 npm + 11,992 PyPI names as of 2026-11-09), and **repoc-cli** (PyPI; default remote scan is metadata-only, does not download the source tree). All three are narrow: a handful of known files (Repo Run Check reads ~8 files, ≤300 KB each), metadata-first, no full-tree content scan, no coverage accounting, no risk chains. They validate the demand and the distribution playbook; they also set the bar RepoGate must visibly clear — full tree, no excluded surfaces, decode-and-rescan, INCONCLUSIVE honesty.

---

## The demand side — how people actually get compromised in late 2026

1. **Recruiter / take-home repos (the volume attack on individuals).** Contagious Interview remains the dominant dev-targeting campaign (>750 infected repos, >500 malicious VS Code task configs in Mar 2026 alone per Trend Micro; still producing first-person victim reports in Nov 2026). The 2026 evolution is *prompt-injection-only* payloads (TL-2026-5876): nothing for AV or package scanners to find — the victim's agent is the malware's runtime.
2. **Skill & MCP registry poisoning at scale.** Snyk ToxicSkills (Feb 2026): of 3,984 skills on ClawHub + skills.sh, **36.8% had a security flaw, 13.4% a critical issue**; skill submissions grew from <50/day (mid-Jan) to >500/day (early Feb). ClawHavoc (Koi, 2026-02-01): **341 of 2,857 ClawHub skills (11.9%) malicious**; registry barrier to publish was a SKILL.md and a week-old GitHub account. ClawHub docs (Oct 2026) still warn the registry "has a real malware history," and skills installed via skills.sh are explicitly marked **"Not scanned by ClawHub."** FakeGit put 600+ impersonating listings on the MCP/skill directories themselves.
3. **Agent-config as persistence and payload.** Mini Shai-Hulud (Apr–May 2026) persisted via `.claude/settings.json` SessionStart hooks + `.vscode/tasks.json`; the Bitwarden CLI hijack (2026) treated `~/.claude.json` and MCP configs as first-class stealer targets; SOMBERMEME (Nov 2026) weaponised repo-local `.claude/settings.json`. The config files *are* the attack surface, and they are the files no package scanner reads.
4. **MCP config sprawl.** GitGuardian (Sep 2026): **24,008 unique secrets in public MCP configuration files, 2,117 valid**; 5.2% of sampled public MCP repos leaked a secret. Users paste MCP configs from READMEs and registries daily, unpinned (`npx -y @latest`), with tokens inline.
5. **Vibe-coded dependency slop.** Agents hallucinate and install plausible package names; attackers register them (slopsquatting — established 2025 research, industrialised in 2026 via the typosquat/confusion shapes in the OSV MAL feed: version `1.999.999` confusion packages, mutable-tarball deps, Oct–Nov 2026). The user never chose the dependency — their agent did — so the check has to happen at the agent's install moment (the osv-guard hook pattern), not in a dashboard reviewed weekly.

**What the agent ecosystem lacks natively (Nov 2026 state):** Claude Code — no consumer-side skill/repo scanning (Enterprise-only, MCP-excluding; above). Cursor — Workspace Trust and run-mode approvals are manual, per-action, and blind to *content* (a folderOpen task with the payload 560 columns off-screen passes a human glance). Codex / Gemini CLI / Hermes — no built-in pre-acquisition vetting surfaced in current sources; all rely on the user or on third-party skills. The registries (ClawHub, skills.sh, Glama, MCP.so, MCP Market, official MCP Registry at 64,000+ servers) are *distribution* infrastructure with, at best, after-the-fact moderation (ClawHub auto-hides after 3 user reports) — vetting is structurally outsourced to whoever shows up to do it.

---

## Distribution wedges for a solo builder with an audience

Ranked by leverage for this project specifically (AI creator, agent-ecosystem audience, zero-budget):

1. **Ship the scanner as a skill, into the registries it protects.** Publish RepoGate's `SKILL.md` to **ClawHub** (`clawhub skill publish`; needs a GitHub account ≥1–2 weeks old) and submit an index request to **skills.sh** (GitHub issue on `vercel-labs/skills`; installs then work via `npx skills add <owner>/<repo>`). The pitch writes itself on skills.sh installs, which OpenClaw literally labels "Not scanned" — RepoGate is the scan. Every agent that installs the skill becomes a distribution node, and the skill format means Claude Code, Hermes, Codex and OpenClaw users all get it from one artifact.
2. **MCP server listing in the official MCP Registry.** Wrap the scanner as an MCP server (`check_repo`, `check_path`, `check_zip` tools), publish the package, then list via `mcp-publisher` + `server.json` (GitHub OIDC auth, ~15-second publishes). The official registry (64,000+ servers, Nov 2026) is the upstream that Glama, mcp.so and MCP Market syndicate from — one listing, every directory. Repo Run Check's Glama presence proves an indie scanner gets surfaced this way.
3. **The shell wrapper as the viral surface.** `repogate clone <url>` — fetch tarball via API, scan, clone only on pass — plus drop-in guards: a `git` shell function, pre-`npm install`/`pip install` wrappers (Socket's `sfw` proved users accept install wrappers), and agent hooks (Claude Code PreToolUse plugin, installable via plugin marketplace, following the osv-guard precedent). Each wrapper is a one-line install and a daily reminder the tool exists.
4. **Zero-friction packaging.** PyPI (`pip install repogate` / `uvx repogate` — natural for a stdlib Python single file), a Homebrew tap (`brew install <tap>/repogate`), GitHub Releases with checksums + Sigstore signatures. Cargo only becomes relevant if a Rust port happens; don't let packaging block launch. **Name check first:** `repoguard-py` already exists on PyPI and "RepoGuard" is taken as a product name — RepoGate needs a trademark/PyPI/registry availability pass before launch, or a rename while it's still cheap.
5. **Content as distribution (the project's unfair advantage).** The audience is the moat's accelerant: scan-the-thing-live content — running RepoGate over the week's real malicious finds (Contagious Interview samples, ClawHub removals, OSV MAL- of the day) is a repeatable format no incumbent's marketing team can match for authenticity, and each video is a tutorial that ends with the install command. Public scan write-ups of *named, real* malicious repos (the SolanaCry starter-kit pattern) are the SEO/GEO surface agents and humans both search after an incident.

---

## Honest risks — where incumbents crush a solo tool, and the mitigations

| # | Risk | Why it's real | Mitigation |
|---|---|---|---|
| 1 | **Malware corpus freshness.** Socket, Snyk and OpenSSF ingest the MAL- feed daily (222,877 npm names by Nov 2026); StepSecurity/Socket employ full-time intel teams. A solo ruleset decays in weeks. | RepoGate's *known-bad* layer would silently rot while its UI still says CLEAN. | **Don't build a corpus — ride the public one.** Vendor `ossf/malicious-packages` as a data dependency: git-pull update when online, bundled snapshot when offline (Flagrix proves local matching against the full feed is practical). RepoGate's original IP stays the *behavioural* layer (chains, surfaces, coverage) that doesn't decay at the same rate. Print feed age in every report; stale feed downgrades CLEAN → INCONCLUSIVE. |
| 2 | **False-positive tuning at scale.** SkillSpector's 100/CRITICAL on 30 legit production skills is the cautionary tale; Snyk tuned ToxicSkills detectors against widely-adopted legit skills to suppress FPs. A solo tool sees a tiny sample and will cry wolf on exactly the popular repos users test it on first. | Two loud FPs in a demo video and the tool is a meme, not a gate. | Chains before BLOCK (single weak signals cap at REVIEW); per-category score caps (already in design); baseline/suppression files (SkillSpector's one good idea here); a public benchmark habit — run against `snyk-labs/toxicskills-goof` (public malicious corpus) + a top-100 legit skills/repos fixture set in CI, and **publish the FP rate**. INCONCLUSIVE exists precisely to avoid forced binary errors. |
| 3 | **Maintenance burden / surface explosion.** New agent surfaces land monthly (new editors, `.zed/tasks.json`, Antigravity configs, next MCP transport). NVIDIA ships SkillSpector releases weekly with a team. | Coverage gaps accumulate silently; the tool's claim ("no excluded surfaces") becomes false by drift. | Narrow wedge discipline: RepoGate owns *one moment* (pre-contact gate) and a *data-driven* rule layer — rules as files others can PR, taxonomy diffed against SkillSpector/zizmor releases on a cadence, not invented. Community rules are the only way a solo project matches a team's surface coverage; design the rule format for contribution from day one. |
| 4 | **Platform absorption.** Anthropic already shipped Enterprise scanning; a consumer-tier launch, or GitHub adding pre-clone warnings, compresses the wedge. | The moat is partly "the platforms haven't bothered yet." | Platform scanners cover only their own surface (Anthropic's excludes MCP entirely; a future Claude scanner still won't gate a Cursor workspace, a Hermes skill, or a Drive zip). RepoGate's cross-platform, cross-ecosystem, arbitrary-artifact stance is the part platforms structurally won't copy. Keep the wedge there, not in "we scan Claude skills" alone. |
| 5 | **The trust paradox.** A security tool by a solo creator is itself an unvetted supply-chain artifact — Snyk's Feb 2026 post is literally titled "Your Skill Scanner Is Just False Security (and Maybe Malware)"; one of the community scanners it reviewed was later removed from ClawHub. | Every distribution channel above asks users to install a stranger's scanner — the exact behaviour RepoGate warns against. | Eat your own cooking, visibly: single file, zero dependencies, reproducible releases, Sigstore-signed artifacts, and RepoGate's own repo carries a RepoGate report with documented suppressions. The audit trail (this research folder) ships in the repo. Transparency is the solo builder's only trust shortcut. |
| 6 | **The deterministic ceiling.** Snyk's core argument is correct in part: regex/AST cannot read *intent* in prose, and novel injections will evade patterns (attackers already plant fake SYSTEM blocks aimed at LLM scanners — and will plant pattern-evading text aimed at deterministic ones). | Overselling detection = the SkillGuard failure mode. | Never let CLEAN say "safe" (already law in the README). Position RepoGate as the **floor**: deterministic, local, always-on, catches the known shapes and the careless 95%, accounts honestly for what it didn't scan. An optional local-LLM second opinion can be layered later — on the user's own model, on their own machine — without breaking the zero-egress claim. |
| 7 | **Name collision.** "RepoGuard" is a live PyPI product; "Repo Run Check", "repoc", "Flagrix" crowd the same search results. | Discoverability and trust confusion at launch; possible takedown friction on registries. | Availability pass (PyPI, npm, GitHub, ClawHub, skills.sh, trademark search) before any public push; rename now if the field is dirty — the brand equity is currently zero, so renaming is free today and expensive later. |

---

## Bottom line

The incumbents are better at everything that requires a team: corpus, cloud, enterprise sales. They are structurally absent from the one place late-2026 compromises actually begin — **an individual, an agent, and an unvetted thing about to be opened** — because that moment is local, cross-platform, pre-account, and pre-revenue. RepoGate's moat is not detection depth; it's **position**: the only scanner that is already there, offline, in one file, speaking verdicts an agent can act on, distributed through the same registries that distribute the threats. The moat holds only if the honesty holds — coverage accounting, published FP rates, a vendored public corpus, and CLEAN never meaning safe.

## Sources (selection, with dates)

- Socket docs — Managed Scans / Permissions / CLI (crawled Nov 2026): docs.socket.dev
- IntuitionLabs — *Claude Skills Security Scanning: HIPAA and ZDR Gaps* (~Nov 10, 2026): intuitionlabs.ai
- aidefensestack — *NVIDIA SkillSpector* (Nov 3, 2026); getcommit.dev — *SkillSpector and the Runtime Trust Gap*; widechaos.cn OSS Radar (Oct 27, 2026)
- Snyk — *ToxicSkills* (Feb 5, 2026) and *Why Your Skill Scanner Is Just False Security* (Feb 11, 2026): snyk.io; snyk-agent-scan on PyPI; toxicskills-goof AGENTS.md (crawled Nov 2026)
- Threadlinqs TL-2026-5876 — *Poisoned Coding Assessment* (disclosed Jun 19, 2026; detections Nov 12, 2026): intel.threadlinqs.com
- Protocol Report — *Poisoned Claude Settings / SOMBERMEME* (Nov 17, 2026, on GTIG Nov 16 reporting): protocolreport.com
- CSA Research Note — *FakeGit and AgentBaiting* (Jul 21, 2026): labs.cloudsecurityalliance.org
- Krasavina — *We trained engineers to run strangers' code* (Nov 9, 2026): linkedin.com
- GitGuardian MCP secrets data via dev.to MCP security checklist (Sep–Oct 2026)
- Kuntur — *How to Vet MCP Servers* (Oct 28 / Nov 4, 2026): kuntur.io
- ClawHub docs (updated Oct 18, 2026): clawdocs.github.io; agentools.sh — *How to Scan Claude Skills* (Nov 13, 2026)
- MCP Registry publishing docs + server counts (Nov 2026): modelcontextprotocol.io; dev.to registry listing guide (Nov 2026)
- Glama — *Repo Run Check* (crawled Nov 2026); Flagrix — *How to check a GitHub repo before you clone it* (Nov 2026, feed counts dated Nov 9, 2026); repoc-cli and repoguard-py on PyPI (crawled Nov 2026)
- OpenSSF — *Detecting Malicious Packages Using the OSV API* (May 20, 2026): openssf.org
- VirusTotal GTI docs — file upload & dataset inclusion (updated Nov 10, 2026): gtidocs.virustotal.com
- RepoGate internal: `README.md`, `research/best-practices-2026.md`, `research/tool-audit-*.md` (Nov 20, 2026)
