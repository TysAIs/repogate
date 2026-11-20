# RepoGate

**Scan a repository or AI agent skill before you clone it, install it, open
it, or run it.** Read-only static analysis — RepoGate never executes the code
it scans — with findings correlated into named risk chains and a single
gate verdict an agent (or a human) can act on.

```
python3 repogate.py github.com/some-owner/some-repo
python3 repogate.py ./local-dir --json report.json
python3 repogate.py suspicious-skill.zip
```

Exit codes: `0` CLEAN · `1` REVIEW / INCONCLUSIVE · `2` BLOCK · `3` tool error.
Zero dependencies: Python 3.10+ standard library only.

## Why

The 2026 malware playbook doesn't wait for you to run anything: it fires on
`npm install` (lifecycle hooks), on opening the folder in VS Code
(`tasks.json` `runOn: folderOpen` — the Contagious Interview campaign), on
reading a SKILL.md (prompt injection that talks your agent into exfiltrating
`~/.ssh`), or in a privileged GitHub Actions trigger. RepoGate is the gate
that sits before all four moments.

## What it merges

RepoGate was built by auditing the current scanner field (Nov 2026) and
absorbing what survived scrutiny — full audits in [`research/`](research/):

- **NVIDIA SkillSpector** — agent-skill taxonomy (prompt injection, tool
  poisoning, MCP risks) and the gate/exit-code contract. Its published
  bypasses (payload hidden in excluded `node_modules`, non-deterministic LLM
  scoring) are designed against here: *no excluded surfaces, deterministic
  verdict path*.
- **DataDog GuardDog** — capability×threat correlation into risk chains and
  registry-metadata detectors (typosquatting, git-URL deps, new install
  scripts).
- **CloneGuard** — read-only discipline and the verdict→exit-code ladder.
- **Sigil** — quarantine-first workflow and evidence-gated verdicts.
- **repo-guard** — pre-clone GitHub API acquisition and trust signals
  (context only, never a clearance).
- **ScanRepo** — tarball-snapshot acquisition and per-report coverage
  accounting with an explicit INCONCLUSIVE verdict. (Unlike ScanRepo, scans
  are fully local: nothing about what you scan leaves your machine.)
- The **Nov 2026 threat record** (Contagious Interview teardown, SANDWORM_MODE,
  Mini-Shai-Hulud, hackerbot-claw) as concrete rules: whitespace-pushed
  payloads, agent-config persistence writes, AI-agent LOTL spawning, Unicode
  Tags-block smuggling with decode-and-rescan.

## Detection shape

7 rule families (lifecycle hooks, auto-run configs, credential access,
network/exfil, execution, obfuscation, prompt injection) + structural checks
(package.json, tasks.json, workflows, setup.py, build.rs, agent settings) +
normalization (string-concat folding, base64 decode-and-rescan, hidden-unicode
detection) → **8 named risk chains** → weighted score with per-category caps →
verdict. Partial coverage caps the verdict at INCONCLUSIVE: an unscanned file
is never silently a clean file.

A CLEAN verdict means *nothing was found by these rules*. It is not, and
never prints as, a guarantee of safety.

## Layout

- `repogate.py` — the scanner (single file, stdlib only)
- `SKILL.md` — the agent-skill wrapper: when and how an agent runs the gate
- `fixtures/` — a clean repo (must pass) and a malicious skill (must BLOCK)
- `tests/run_tests.py` — fixture test suite
- `research/` — the source audits and the 2026 best-practice evidence base
- `docs/DESIGN.md` — design invariants and audit-driven requirements

## License

MIT
