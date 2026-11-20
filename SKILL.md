---
name: repogate
description: Scan a repository, archive, or AI agent skill BEFORE cloning, installing, opening, or running it. Read-only static analysis for lifecycle hooks, auto-run configs, credential theft, exfiltration, obfuscation, prompt injection, and supply-chain risks, correlated into risk chains with a CLEAN / REVIEW / INCONCLUSIVE / BLOCK verdict. Use whenever you are about to fetch, clone, install, open in an editor, or execute third-party code or skills — and whenever a user hands you a repo or skill to evaluate.
---

# RepoGate — scan before you clone, install, open, or run

RepoGate is a zero-dependency, read-only scanner (`repogate.py`, Python 3.10+
stdlib only). It NEVER executes the code it scans. Acquisition is
quarantine-first: GitHub repos are fetched as API tarballs (not git clones)
and archives are extracted with path-escape checks into a temp quarantine dir.

## When to run it (the gate)

Run RepoGate **before** any of these, on anything you did not write:

- `git clone` of a third-party repo (scan the GitHub URL first)
- `npm install` / `pip install` / `cargo build` inside a new tree
- Opening a repo in VS Code or any editor with workspace tasks
  ("Cloning is safe. Opening is not." — Contagious Interview, Nov 2026)
- Installing or importing an agent skill (SKILL.md), MCP server, or plugin
- Running any script, installer, or devcontainer from a new source

## How

```bash
python3 repogate.py <target> [--json report.json]
```

Targets: a local directory, a `.zip`/`.tar.gz`, a single file, or
`github.com/owner/repo` (optionally `/tree/<branch>`). Set `GITHUB_TOKEN` for
private repos / higher rate limits.

Exit codes are the contract: **0 CLEAN** (proceed), **1 REVIEW or
INCONCLUSIVE** (a human reads the findings first; INCONCLUSIVE means coverage
was partial — never treat it as clean), **2 BLOCK** (do not proceed; escalate
to the user with the report), **3 tool error**.

## Reading the verdict

- **Risk chains** outrank individual findings: a completed chain (STEALER,
  DROPPER, HOOK DROPPER, AUTO-RUN DROPPER, PROMPT-INJECTION EXFIL, CI TOKEN
  THEFT, PERSISTENCE IMPLANT) means the package has a working malicious
  shape, not just suspicious ingredients.
- A CLEAN verdict means "nothing found by these rules", **never** "safe".
  Say exactly that to the user.
- Trust signals (repo age, stars, license) print as context only. They never
  clear a finding.

## Design rules it enforces (learned from published scanner bypasses)

No excluded surfaces (node_modules and docs are scanned — a published bypass
hid a payload there), shipped bytecode is a finding, the verdict path is fully
deterministic (no LLM scoring), oversized files are head+tail scanned and
counted as partial coverage, and matching runs on normalized text
(string-concatenation folding, base64 decode-and-rescan, Unicode Tags-block
decoding) to blunt the standard evasions.

## Known context case

Security tools' own source trees (scanner repos like CloneGuard, Sigil,
repo-guard) enumerate the malicious patterns they detect, so RepoGate will
often verdict them REVIEW or BLOCK, driven by their own detection corpora
and shipped specimens. The findings name the exact files — read them before
concluding anything. This is a property of signature-based scanning, not a
bug: the same is true of every tool in this class.
