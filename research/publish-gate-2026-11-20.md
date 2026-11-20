# RepoGate — Final Pre-Publication Gate Report

Date: 2026-11-20 · Scope: verification only (no repo created, nothing pushed)
Target if cleared: TysAIs/repogate (public)
Gate standard (the owner's order): zero personal data in the tree, and flawless.

Publication note: this report ships in the repo, so the owner's name, family
names, account handles, hostnames, and local absolute paths it originally
listed were redacted at publish time. The unredacted copy stays local with
the audit records. The two blocking references below were neutralized in
place ("the maintainer") before publication.

## 1. Tests

Scanner version: **1.3** — `repogate.py` line 35 `VERSION = "1.3"`;
`python3 repogate.py --version` prints `repogate 1.3`; JSON report payload
carries the same version string.

Suite run: `python3 tests/run_tests.py` → exit 0, "All fixture tests passed."

| Case | Exit | Verdict | Score | Expected | Result |
|---|---|---|---|---|---|
| fixtures/clean-repo | 0 | CLEAN | 0 | CLEAN / 0 | PASS |
| fixtures/malicious-skill | 2 | BLOCK | 100 | BLOCK, all chains | PASS |
| fixtures/evasion/01-split-stealer | 2 | BLOCK | — | BLOCK | PASS |
| fixtures/evasion/02-b64-varcat | 2 | BLOCK | — | BLOCK | PASS |
| fixtures/evasion/03-tagsblock-skill | 2 | BLOCK | — | BLOCK | PASS |
| fixtures/evasion/04-pyc-payload | 2 | BLOCK | — | BLOCK | PASS |
| fixtures/evasion/05-postinstall-fetch | 2 | BLOCK | — | BLOCK | PASS |
| fixtures/evasion/06-pi-in-js-comments | 2 | BLOCK | — | BLOCK | PASS |
| fixtures/evasion/07-nested-zip.zip | 2 | BLOCK | — | BLOCK | PASS |
| fixtures/evasion/08-folderopen-whitespace | 2 | BLOCK | — | BLOCK | PASS |
| fixtures/evasion/09-getattr-varcat | 2 | BLOCK | — | BLOCK | PASS |
| fixtures/evasion/10-docx-pi | 2 | BLOCK | — | BLOCK | PASS |

Malicious-skill chains found: chain-autorun-dropper, chain-dropper,
chain-hook-dropper, chain-prompt-exfil, chain-stealer — the three required
chains (chain-stealer, chain-autorun-dropper, chain-prompt-exfil) all present,
plus the required findings (pi-ignore-instructions, auto-vscode-folderopen,
hook-npm-lifecycle). **No deviations from expected results.**

## 2. Privacy re-grep

Scope: every file in the tree except `.bench/` and
`research/privacy-scrub.md` (excluded by design — it contains the searched
terms). Text grep plus manual inspection of all four binary files and both
archive interiors (see below).

### Blocking hits — real personal references (2)

| File | Line | Content | Verdict |
|---|---|---|---|
| research/corpus-expansion.md | 73 | "Recall numbers measured against this are numbers **[owner first name]** can publish." | Owner's first name in shipped prose |
| research/corpus-expansion.md | 151 | "Take it only if **[owner first name]** decides manifest-stage vuln flags are in scope…" | Owner's first name in shipped prose |

These are the same class the earlier scrub removed 22 of across the tree;
these two survived in corpus-expansion.md. First name only — no surname,
no contact data — but the tree's established standard is zero, and the
publish condition is zero personal data. **Must be neutralized before push**
(e.g. "the maintainer" / "the project owner").

### Zero hits (searched, none found)

- Surnames / family names: the owner's surname and six family names
  (full list in the local audit copy) — 0 hits.
- Handles / accounts: the owner's three account handles (local audit
  copy) — 0 hits.
- Hostnames: the four cluster node names, the workstation name, and the
  compute server's name (local audit copy) — 0 hits.
- IPs: the LAN serving-subnet prefix — 0 hits. Tailscale CGNAT range
  100.64.0.0/10 — 0 hits.
- Email: no personal email addresses anywhere.
- Phone-number patterns — 0 hits.
- MAC addresses — 0 hits.
- Device serial numbers: every "serial" hit is the word
  serialize/serialization in rule names and prose (e.g. GuardDog's
  `npm-serialize-environment`); no `s/n` values, no hardware serials.

### Benign hits (reviewed, cleared)

- research/detection-science.md:373 — "numbers to chase": the verb, not a
  person.
- third_party/guarddog-data/top_go_packages.json:804, :2424 —
  `github.com/tyler-smith/go-bip39`, `github.com/TylerBrock/colorjson`:
  other people's public upstream packages in GuardDog's verbatim
  top-packages data. Public upstream data, byte-identical to source.
- third_party/sigil-packs/*.json line 7 — `hello@sigilsec.ai`: the Sigil
  pack author's public contact in upstream rule-pack metadata.
- third_party/guarddog-yara/LICENSE:189, guarddog-data/LICENSE:189 —
  `opensource@datadoghq.com` inside the Apache license text.
- RFC 5737 documentation IPs (198.51.100.23 in the malicious-skill fixture;
  192.0.2. / 198.51.100. / 203.0.113. prefixes in Sigil packs) and
  169.254.169.254 cloud-metadata references (docs/DESIGN.md:41,
  research/fp-baseline-1.md:147) — documentation ranges and detection
  targets, not real addresses.
- third_party/sigil-packs regex patterns containing `/home/[\w.-]+` and
  `/Users/[\w.-]+` — generic pattern classes inside upstream detection
  rules, not actual local paths.
- research/unified-architecture.md:763 and docs/SYNTHESIS-v2.md:100 —
  "TysAIs/repogate": the intended public destination repo itself.
- "hatch" hits outside the exclusions are the PyPI package names
  (hatch, hatch-vcs, …) in GuardDog's upstream top-packages data.

### Binary / archive inspection

Complete binary inventory outside `.bench/` and `third_party/` is four
files; all inspected:

- `__pycache__/repogate.cpython-312.pyc` — embeds the absolute source path
  `~/workspace/repogate/repogate.py` (absolute path in the original).
  EXCLUDED from the publish
  set (and already covered by `.gitignore`), but note it exists in the
  tree now — it regenerates on every scanner/test run, so the publish
  procedure must exclude it explicitly, not rely on a clean tree.
- `tests/last-report.json`:4 — `"target": "~/workspace/repogate/
  fixtures/evasion/10-docx-pi"`: generated test artifact containing an
  absolute local path. EXCLUDED (already in `.gitignore`).
- `fixtures/evasion/04-pyc-payload/payload.pyc` — embeds only the generic
  relative scratch path `./tmp/rg-evasion/04-pyc-payload/_payload_src.py`.
  Synthetic fixture, retained deliberately. Benign.
- `fixtures/evasion/07-nested-zip.zip` (README + inner.zip with
  package.json / steal.js) and `fixtures/evasion/10-docx-pi/guide.docx` —
  interiors contain only the fixtures' synthetic test payloads on fake /
  example endpoints. No personal data inside either archive.

### third_party manifest / NOTICE disclosure

`sha256sum -c third_party/MANIFEST.sha256`: 87 of 88 entries verify OK.
The single non-verifying entry is `SOURCES.md` (manifest hash
e1c73b1b… vs actual f56bb4db…) — the known post-integration redaction of a
workstation name. The disclosure text exists in the root `NOTICE`
("One post-integration edit: third_party/SOURCES.md had a workstation name
redacted for publication hygiene, so its hash no longer matches the
manifest…"). Confirmed as documented; not a gate failure.

## 3. Publish set

### Ships

- `.gitignore`
- `NOTICE`
- `README.md`
- `SKILL.md`
- `repogate.py`
- `docs/` — DESIGN.md, SYNTHESIS-v2.md
- `fixtures/` — clean-repo/, malicious-skill/, evasion/ (all 10 fixtures,
  including the .pyc / .zip / .docx specimens above)
- `tests/` — run_tests.py only
- `research/` — all 16 briefs EXCEPT privacy-scrub.md (see exclusions);
  includes this gate report
- `rust-spike/` — Cargo.toml, Cargo.lock, src/ (no `target/` present)
- `third_party/` — MANIFEST.sha256, SOURCES.md, sigil-packs/,
  guarddog-yara/, guarddog-data/ (largest files: top_pypi_packages.json
  379 KB, top_npm_packages.json 225 KB — upstream data, fine)

### Excluded (must not ship)

- `.bench/` — 296 MB of shallow clones of other people's repositories.
- `research/privacy-scrub.md` — contains the searched personal terms by
  necessity.
- `__pycache__/` — embeds an absolute local path (see §2).
- `tests/last-report.json` — generated artifact with an absolute local
  path (see §2).
- `.git` internals — none exist; the local tree is not a git repository,
  so the published repo is created fresh from the publish set.

### Required at publish (not in tree yet)

- `LICENSE` (MIT) — absent from the tree. README declares MIT and NOTICE
  already defers to it ("see LICENSE when published"). Add the standard
  MIT text as part of the publish step.

## 4. Verdict

**NOT PUBLISHABLE — yet. One blocking item.**

1. **BLOCKER:** Neutralize the two first-name references in
   `research/corpus-expansion.md` (lines 73 and 151). Two-line edit;
   after it, re-run the §2 name grep to confirm zero.

Everything else passes: the fixture suite is exact (CLEAN 0 / BLOCK with
all chains / evasion 10/10, version 1.3), the rest of the privacy sweep is
zero or verified-benign upstream/documentation content, the one manifest
mismatch is the known redaction and is disclosed in NOTICE, and the
publish set is clean provided the four exclusions above are honored and a
MIT LICENSE is added at publish. Once the blocker edit lands and the
re-grep confirms zero, this gate clears without further changes.
