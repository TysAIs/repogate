# RepoGate v1.2 — False-Positive Baseline #1 (Nov 20, 2026)

First measurement of v1.2 verdicts on known-benign software. Method:
`python3 repogate.py github.com/<owner>/<repo> --json /tmp/fp-baseline/<repo>.json`
on 12 popular, reputable open-source repos (~29,950 files total, 4 of them
1000+ files). No scanner code was changed. Raw reports:
`/tmp/fp-baseline/*.json`.

**Classification key** — TRUE CONTEXT: the finding is accurate, the repo
genuinely contains that pattern. BENIGN PATTERN: real pattern, legitimately
used; the rule is too broad. NOISE: should never have fired.

## Headline

| Verdict | Count |
|---|---|
| CLEAN | **0 / 12** |
| REVIEW | 2 / 12 (tokio 36, httpx 47) |
| BLOCK | **10 / 12** |

Every single reputable repo trips at least a REVIEW, and 10 of 12 BLOCK —
including a 61-file Go CLI library at score 100. As calibrated today,
RepoGate's verdict on arbitrary real-world software is close to
"BLOCK unless small and quiet." The catches on the malicious fixture set
(fixtures/evasion/*, all BLOCK) are real, but the benign side of the curve
is unusable until the three fixes at the bottom land.

## Per-repo results

### 1. pallets/click — BLOCK 100 · 167 files · 13 live / 22 contextual
Top live: chain-autorun-dropper (critical); exec-indirection HIGH ×2
(`getattr(_main, "__package__…`, `globals()[…` — lazy-loading shims);
auto-whitespace-hiding HIGH ×2 (docs/_static/*.svg logo path data);
cred-env-dump MEDIUM ×4 (bare `os.environ` access); sc-tarball-dep MEDIUM
(uv.lock recording wheels from files.pythonhosted.org).
**Classification: BENIGN PATTERN dominant + NOISE chain.** Every CLI
framework reads `os.environ` and uses getattr import shims. The critical
chain's autorun leg is an SVG logo. The tarball hit is PyPI's own file
host inside a lockfile.

### 2. psf/requests — BLOCK 100 · 103 files · 21 live / 23 contextual
Top live: chain-autorun-dropper + chain-stealer-xfile (both critical);
cred-ssh-aws HIGH ×2 (`.netrc` — requests *implements* netrc auth);
exec-indirection HIGH ×3 (`__import__(`, `importlib.import_module`,
`getattr(cryptography, "__version__"` — compat shims); cred-env-dump ×2.
**Classification: BENIGN PATTERN + NOISE chains.** An HTTP library that
reads netrc files and environment proxies is doing its documented job;
the stealer chain completes because those benign legs coexist in one
package with fetch primitives.

### 3. sindresorhus/execa — BLOCK 100 · 677 files · 34 live / 32 contextual
Top live: chain-autorun-dropper + chain-stealer-xfile (critical);
exec-eval-nonliteral HIGH ×7 (`Function(f…`, `Function(v…` — identifiers
*ending* in "Function"); exec-eval MEDIUM ×8 in lib/ (child_process —
execa is a process-execution library; spawning is its API);
auto-whitespace-hiding HIGH ×2 (media/*.svg logos).
**Classification: BENIGN PATTERN (capability is the product) + NOISE**
(the Function( suffix matches; the SVG chain leg).

### 4. expressjs/express — BLOCK 59 · 210 files · 4 live / 11 contextual
Top live: chain-autorun-dropper (critical) — the *only* consequential
finding; cred-files MEDIUM (`.env` in lib/application.js);
net-fetch-primitive LOW; sc-no-lockfile LOW.
**Classification: NOISE.** The chain's autorun leg is a *contextual*
auto-whitespace-hiding hit on a >600-char line in History.md (a
changelog). A demoted, never-scored doc finding completed a critical
chain and single-handedly moved express from ~19 (REVIEW) to BLOCK.
This is the cleanest single FP bug in the baseline.

### 5. prettier/prettier — BLOCK 100 · 9,697 files · 238 live / 108 contextual
Top live: chain-autorun-dropper + chain-stealer-xfile (critical);
auto-whitespace-hiding HIGH ×48 (website SVG logos + snapshots);
exec-eval-nonliteral ×34 (`Function(i/g/o/p…` from helpers literally
named …Function(…), `exec(v…` from RegExp `.exec()`); cred-files ×41;
struct-binary-present ×83 (info).
**Classification: NOISE dominant + BENIGN PATTERN.** Scale amplifies
every broad rule: 238 live findings on a code formatter.

### 6. tokio-rs/tokio — REVIEW 36 · 876 files · 3 live / 2 contextual
Top live: obf-hex-exec HIGH (`\x00\x03\x43\x95…` — a byte-string literal
in async I/O test/example code); cred-env-dump MEDIUM (`printenv` named
in process docs); cred-files MEDIUM (`.env`).
**Classification: BENIGN PATTERN.** The best-behaved large repo in the
set, and the only large one not BLOCKed — Rust code trips few of the
JS/Python-shaped rules. Still not CLEAN.

### 7. spf13/cobra — BLOCK 100 · 61 files · 5 live / 2 contextual
Top live: net-curl-pipe-shell CRITICAL (Makefile:
`curl -sfL https://install.goreleaser.com/…/golangci-lint.sh | sh`);
persist-os HIGH (`>> ~/.zshrc` in completions.go); chain-persistence-
implant HIGH; chain-autorun-dropper CRITICAL.
**Classification: TRUE CONTEXT patterns, benign intent.** The Makefile
really does pipe curl to sh (dev-lint tooling install), and cobra's
completion generator really does append to ~/.zshrc — that *is* the
feature users invoke. Worst verdict-per-file ratio in the set: 100 on
61 files from essentially two items.

### 8. encode/httpx — REVIEW 47 · 107 files · 15 live / 35 contextual
Top live: cred-ssh-aws HIGH (`.netrc` in httpx/_auth.py — netrc auth
implementation); cred-env-dump MEDIUM; obf-string-split LOW ×3
(`.join([` in URL/multipart code); struct-binary-present ×10 (info,
docs images).
**Classification: BENIGN PATTERN.** Closest to a correct verdict in the
set; the netrc HIGH is the only finding that moves the score materially.

### 9. vuejs/core — BLOCK 100 · 685 files · 107 live / 31 contextual
Top live: hook-npm-lifecycle CRITICAL (`scripts.preinstall = npx
only-allow pnpm` in package.json); chain-autorun-dropper +
chain-stealer-xfile (critical); exec-eval-nonliteral ×41 (…Function(
suffixes + build-script `exec(`); sc-no-lockfile ×18 (per-package
manifests in a monorepo whose lockfile lives at the root);
cred-files ×17; sc-git-dep ×12.
**Classification: TRUE CONTEXT hook + NOISE bulk.** The preinstall hook
exists exactly as flagged — its payload is a package-manager guard, a
well-known benign pattern the rule cannot see. The remaining ~100 live
findings are monorepo/suffix noise.

### 10. faker-ruby/faker — BLOCK 100 · 1,143 files · 223 live / 5 contextual
Top live: chain-autorun-dropper (critical) + chain-dropper-xfile;
net-fetch-primitive ×206 (evidence literally `fetch(` — matched inside
locale YAML *data* files); auto-whitespace-hiding ×7 (locale files and
movie-quote data lines); obf-unicode-hidden HIGH ×3 (zero-width
characters in fa.yml / es-AR.yml locale data); net-webhook ×2 (evidence
"…oast." — a substring inside ordinary words like "roast" in food /
Chuck Norris locale text).
**Classification: NOISE — the worst offender in the baseline.** Faker is
a fake-data library: its "network egress" is the word fetch( in YAML
data, its "hidden unicode smuggling" is the zero-width non-joiner that
Persian orthography *requires*, and its "whitespace hiding" is long
lines of locale data and film quotes. 223 live findings, none of them
an executable threat.

### 11. curl/curl — BLOCK 100 · 4,524 files · 34 live / 133 contextual
Top live: chain-stealer-xfile (critical); net-download-exec HIGH
(appveyor.yml CI uses DownloadString); auto-whitespace-hiding HIGH ×19
(tests/data/test* — long-line test fixtures that stayed live because
the autorun category is exempt from test-tree demotion above depth 3);
cred-ssh-aws ×10 (curl's source implements ssh/netrc handling).
**Classification: TRUE CONTEXT + BENIGN PATTERN, with a NOISE assist**
from test-data whitespace. curl genuinely contains download-and-execute
CI scripting and credential-file handling — because it is a transfer
tool. The scanner is describing the repo accurately and still producing
a verdict no maintainer would accept.

### 12. projectdiscovery/nuclei-templates — BLOCK 100 · 14,704 files · 885 live / 17 contextual
Top live: net-metadata-ip CRITICAL ×15 (templates for SSRF detection
contain 169.254.169.254 — that is their purpose); pi-exfil-instruction
CRITICAL ×36 (template *descriptions* narrating upload/exfil attacks);
auto-whitespace-hiding ×390; net-webhook ×259 (OOB callback endpoints
in detection templates); obf-long-blob ×90 (encoded payloads the
templates test for).
**Classification: TRUE CONTEXT — the expected corpus case, and a
context-system gap.** The findings accurately describe an attack-
template corpus. But the corpus exemption almost never engaged (17 of
902 findings contextual): it requires ≥5 distinct rules in a *single*
file under a rules/signatures/detections-style path, while this corpus
is one-template-per-file under http/, cves/, javascript/. A directory-
level corpus signal (a large share of files tripping the same payload
classes) would catch this shape.

## Aggregate FP table

| Repo | Verdict | Score | Files | Live | Ctx | Dominant class |
|---|---|---|---|---|---|---|
| pallets/click | BLOCK | 100 | 167 | 13 | 22 | Benign pattern |
| psf/requests | BLOCK | 100 | 103 | 21 | 23 | Benign pattern |
| sindresorhus/execa | BLOCK | 100 | 677 | 34 | 32 | Benign + Noise |
| expressjs/express | BLOCK | 59 | 210 | 4 | 11 | **Noise** |
| prettier/prettier | BLOCK | 100 | 9,697 | 238 | 108 | Noise |
| tokio-rs/tokio | REVIEW | 36 | 876 | 3 | 2 | Benign pattern |
| spf13/cobra | BLOCK | 100 | 61 | 5 | 2 | True context |
| encode/httpx | REVIEW | 47 | 107 | 15 | 35 | Benign pattern |
| vuejs/core | BLOCK | 100 | 685 | 107 | 31 | Noise + True context |
| faker-ruby/faker | BLOCK | 100 | 1,143 | 223 | 5 | **Noise** |
| curl/curl | BLOCK | 100 | 4,524 | 34 | 133 | True context |
| projectdiscovery/nuclei-templates | BLOCK | 100 | 14,704 | 885 | 17 | True context (corpus) |
| **Total** | **0 CLEAN / 2 REVIEW / 10 BLOCK** | | **29,954** | **1,582** | **421** | |

Live risk chains on benign repos: chain-autorun-dropper in **9 of 12**,
chain-stealer-xfile in 6, chain-persistence-implant in 2,
chain-dropper-xfile in 2, chain-prompt-exfil in 1.

Top live rules across all 12 repos: auto-whitespace-hiding 470,
net-webhook 261, net-fetch-primitive 218, struct-binary-present 107
(info, harmless), obf-long-blob 91, exec-eval-nonliteral 83,
cred-files 69, pi-exfil-instruction 36, exec-eval 28, net-raw-ip 27,
sc-no-lockfile 24, exec-indirection 22, cred-env-dump 21,
cred-ssh-aws 20.

## The 3 rule changes that buy the most FP reduction

### 1. Chain-leg hygiene: chains ignore contextual findings, and whitespace-hiding leaves the autorun category
Package-level chains currently complete on findings that were demoted
to contextual (express: a changelog line was the autorun leg of a
critical chain), and auto-whitespace-hiding is *categorized as
autorun*, so SVG logos and long data lines serve as the "something
runs on open/install" leg in click, requests, execa, prettier, vue,
faker, and curl. Fix: (a) chain leg filters exclude `contextual`
findings; (b) recategorize auto-whitespace-hiding to obfuscation;
(c) skip the whitespace rule on .svg and pure data files.
**Expected effect:** chain-autorun-dropper (9/12 benign repos) loses
its FP legs almost everywhere; express drops to REVIEW; one critical
disappears from ~8 of the 10 BLOCKs.
**Fixture safety: SAFE.** malicious-skill and evasion/08 complete
their autorun chains through the genuine folderOpen rule
(auto-vscode-folderopen) and lifecycle hooks, never through a
whitespace or contextual leg. No evasion fixture's BLOCK depends on
either mechanism.

### 2. exec-eval-nonliteral precision: word boundaries and method-call exclusion
The pattern `Function\s*\(\s*[A-Za-z_$]` has no word boundary, so it
matches every identifier *ending* in "Function" (`…Function(value)` —
83 live hits across the set; 41 in vue, 34 in prettier, 7 in execa,
evidence literally `Function(v`), and `\bexec\s*\(` matches RegExp
`.exec(` calls. Fix: require `\bFunction\s*\(` (a real
`new Function(payload)` still matches) and exclude `.exec(` method
calls / suffix identifiers for the exec alternative.
**Expected effect:** removes most of the 83 live hits and the
execution-category score mass behind stealer-xfile chains in execa,
vue, and prettier.
**Fixture safety: SAFE.** Evasion/02's catch is `eval(load())` via
`\beval`, untouched; evasion/09 is getattr-based; no evasion fixture
uses the Function constructor or a bare `exec(`.

### 3. Credential-reference precision: bare mentions are not credential access
cred-ssh-aws fires HIGH on the substring `.netrc` (requests ×2, httpx
— both *implementing* netrc auth), cred-files fires on bare `.env`
mentions (69 live), and cred-env-dump fires MEDIUM on any `os.environ`
/ `process.env` access (21 live; every CLI and HTTP library on earth).
Fix: bare mentions of .netrc/.env/environment access drop to low/info
unless paired with read/open/serialize semantics in the same file;
keep HIGH for full credential-store paths (id_rsa, id_ed25519,
.aws/credentials, browser Login Data) and for actual read calls
against them.
**Expected effect:** removes the HIGH/MEDIUM credential legs behind
the stealer-xfile chains in requests and curl and ~90 live findings
overall; httpx likely drops to CLEAN-adjacent REVIEW, click loses 6
of 13 live findings.
**Fixture safety: SAFE with one flagged tradeoff.** Evasion/01 reads
id_rsa + .aws/credentials via fs.readFileSync — full paths plus read
semantics, still HIGH, and the private-key cross-file chain still
completes. malicious-skill uses explicit credential-store paths.
Tradeoff: a stealer that *only* embeds credential paths as strings
without any read call in the same file would lose a severity level
on that leg; its chains would still fire on the network/exec legs,
but this is the one change of the three that touches a real
detection surface and should ship with a fixture asserting the
read-semantics case.

### Runner-up fixes (not in the top 3, all fixture-safe)
- Directory-level corpus detection for template-per-file corpora
  (nuclei-templates: 885 live findings, 17 contextual — the per-file
  ≥5-rule corpus test structurally cannot see this shape).
- Exempt zero-width joiner/non-joiner in fa/ar locale/data files
  (orthographic, not smuggling).
- sc-no-lockfile: check the workspace root only (vue's 18 hits are
  monorepo member manifests).
- sc-tarball-dep: don't flag files.pythonhosted.org URLs recorded in
  uv.lock (that is the registry's own file host).
- obf-hex-exec: require decode+exec proximity outside test code
  (tokio's HIGH is a byte literal in codec tests).
