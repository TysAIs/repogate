# RepoGate v1.3 — false-positive calibration record (Nov 20, 2026)

Response to fp-baseline-1.md (v1.2: 0 CLEAN / 2 REVIEW / 10 BLOCK on benign
repos) and the fleet's independent verification (same verdicts on a disjoint
set: fastify/gin/werkzeug/starlette/cobra). All fixes regression-tested:
the fixture suite (clean CLEAN, malicious-skill BLOCK with all chains,
evasion 10/10 BLOCK) passes after every round.

## Final benign table (local clones, .git included)

| repo | v1.2 | v1.3 | note |
| --- | --- | --- | --- |
| faker-ruby/faker | BLOCK 100 | REVIEW 57 | locale + Hash#fetch + `oast.` in "roast." |
| expressjs/express | BLOCK | CLEAN 7 | sole cause was a chain on a demoted leg |
| spf13/cobra | BLOCK 100 | REVIEW 62 | Makefile curl\|sh + completion persistence: true patterns, REVIEW tier |
| tokio-rs/tokio | REVIEW 36 | REVIEW 29 | |
| encode/httpx | REVIEW 47 | CLEAN 10 | .netrc reclass |
| vuejs/core | BLOCK | REVIEW 88 | `npx only-allow pnpm` was a lone-critical BLOCK |
| prettier/prettier | BLOCK | REVIEW 100 | score saturation, bulk gate |
| psf/requests | BLOCK class | REVIEW 51 | .netrc + compat-shim reflection |
| pytest-dev/pytest | BLOCK | REVIEW 97 | reflective architecture, bulk gate |
| django/django | — | REVIEW 100 | bulk gate |
| projectdiscovery/nuclei-templates | BLOCK | BLOCK 100 | DOCUMENTED true-context: findings are live attack payloads; a same-file dropper chain completes inside a code template. Specimen corpora with non-corpus path names need a policy declaration (v2 RRF policy layer), not silent tuning. |

## Fix rounds

Round 1 (from the baseline's three named fixes + data checks):
- Chains never complete on contextual findings (`live()` + same-file leg
  hygiene). chain-autorun-dropper had fired in 9/12 benign repos.
- auto-whitespace-hiding: category autorun → obfuscation; thresholds
  tightened (space-run shape at any length, bare line > 2000 chars);
  locale paths exempt.
- exec-eval / exec-eval-nonliteral: lookbehind boundaries — RegExp.exec(),
  method calls, and identifiers ending in "Function" no longer match.
- cred-env-dump: bare os.environ access removed; dump shapes only;
  later also scoped to code files.
- Credential-reference demotion: cred-ssh-aws/browser/keychain/files
  findings without read semantics in the file go contextual.
- net-fetch split: bare `fetch(` is JS/TS-only (Ruby Hash#fetch = 206 FPs).
- Locale context for obf-unicode-hidden (ZWNJ is Persian orthography).
- Per-rule score cap (first 5 findings score).

Round 2 (clone-scan reality + leg analysis):
- hook-githooks excludes `*.sample` (git's inert templates; a clone's
  .git/hooks completed chains in every cloned repo).
- net-webhook `oast.` requires a non-letter before it ("roast." is food).
- .netrc moved cred-ssh-aws → cred-files (HTTP-client behaviour).
- exec-indirection high → medium; getattr arm narrowed to dangerous
  names/dunders (getattr(x, "__init__") is standard introspection).
- Makefile curl|sh demotes one tier (explicit-invocation surface).

Round 3 (chain-leg economics + scoring model):
- Cross-file stealer requires a credential-STORE leg (cred-ssh-aws,
  cred-browser, cred-keychain, cred-keyword-filter). Generic .env/env
  legs completed it in requests/django/pytest/prettier/vue alike.
- Package-chain legs must sit on an executable surface: code files, CI
  workflow definitions, package.json. Data describing a capability is
  not the capability (template libraries).
- Diminishing per-rule scoring: first finding full weight, next 4 at +1.
- Lone critical forces BLOCK only on an executable surface or as a
  chain — with prompt-injection criticals exempted (live PI is in skill
  scope by construction; tags-block fixture regression caught this).
- Score-only BLOCK does not survive bulk: >500 scanned files with no
  chain and no surface critical caps at REVIEW. Padding buys an attacker
  only a human review; chains and criticals bypass the gate.
- BENIGN_LIFECYCLE exact-shape list (only-allow, husky, patch-package,
  echo/true/exit 0): listed at medium, never a lone-critical BLOCK.

## Bugs found in RepoGate itself during this pass

- const_propagate was silently broken for the canonical varcat shape:
  ASSIGN_RE's first-char class excluded `_` (so `_a = 'sy'` never
  registered), its trailing anchor consumed the newline (only the first
  of consecutive assignments was found), and substitution rewrote the
  definition site. All three fixed; fixture 09's payload was changed to
  a pipe-free command so the fixture now regresses the reflection catch
  itself (exec-resolved-reflection, new critical rule) instead of the
  literal `curl | bash` string the fleet verifier caught it coasting on.
- VERSION string said 0.1.0; now 1.3 (fleet verifier catch).

## Performance (same trees, v1.1 → v1.3)

- pytest tree (652 files): 25.7s → 8.9s
- django tree (7,104 files): 131.4s → 44.7s
From: Tags-block regex guard, one-time pattern precompilation, variant
gates. The prefilter/multiprocessing/incremental-cache tier remains in
research/performance.md as the v2 lever.

## Known limits after v1.3

- nuclei-templates class (specimen corpora under ordinary path names)
  still BLOCKs — findings are accurate; the verdict needs a corpus
  policy declaration, designed into the v2 RRF policy layer.
- REVIEW is doing real work in this calibration: frameworks that execute
  code by design (pytest, django, vue) land at high REVIEW scores. That
  is the honest tier for "you are about to run a code-execution engine."
