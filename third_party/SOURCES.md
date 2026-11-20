# RepoGate Phase-1 vendor bundle — sources, licenses, exclusions

Bundle built 2026-11-20 on the project workstation. This is **detection data only** — no upstream engine
code was taken. Every vendored file was copied byte-for-byte from a clean clone, and
each one is hashed in `MANIFEST.sha256` next to this file.

Totals for the vendored content under `third_party/`: 87 files, 1,537,659 bytes.

| Component | Upstream | Commit | License | Files |
| --- | --- | --- | --- | --- |
| Sigil core packs | https://github.com/NOMARJ/sigil | `5b379725de7bb219b660a2f6eda5545c36b13d91` | Apache-2.0 | 19 JSON + LICENSE |
| GuardDog YARA rules | https://github.com/DataDog/guarddog | `5da9538eb05b8c2710db60541ec9732557687f8b` | Apache-2.0 | 55 `.yar` + 4 `.meta` + LICENSE + NOTICE |
| GuardDog top-packages data | https://github.com/DataDog/guarddog | `5da9538eb05b8c2710db60541ec9732557687f8b` | Apache-2.0 | 4 JSON + LICENSE + NOTICE |

Both clones were taken at the commit above and their working trees were clean
(`git status --porcelain` empty) before copying.

---

## 1. Sigil — `cli/packs/core/v1/`

- **Upstream:** https://github.com/NOMARJ/sigil
- **Commit cloned:** `5b379725de7bb219b660a2f6eda5545c36b13d91`
  (2026-10-09 17:08:19 +1000, "Make the CLI and the API agree on scan, report and
  threat-lookup requests (#188)")
- **Upstream package version at that commit:** Sigil CLI crate `1.3.7` (`cli/Cargo.toml`)
- **License:** Apache-2.0 (`LICENSE` at repo root, 11,357 bytes, copied verbatim to
  `third_party/sigil-packs/LICENSE`; `cli/Cargo.toml` declares `license = "Apache-2.0"`).
  Sigil carries **no root `NOTICE`** file, so §4(d) imposes no notice obligation for this
  component.
- **Taken, verbatim:** all 19 JSON files of `cli/packs/core/v1/` (652,093 bytes), unchanged,
  in directory order, plus the repo-root `LICENSE` (11,357 bytes). 432 rule entries in
  total; every rule `id` is unique across the whole pack set (checked programmatically,
  0 duplicates).

| Pack file | Meta version | Rules (all rule-list keys) |
| --- | --- | --- |
| agent_instructions.json | 1.1.0 | 33 |
| agent_manipulation.json | 1.3.0 | 13 |
| agent_supply_chain.json | 1.0.0 | 21 |
| code_patterns.json | 1.0.0 | 23 |
| creds.json | 1.2.0 | 39 |
| inference_security.json | 1.0.0 | 13 |
| insecure_transport.json | 1.0.0 | 11 |
| install_hooks.json | 1.0.0 | 13 |
| multilingual_injection.json | 1.1.0 | 4 |
| network_exfil.json | 1.1.0 | 27 |
| obfuscation.json | 1.0.0 | 15 |
| obfuscation_chain.json | 1.0.0 | 19 |
| persistence.json | 1.0.0 | 13 |
| prompt_injection.json | 1.2.0 | 18 |
| provenance.json | 1.2.0 | 13 |
| reverse_shells.json | 1.0.0 | 81 |
| skill_security.json | 1.2.0 | 24 |
| structural.json | 1.0.0 | 25 |
| supply_chain.json | 1.2.0 | 27 |

Counts include `rules`, `provenance_rules`, `correlation_rules` and `engine_rules`;
rule-bearing files also carry a `meta` block (`id`, `name`, `version`, `updated_at`,
`author`, `description`) that RepoGate can use directly.

### Exclusions applied

- **`packs/lolbin/v1/` — EXCLUDED, GPL-3.0.** This is the hard exclusion from the brief,
  and it holds: at this commit the GPL bundle lives at `packs/lolbin/v1/`
  (`lolbin_unix.json`, `lolbin_windows.json`, `LICENSE`, `NOTICE.md`) — **not** under
  `cli/packs/`, so the requested path never intersected it. Upstream's own
  `packs/lolbin/v1/NOTICE.md` records that those rules are generated from
  GTFOBins (`GTFOBins/GTFOBins.github.io@acd5246`) and LOLBAS
  (`LOLBAS-Project/LOLBAS@f06df10`), both GPL-3.0, and that the bundle is kept separate
  from the Apache-2.0 binary for exactly that reason (`packs/lolbin/v1/LICENSE`
  is the full GNU GPL v3 text).
  **No part of that pack is in this bundle.** Verified after copying: no file named
  `*lolbin*`/`*lolbas*` from Sigil, no `lolbin_unix`/`lolbin_windows` identifiers, and no
  GNU GPL text anywhere in the bundle.
- `cli/packs/known-good/v1/top-packages-2026-09.manifest.json` — present upstream,
  **not taken** (outside the `core/v1` scope given in the brief).
- Everything else in the Sigil repository (CLI/Rust source, API, dashboard, plugins,
  docs, top-level `packs/` plugin marketplace content) — not taken. Data only.

### Provenance note (not an exclusion)

`reverse_shells.json` is Apache-2.0 as part of the Sigil pack set, but its own
`meta.description` states it was generated from the **MIT**-licensed
`0dayCTF/reverse-shell-generator@9fda27f91b1b` (retrieved 2026-06-22). MIT is
one-way compatible with Apache-2.0 redistribution, so it stays in scope; the upstream
attribution string is preserved verbatim inside the file. Upstream explicitly confirms
in `packs/lolbin/v1/NOTICE.md` that this pack is MIT-derived and therefore is embedded
in the Apache-2.0 binary — unlike the GPL lolbin packs.

---

## 2. GuardDog — YARA rules

- **Upstream:** https://github.com/DataDog/guarddog
- **Commit cloned:** `5da9538eb05b8c2710db60541ec9732557687f8b`
  (2026-11-16 20:00:40 +0000, "Merge pull request #926 from
  DataDog/engraver-auto-version-upgrade/minorpatch/poetry/0-1794816337")
- **Upstream package version at that commit:** `3.2.0` (`pyproject.toml`)
- **License:** Apache-2.0 (`LICENSE` at repo root, 201 lines, copied verbatim).
  **`NOTICE` copied verbatim** per Apache-2.0 §4(d):
  ```
  Datadog guarddog
  Copyright [2022-Present] Datadog, Inc.

  This product includes software developed at Datadog (<https://www.datadoghq.com/).>
  ```
- **Taken, verbatim:** all 55 `guarddog/analyzer/sourcecode/*.yar` files
  (97,318 bytes), one public rule per file — 55 top-level rules in total.
  Additionally the 4 `.meta` include fragments from the same directory, because three of
  the `.yar` files will not compile without them (see next section).
- Full file list:

```
capability-filesystem-browser.yar          threat-network-exfiltration.yar
capability-filesystem-delete.yar           threat-network-outbound-shady-links.yar
capability-filesystem-read.yar             threat-network-reverse-shell.yar
capability-filesystem-write-executable.yar threat-npm-dependency-confusion.yar
capability-network-download.yar            threat-npm-http-dependency.yar
capability-network-lolbas.yar              threat-npm-preinstall-script.yar
capability-network-outbound.yar            threat-process-cryptomining.yar
capability-process-hooks.yar               threat-process-download-exec.yar
capability-process-schedule.yar            threat-process-hooks.yar
capability-process-spawn.yar               threat-process-injection-dll.yar
capability-runtime-clipboard.yar           threat-process-memory.yar
threat-filesystem-autostart.yar            threat-process-powershell-encoded.yar
threat-filesystem-destruction.yar          threat-process-spawn-silent.yar
threat-filesystem-read.yar                 threat-process-sysinfo.yar
threat-network-dns-exfil.yar               threat-runtime-autostart.yar
threat-network-exfil-messenger.yar         threat-runtime-dynamic-loader.yar
threat-network-exfil-sysinfo.yar           threat-runtime-enumeration.yar
threat-runtime-environment-read.yar        threat-runtime-obfuscation-import-exec.yar
threat-runtime-keylogging.yar              threat-runtime-obfuscation-js-mangling.yar
threat-runtime-obfuscation-api.yar         threat-runtime-obfuscation-log-suppress.yar
threat-runtime-obfuscation-base64exec.yar  threat-runtime-obfuscation-pyarmor.yar
threat-runtime-obfuscation-chr.yar         threat-runtime-obfuscation-steganography.yar
threat-runtime-obfuscation-dynamic-eval.yar threat-runtime-obfuscation-unicode.yar
threat-runtime-obfuscation-general.yar     threat-runtime-obfuscation.yar
threat-runtime-obfuscation-hidden-code.yar threat-runtime-screencapture.yar
threat-runtime-self-propagation.yar        threat-setup-import-aliasing.yar
threat-runtime-system-info.yar             threat-setup-network-in-install.yar
                                           threat-setup-suspicious-imports.yar
.meta support files: hooks.meta, lolbas-net.meta, lolbas-proc.meta, lolbas-sysinfo.meta
```

### Addition beyond the literal brief: the `.meta` include fragments

The brief said "`*.yar` (55 YARA rules)". The upstream directory also holds four
`.meta` files, and three rules `include` them:

- `capability-network-lolbas.yar` → `include "lolbas-net.meta"`
- `capability-process-hooks.yar` → `include "hooks.meta"`
- `threat-process-sysinfo.yar` → `include "lolbas-sysinfo.meta"`

Those fragments define private helper rules (`lolbas_net`, `has_npm_hook`,
`lolbas_sysinfo`) referenced in the public rules' conditions. Without them the rules do
not compile. I vendored all four `.meta` files verbatim (`lolbas-proc.meta` is not
referenced by any `.yar` at this commit — that is upstream's state, and it is kept for
fidelity).

Proof, using `yara-python` 4.5.4 against the vendored directory (`verify_rules.py`,
scratch, not shipped):

- with the `.meta` files present: **55/55 rules compile**;
- in a copy holding only the 55 `.yar` files: **52/55**, with the three include-dependent
  rules failing on `undefined identifier`.

**Integration note:** GuardDog compiles each rule with
`yara.compile(filepath=rule_path)` and no `include_callback`
(`guarddog/analyzer/analyzer.py`), so libyara resolves `include` relative to the process
working directory. RepoGate should compile with the `guarddog-yara` directory as CWD or
supply an `include_callback` that resolves into it — otherwise those three rules fail
even though the files are present.

### Exclusions applied

- No GuardDog engine code (Python), tests, evals, notebooks, docs, `RULES.md`,
  `WRITING_RULES.md`, lockfiles, or `LICENSE-3rdparty.csv` were taken — that file lists
  the dependencies of GuardDog's *engine* (semgrep LGPL-2.1, tqdm MPL-2.0, etc.), none of
  which is redistributed here.
- GuardDog's `capability-network-lolbas.yar` is GuardDog's own Apache-2.0 rule about
  Windows LOLBAS binaries. It is **not** Sigil's GPL-3.0 lolbin pack and embeds no
  GTFOBins/LOLBAS corpus data; it is included.

---

## 3. GuardDog — top-packages data

- **Upstream:** https://github.com/DataDog/guarddog (same commit
  `5da9538eb05b8c2710db60541ec9732557687f8b`)
- **License:** Apache-2.0, same `LICENSE`; `NOTICE` copied alongside per §4(d).
- **Upstream paths:** `guarddog/analyzer/metadata/resources/top_{go,npm,pypi,rubygems}_packages.json`
- **Taken, verbatim:** all four files (749,778 bytes). Shape is
  `{"downloaded_timestamp": <int>, "packages": [<name>, ...]}`.

| File | Packages | `downloaded_timestamp` (UTC) |
| --- | --- | --- |
| top_npm_packages.json | 8,000 | 2026-06-16T16:08:16Z |
| top_pypi_packages.json | 15,000 | 2026-06-16T16:08:17Z |
| top_go_packages.json | 2,921 | 2026-02-05T16:49:54Z |
| top_rubygems_packages.json | 974 | 2026-06-16T16:08:18Z |

The brief named the npm/PyPI lists; the same upstream directory holds Go and RubyGems
lists in the identical format and under the identical license, so all four are included
rather than dropping two that RepoGate would otherwise have to re-fetch. Say the word if
Phase 1 should ship only npm/PyPI — they are separable, one file each.

- **Excluded:** `placeholder_email_domains.txt` (same directory, not a package list);
  `tests/analyzer/metadata/resources/npm_data.json` (a test fixture, not production data).

---

## Integrity and reproduction

- `MANIFEST.sha256` (bundle root) lists the SHA-256 of every file above, paths relative
  to the bundle root. Verify with:
  `cd ~/repogate-vendor && sha256sum -c MANIFEST.sha256`
- Every copied file was compared byte-for-byte against its upstream original
  (`cmp`) after copying: 19/19 Sigil JSON + LICENSE, 55/55 `.yar`, 4/4 `.meta`,
  4/4 data JSON, LICENSE and NOTICE — zero mismatches.
- Upstream counts match the vendored counts exactly (19, 55, 4), so nothing was silently
  dropped.
- To reproduce: clone both repos, `git checkout` the two commit SHAs above, then copy the
  listed paths. No upstream repo or local config was modified while building this bundle;
  the clones live in a task scratch workspace.

## License summary for redistribution

Everything in this bundle is Apache-2.0. The two `LICENSE` copies and GuardDog's
`NOTICE` are included verbatim; GuardDog's `NOTICE` also sits in `third_party/guarddog-data/`
so that directory stands alone if split out later. No GPL-3.0 content is present.
