#!/usr/bin/env python3
"""RepoGate — read-only pre-clone / pre-run scanner for repositories and AI agent skills.

Scans a local directory, an archive (.zip/.tar.gz), a single file, or a GitHub
repo (fetched as an API tarball — never git-cloned, never executed) and reports
malware-shaped patterns: lifecycle hooks, auto-run configs, credential access,
network exfiltration, obfuscation, prompt injection, and supply-chain smells.
Findings are correlated into risk chains. NOTHING scanned is ever executed.

A clean verdict means "nothing found", never "safe".

Zero third-party dependencies: Python 3.10+ standard library only.

Exit codes: 0 = CLEAN, 1 = REVIEW or INCONCLUSIVE, 2 = BLOCK, 3 = tool error.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import io
import json
import math
import os
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "1.3"

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_WEIGHT = {"info": 1, "low": 3, "medium": 8, "high": 20, "critical": 45}
CATEGORY_CAP = 60           # max score contribution per category (anti-flood)
MAX_FILE_BYTES = 8 * 1024 * 1024   # files above this are head+tail scanned (partial)
HEAD_TAIL_BYTES = 512 * 1024

CODE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".sh", ".bash",
             ".zsh", ".rb", ".pl", ".php", ".go", ".rs", ".java", ".c", ".cpp",
             ".ps1", ".bat", ".cmd", ".lua", ".r", ".swift", ".kt"}
DOC_EXTS = {".md", ".markdown", ".txt", ".rst", ".mdx"}
CONFIG_EXTS = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".xml"}
BYTECODE_EXTS = {".pyc", ".pyo", ".class", ".wasm"}
BINARY_EXTS = {".exe", ".dll", ".so", ".dylib", ".bin", ".dat", ".o", ".a",
               ".deb", ".rpm", ".msi", ".dmg", ".elf"}

# ---------------------------------------------------------------- rules ----
# Each rule: id, category, severity, any-of regex patterns, optional filename
# scope (regex on the relative path), optional extensions scope, note.
# Patterns run against the raw text AND a normalized copy (see normalize()).

def R(rid, cat, sev, patterns, note, paths=None, exts=None):
    return {"id": rid, "category": cat, "severity": sev, "patterns": patterns,
            "note": note, "paths": paths, "exts": exts}

RULES = [
    # --- credential access -------------------------------------------------
    R("cred-ssh-aws", "credential-access", "high",
      [r"\.ssh[/\\]", r"\.aws[/\\]credentials", r"id_rsa", r"id_ed25519",
       r"\.gnupg[/\\]"],
      "References SSH/GPG/AWS credential locations. (.netrc lives in "
      "cred-files instead: every HTTP client reads it for the user's own "
      "auth — client behaviour, not a theft shape; requests/httpx measured)"),
    R("cred-browser", "credential-access", "high",
      [r"Login Data", r"Cookies\.sqlite", r"cookies\.sqlite",
       r"Chrome[/\\]User Data", r"mozilla[/\\].*cookies", r"Local State"],
      "References browser credential/cookie stores"),
    R("cred-env-dump", "credential-access", "medium",
      [r"dict\(os\.environ\)", r"os\.environ\.items\(\)", r"os\.environ\.copy\(\)",
       r"\{\s*\*\*\s*os\.environ", r"for\s+\w+\s+in\s+os\.environ\b",
       r"json\.dumps\(\s*os\.environ", r"printenv\b",
       r"\benv\s*\|", r"process\.env\b(?!\.)", r"JSON\.stringify\(process\.env\)",
       r"\.\.\.process\.env"],
      "Bulk environment-variable dump (possible secret harvest); a bare "
      "os.environ / process.env.KEY access is ordinary configuration, not "
      "a dump. Code files only: in YAML/JSON data these strings are "
      "payload text, not behaviour (nuclei-templates' cgi-printenv "
      "detection templates measured)", exts=CODE_EXTS),
    R("cred-keychain", "credential-access", "high",
      [r"security find-generic-password", r"Keychain", r"secret-tool lookup",
       r"gnome-keyring", r"Credential Manager", r"vault kv get"],
      "References OS keychain / secret-store access"),
    R("cred-files", "credential-access", "medium",
      [r"\.env\b", r"\.env\.(local|production|prod|dev)", r"credentials\.json",
       r"secrets?\.(json|ya?ml|toml)", r"\.netrc"],
      "References .env / credentials / secrets files", exts=CODE_EXTS),

    # --- network / exfiltration --------------------------------------------
    R("net-raw-ip", "network-exfil", "medium",
      [r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"],
      "URL with a raw IP address instead of a hostname"),
    R("net-metadata-ip", "network-exfil", "critical",
      [r"169\.254\.169\.254", r"metadata\.google\.internal",
       r"100\.100\.100\.200"],
      "Cloud instance-metadata endpoint (credential theft vector)"),
    R("net-webhook", "network-exfil", "high",
      [r"discord(app)?\.com/api/webhooks", r"api\.telegram\.org/bot",
       r"hooks\.slack\.com/services", r"webhook\.site", r"requestbin",
       r"pipedream\.net", r"burpcollaborator", r"(?<![A-Za-z])oast\.[a-z]{2,}",
       r"interact\.sh"],
      "Third-party webhook / request-bin endpoint (classic exfil channel)"),
    R("net-paste", "network-exfil", "medium",
      [r"pastebin\.com/(raw|api)", r"hastebin", r"dpaste", r"ix\.io",
       r"transfer\.sh", r"0x0\.st", r"file\.io"],
      "Paste / anonymous file-host service reference"),
    R("net-curl-pipe-shell", "network-exfil", "critical",
      [r"(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(ba)?sh\b",
       r"(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?zsh\b",
       r"iwr\b[^|\n]*\|\s*iex\b", r"Invoke-Expression.*DownloadString"],
      "Download piped directly into a shell (remote code execution)"),
    R("net-download-exec", "network-exfil", "high",
      [r"DownloadString\(", r"DownloadFile\(", r"urlopen\([^)]*\)[\s\S]{0,200}(exec|eval)\(",
       r"requests\.get\([^)]*\)[\s\S]{0,200}(exec|eval|__import__)"],
      "Downloads remote content and executes it"),
    R("net-dns-tunnel", "network-exfil", "high",
      [r"dnscat", r"iodine", r"dns\.resolve.*txt", r"dig\s+.*\$\(",
       r"nslookup\s+.*\$\("],
      "Possible DNS-tunnelling exfiltration"),

    # --- execution / dynamic code -------------------------------------------
    R("exec-eval", "execution", "medium",
      [r"(?<![\w$.])eval\s*\(", r"(?<![\w$.])exec\s*\(",
       r"(?<![\w$])Function\s*\([^)]*\)\s*\(",
       r"child_process\.(exec|execSync|spawn)", r"os\.system\s*\(",
       r"subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True"],
      "Dynamic code execution primitive", exts=CODE_EXTS),
    R("exec-indirection", "execution", "medium",
      [r"getattr\s*\([^,]+,\s*['\"][^'\"]*(system|popen|exec|eval|__import__|__builtins__|__getattribute__|__class__|__subclasses__|__globals__)",
       r"__import__\s*\(", r"importlib\.import_module",
       r"globals\(\)\[", r"eval\(atob", r"eval\(Buffer\.from"],
      "Indirect / reflective execution. Medium, with the getattr arm "
      "narrowed to dangerous names/dunders: getattr(x, '__init__') and "
      "importlib.import_module are standard introspection in plugin "
      "frameworks (pytest measured: 15 false highs), while getattr "
      "resolving to an executor is exec-resolved-reflection's critical"),
    R("exec-resolved-reflection", "execution", "critical",
      [r"getattr\s*\([^,]+,\s*['\"](system|popen|exec|execv|execve|eval|__import__)['\"]\s*\)",
       r"getattr\s*\([^,]+,\s*['\"][^'\"]*(system|popen)['\"]\s*\)\s*\("],
      "Reflection resolves to a named executor (os.system/popen/exec/eval). "
      "In folded/propagated variants this is the varcat shape: the executor "
      "name was assembled from pieces so a raw scan never sees it. Literal "
      "getattr(os, 'system') in raw code is the same shape worn openly — "
      "benign dispatch code uses variable names, not executor literals",
      exts=CODE_EXTS),
    R("exec-shell-string", "execution", "low",
      [r"os\.popen\s*\(", r"Runtime\.getRuntime\(\)\.exec", r"shell_exec\s*\(",
       r"passthru\s*\(", r"popen\s*\("],
      "Shell invocation primitive", exts=CODE_EXTS),
    R("exec-eval-nonliteral", "execution", "high",
      [r"(?<![\w$.])eval\s*\(\s*[A-Za-z_$]", r"(?<![\w$.])exec\s*\(\s*[A-Za-z_$]",
       r"(?<![\w$])Function\s*\(\s*[A-Za-z_$]"],
      "eval/exec called on a variable, not a literal — the executed content "
      "is not visible in the source. Lookbehinds keep RegExp.exec(), "
      "Hash#fetch-style method calls and identifiers ending in 'Function' "
      "from matching (measured FP class on vue/prettier)", exts=CODE_EXTS),

    # --- obfuscation ---------------------------------------------------------
    R("obf-base64-exec", "obfuscation", "high",
      [r"base64\.b64decode[\s\S]{0,200}(exec|eval|__import__|os\.system)",
       r"atob\s*\([^)]*\)[\s\S]{0,120}(eval|Function)",
       r"fromCharCode[\s\S]{0,120}eval"],
      "Base64-decoded content fed to an executor"),
    R("obf-long-blob", "obfuscation", "medium",
      [r"[A-Za-z0-9+/=]{400,}"],
      "Very long base64-shaped blob (possible hidden payload)"),
    R("obf-hex-exec", "obfuscation", "high",
      [r"bytes\.fromhex[\s\S]{0,200}(exec|eval)", r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){15,}"],
      "Hex-encoded content, possibly decoded and executed"),
    R("obf-string-split", "obfuscation", "low",
      [r"['\"][a-z]{1,3}['\"]\s*\+\s*['\"][a-z]{1,4}['\"]\s*\+\s*['\"][a-z]{1,4}['\"]\s*\+",
       r"\.join\(\[", r"String\.fromCharCode\((\d+,){8,}"],
      "String-splitting / char-code assembly (evasion shape)", exts=CODE_EXTS),
    R("obf-unicode-hidden", "obfuscation", "high",
      ["\u200b", "\u200c", "\u200d", "\ufeff", "\u202a", "\u202b", "\u202c",
       "\u202d", "\u202e", "\u2060"],
      "Zero-width / bidi-control unicode characters (hidden-content smuggling)"),

    # --- prompt injection / agent manipulation (docs + skill + MCP files) ----
    R("pi-ignore-instructions", "prompt-injection", "critical",
      [r"ignore (all )?(previous|prior|above) instructions",
       r"disregard (all )?(previous|prior|your) (instructions|rules)",
       r"forget (all )?(previous|prior) instructions",
       r"you are (now|actually) (a|an|in)\b.{0,60}(mode|persona|assistant)"],
      "Prompt-injection: instruction override directed at an AI agent",
      exts=DOC_EXTS | CODE_EXTS | {".json", ".yaml", ".yml", ".xml", ".toml"}),
    R("pi-exfil-instruction", "prompt-injection", "critical",
      [r"(send|upload|post|transmit|forward).{0,80}(contents of|the file|~\/\.ssh|environment variables|api keys?|credentials)",
       r"(read|cat|open).{0,40}(\.env|id_rsa|\.aws).{0,80}(send|post|upload|share)",
       r"do not (tell|inform|mention to) the user"],
      "Instruction telling an agent to exfiltrate data or hide actions from the user",
      exts=DOC_EXTS | CODE_EXTS | {".json", ".yaml", ".yml", ".xml", ".toml"}),
    R("pi-hidden-directive", "prompt-injection", "high",
      [r"<!--[\s\S]{0,400}(instruction|you must|run this|execute)", 
       r"\[SYSTEM\]", r"<\s*system\s*>", r"IMPORTANT:\s*AI (assistant|agent)"],
      "Hidden or fake-system directive embedded in content",
      exts=DOC_EXTS | CODE_EXTS | {".json", ".yaml", ".yml", ".html", ".xml"}),
    R("pi-tool-poison", "prompt-injection", "high",
      [r"\"description\"\s*:\s*\"[^\"]{200,}",
       r"before (using|calling) this tool.{0,120}(first|always)",
       r"when (the user|you) (use|call) this tool.{0,120}(also|always|silently)"],
      "MCP/tool description shaped like an instruction to the agent",
      paths=r"(\.json$|mcp|server)"),

    # --- supply chain ---------------------------------------------------------
    R("sc-git-dep", "supply-chain", "medium",
      [r"\"(git\+https?|git://|github:)[^\"]+\"", r"=\s*\"git\+https?",
       r"url\s*=\s*\"https://github\.com/[^\"]+\""],
      "Dependency pinned to a git URL instead of a registry version"),
    R("sc-tarball-dep", "supply-chain", "medium",
      [r"\"resolved\"\s*:\s*\"https?://(?!registry\.npmjs\.org|registry\.yarnpkg\.com)",
       r"\"(https?://[^\"]+\.(tgz|tar\.gz))\""],
      "Dependency resolved from a non-registry tarball URL"),
]

POPULAR_PACKAGES = {
    "requests", "express", "lodash", "react", "axios", "numpy", "pandas",
    "flask", "django", "chalk", "commander", "debug", "underscore", "moment",
    "typescript", "webpack", "eslint", "prettier", "dotenv", "uuid", "ws",
    "jsonwebtoken", "bcrypt", "mongoose", "redis", "pg", "mysql2",
}

# ------------------------------------------------------------- findings ----
@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    path: str
    line: int | None
    evidence: str
    note: str
    chain: bool = False
    contextual: bool = False   # test/demo/corpus/doc context: listed, never scored

@dataclass
class ScanResult:
    target: str
    findings: list = field(default_factory=list)
    files_total: int = 0
    files_scanned: int = 0
    files_partial: int = 0
    files_skipped: list = field(default_factory=list)
    trust: dict = field(default_factory=dict)

    def add(self, f: Finding):
        self.findings.append(f)

# --------------------------------------------------------- normalization ----
ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\ufeff\u2060"), None)
B64_RUN = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
STR_CONCAT = re.compile(r"""(['\"])((?:(?!\1).)*)\1\s*\+\s*(['\"])((?:(?!\3).)*)\3""")

TAGS_RE = re.compile(r"[\U000E0000-\U000E007F]")

def decode_tags_block(text: str) -> str:
    """Unicode Tags block (U+E0000..U+E007F) smuggles ASCII: char - 0xE0000.
    Guarded by a single regex probe: the per-character loop costs ~27% of
    profiled runtime on real trees where Tags chars appear in 0 files."""
    if not TAGS_RE.search(text):
        return ""
    out = []
    for ch in text:
        o = ord(ch)
        if 0xE0000 <= o <= 0xE007F:
            out.append(chr(o - 0xE0000))
    return "".join(out)

def normalize(text: str) -> str:
    """Constant-fold literal string concatenation so split keywords re-form."""
    prev = None
    cur = text
    for _ in range(6):
        if cur == prev:
            break
        prev = cur
        cur = STR_CONCAT.sub(lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1), cur)
    return cur

ASSIGN_RE = re.compile(r"""(?m)^[ \t]*(?:const\s+|let\s+|var\s+)?([_A-Za-z$][\w$]*)\s*=\s*(['\"])((?:(?!\2).){1,400})\2[ \t]*;?""")

def const_propagate(text: str) -> str:
    """Light constant propagation: substitute identifiers that were assigned
    a string literal with that literal, then re-fold concatenations. Catches
    payload strings split across variables (the verifier's b64-varcat and
    getattr-varcat fixtures). Shadowing/reassignment makes this approximate
    by design — it only ever ADDS a rescanned variant, never removes one.

    Two measured bugs fixed in 1.3: the old anchor consumed the trailing
    newline, so only the FIRST of consecutive assignments was ever found;
    and substitution rewrote the definition site itself ('_a = ...' became
    ''sy' = ...'). Substitution now skips every assignment statement's own
    span."""
    env = {}
    spans = []
    for m in ASSIGN_RE.finditer(text):
        env[m.group(1)] = (m.group(2), m.group(3))
        spans.append(m.span())
    if not env:
        return text
    def in_span(pos):
        return any(a <= pos < b for a, b in spans)
    # Single pass over the ORIGINAL text so span positions stay valid.
    names = sorted(env, key=len, reverse=True)
    pat = re.compile(r"(?<![\w$])(" + "|".join(re.escape(n) for n in names)
                     + r")(?![\w$])")
    def repl(m):
        if in_span(m.start()):
            return m.group(0)
        q, val = env[m.group(1)]
        return q + val + q
    return normalize(pat.sub(repl, text))

def decoded_variants(text: str):
    """Yield rescannable text recovered from base64 runs and Tags block."""
    tags = decode_tags_block(text)
    if len(tags) >= 8:
        yield tags
    for m in B64_RUN.finditer(text):
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        try:
            dec = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if sum(c.isprintable() or c in "\n\t" for c in dec) / max(len(dec), 1) > 0.85:
            yield dec

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())

# ------------------------------------------------------------ inventory ----
def classify(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in BYTECODE_EXTS:
        return "bytecode"
    if ext in BINARY_EXTS:
        return "binary"
    if ext in CODE_EXTS:
        return "code"
    if ext in DOC_EXTS:
        return "doc"
    if ext in CONFIG_EXTS:
        return "config"
    if path.name in {"Makefile", "Dockerfile", "Jenkinsfile", "Vagrantfile"}:
        return "code"
    return "other"

TEXTY = {"code", "doc", "config", "other"}

def read_for_scan(path: Path):
    """Return (text, partial). Oversized files are head+tail scanned, never
    silently skipped (anti-truncation)."""
    size = path.stat().st_size
    if size <= MAX_FILE_BYTES:
        data = path.read_bytes()
        return data.decode("utf-8", errors="replace"), False
    with open(path, "rb") as fh:
        head = fh.read(HEAD_TAIL_BYTES)
        fh.seek(-HEAD_TAIL_BYTES, os.SEEK_END)
        tail = fh.read(HEAD_TAIL_BYTES)
    return (head + b"\n" + tail).decode("utf-8", errors="replace"), True

# ------------------------------------------------------ structural checks ---
LIFECYCLE_KEYS = ("preinstall", "install", "postinstall", "prepare",
                  "prepublish", "prepack", "postpack")
EXEC_TOKEN = re.compile(r"\b(node|npx|curl|wget|bash|sh|zsh|powershell|pwsh|bun|deno|python\d?|pip\d?|chmod|eval|http)", re.I)
# Lifecycle commands whose whole behaviour is a known, bounded guard or
# setup step. They still run at install (listed, medium) but they are not
# droppers: vue core's `npx only-allow pnpm` preinstall was a lone-critical
# BLOCK before this list existed. Exact-shape matches only — anything
# chained (`&&`, `;`, `|`) falls through to the EXEC_TOKEN reading.
BENIGN_LIFECYCLE = re.compile(
    r"^\s*(npx\s+only-allow\s+\w+|husky(\s+install)?|patch-package"
    r"|echo\b[^|&;]*|true|exit\s+0)\s*$")

def check_package_json(rel: str, text: str, res: ScanResult):
    try:
        pkg = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        res.add(Finding("struct-pkg-unparseable", "supply-chain", "low", rel, None,
                        "package.json does not parse", "Unparseable manifest hides its scripts"))
        return
    scripts = pkg.get("scripts") or {}
    for key in LIFECYCLE_KEYS:
        if key in scripts:
            val = str(scripts[key])
            if BENIGN_LIFECYCLE.match(val):
                sev, tail = "medium", " (known guard/setup command)"
            elif EXEC_TOKEN.search(val):
                sev, tail = "critical", " and fetches/executes"
            else:
                sev, tail = "medium", ""
            res.add(Finding("hook-npm-lifecycle", "lifecycle-hooks", sev, rel, None,
                            f"scripts.{key} = {val[:120]}",
                            "npm lifecycle script runs automatically on install"
                            + tail))
    deps = {}
    for sect in ("dependencies", "devDependencies", "optionalDependencies"):
        deps.update(pkg.get(sect) or {})
    for name, spec in deps.items():
        spec = str(spec)
        if spec.startswith(("git+", "git://", "github:", "http://", "https://")) \
                and "registry" not in spec:
            res.add(Finding("sc-git-dep-struct", "supply-chain", "high", rel, None,
                            f"{name}: {spec[:100]}",
                            "Dependency fetched from a mutable remote, not a registry"))
        base = name.split("/")[-1].lower()
        for pop in POPULAR_PACKAGES:
            if base != pop and damerau(base, pop) <= 1 and len(pop) >= 4:
                res.add(Finding("sc-typosquat", "supply-chain", "high", rel, None,
                                f"{name} ~ {pop}",
                                "Dependency name is one edit from a popular package"))
                break
    if deps and not any((Path(res.target) / lf).exists()
                         for lf in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml")):
        res.add(Finding("sc-no-lockfile", "supply-chain", "low", rel, None,
                        f"{len(deps)} dependencies, no lockfile in repo",
                        "Floating dependency resolution"))

def damerau(a: str, b: str) -> int:
    """Damerau-Levenshtein distance (small strings only)."""
    la, lb = len(a), len(b)
    if abs(la - lb) > 2:
        return 3
    d = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        d[i][0] = i
    for j in range(lb + 1):
        d[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[la][lb]

def check_vscode_tasks(rel: str, text: str, res: ScanResult):
    folder_open = '"runOn"' in text and "folderOpen" in text
    silent = '"reveal"' in text and '"silent"' in text
    if folder_open:
        sev = "critical" if (EXEC_TOKEN.search(text) or silent) else "high"
        res.add(Finding("auto-vscode-folderopen", "autorun", sev, rel, None,
                        "tasks.json task runs on folderOpen"
                        + (" with silent presentation" if silent else ""),
                        "Code executes when the folder is merely opened in VS Code "
                        "(Contagious Interview pattern)"))
    if "task.allowAutomaticTasks" in text and '"on"' in text:
        res.add(Finding("auto-vscode-allowauto", "autorun", "high", rel, None,
                        "task.allowAutomaticTasks = on",
                        "Workspace enables automatic tasks"))

def check_workflow(rel: str, text: str, res: ScanResult):
    untrusted = re.search(r"pull_request_target|workflow_run|issue_comment|repository_dispatch", text)
    head_checkout = re.search(r"pull_request\.head|github\.head_ref|refs/pull/", text)
    if untrusted and head_checkout:
        res.add(Finding("ci-untrusted-checkout", "ci", "critical", rel, None,
                        "Privileged trigger + checkout of untrusted PR ref",
                        "Classic GitHub Actions pwn-request: privileged token meets attacker code"))
    if re.search(r"run:\s*[^\n]*\$\{\{\s*(github\.event|github\.head_ref|.*\.title|.*\.body)", text):
        res.add(Finding("ci-template-injection", "ci", "high", rel, None,
                        "Event data interpolated directly inside run:",
                        "Script injection via attacker-controlled event fields"))
    if re.search(r"echo\s+[^\n]*\$\{\{\s*secrets\.", text) or "secrets: inherit" in text and untrusted:
        res.add(Finding("ci-secrets-exposure", "ci", "critical", rel, None,
                        "Secrets echoed or inherited into an untrusted-trigger workflow",
                        "CI token/secret theft shape"))
    if "permissions: write-all" in text:
        res.add(Finding("ci-write-all", "ci", "high", rel, None,
                        "permissions: write-all", "Workflow token has full write access"))
    for m in re.finditer(r"uses:\s*([\w.-]+/[\w./-]+)@([^\s#]+)", text):
        if not re.fullmatch(r"[0-9a-f]{40}", m.group(2)):
            res.add(Finding("ci-unpinned-action", "ci", "medium", rel, None,
                            f"{m.group(1)}@{m.group(2)}",
                            "Action pinned by tag/branch, not full commit SHA"))
    if "self-hosted" in text and untrusted:
        res.add(Finding("ci-self-hosted-untrusted", "ci", "medium", rel, None,
                        "Self-hosted runner on an untrusted trigger",
                        "Runner state can be poisoned across runs"))

def check_claude_settings(rel: str, text: str, res: ScanResult):
    if '"hooks"' in text or "SessionStart" in text or "PreToolUse" in text:
        res.add(Finding("persist-agent-hook", "persistence", "high", rel, None,
                        ".claude/settings.json defines hooks",
                        "Agent hooks execute automatically in future sessions "
                        "(Mini-Shai-Hulud persistence target)"))

def check_setup_py(rel: str, text: str, res: ScanResult):
    if re.search(r"cmdclass|class\s+\w+\((install|develop|build)", text) and \
            re.search(r"os\.system|subprocess|urllib|requests\.|socket", text):
        res.add(Finding("hook-setuppy-cmdclass", "lifecycle-hooks", "critical", rel, None,
                        "setup.py custom install command with exec/network",
                        "Code runs at pip install time"))
    elif re.search(r"^(import\s+(subprocess|socket)|.*(os\.system|urlopen)\s*\()", text, re.M):
        res.add(Finding("hook-setuppy-toplevel", "lifecycle-hooks", "high", rel, None,
                        "setup.py top-level exec/network call",
                        "Code runs at pip install time"))

def check_build_rs(rel: str, text: str, res: ScanResult):
    if re.search(r"process::Command|TcpStream|reqwest|curl", text):
        res.add(Finding("hook-buildrs-exec", "lifecycle-hooks", "high", rel, None,
                        "build.rs spawns processes or uses the network",
                        "Cargo build script executes at build time"))
    else:
        res.add(Finding("hook-buildrs-present", "lifecycle-hooks", "low", rel, None,
                        "build.rs present", "Cargo build script executes at build time"))

STRUCTURAL = [
    (r"(^|/)package\.json$", check_package_json),
    (r"\.vscode/(tasks|settings)\.json$", check_vscode_tasks),
    (r"\.github/workflows/[^/]+\.ya?ml$", check_workflow),
    (r"(^|/)\.claude/settings\.json$", check_claude_settings),
    (r"(^|/)setup\.py$", check_setup_py),
    (r"(^|/)build\.rs$", check_build_rs),
]

# Extra single-purpose regex rules absorbed from the 2026 best-practice sweep.
EXTRA_RULES = [
    R("auto-whitespace-hiding", "obfuscation", "high",
      [r" {80,}\S", r".{600,}"],
      "Content pushed far off-screen by whitespace or extreme line length "
      "(payload hiding, Contagious Interview shape)"),
    R("persist-agent-config-write", "persistence", "critical",
      [r"(writeFile|appendFile|createWriteStream|open\([^)]*['\"][wa]['\"]|>\s*|tee\s+|sed\s+-i)[^\n]*(\.claude/settings\.json|\.claude\.json|\.vscode/tasks\.json|claude_desktop_config\.json|\.mcp\.json|\.cursor/rules)"],
      "Code writes into agent/editor configuration (persistence implant)"),
    R("persist-os", "persistence", "high",
      [r"crontab\s+-", r"systemctl\s+enable", r"LaunchAgents|LaunchDaemons",
       r"schtasks\s+/create", r"reg\s+add[^\n]*\\Run", r">>\s*~/\.(bashrc|zshrc|profile)",
       r"\.config/autostart"],
      "OS-level persistence write (cron/systemd/launchd/registry/run keys)"),
    R("exec-agent-lotl", "execution", "critical",
      [r"(claude|codex|gemini|copilot|kiro-cli)\b[^\n]*(--dangerously-skip-permissions|--yolo|--ask-for-approval\s+never|--sandbox\s+danger-full-access|--autopilot)"],
      "Spawns an AI coding agent with safety checks disabled (agent LOTL)"),
    R("exec-defense-disable", "execution", "high",
      [r"Set-MpPreference[^\n]*-Disable", r"Add-MpPreference[^\n]*-Exclusion",
       r"DisableAntiSpyware", r"xattr\s+-d\s+com\.apple\.quarantine",
       r"spctl\s+--master-disable", r"Stop-Service\s+WinDefend"],
      "Disables endpoint defenses or quarantine"),
    R("exec-hidden-spawn", "execution", "high",
      [r"detached\s*:\s*true[\s\S]{0,120}unref\(\)", r"Start-Process[^\n]*-WindowStyle\s+Hidden",
       r"start_new_session\s*=\s*True[\s\S]{0,120}DEVNULL", r"nohup\s+[^\n]*&"],
      "Process spawned detached/hidden"),
    R("fetch-dead-drop", "network-exfil", "high",
      [r"eth_call", r"resolveTxt", r"dns\.resolve.*[Tt]xt",
       r"ipfs\.io/ipfs|gateway\.ipfs", r"docs\.google\.com[^\n]*export"],
      "Dead-drop resolver: next-stage address fetched from chain/DNS/docs"),
    R("cred-keyword-filter", "credential-access", "high",
      [r"(Object\.keys\(process\.env\)|os\.environ\.keys\(\)|env\.keys\(\))[^\n]{0,160}(TOKEN|SECRET|PASSWORD|KEY|AUTH)",
       r"for\s+\w+\s+in\s+os\.environ[^\n]{0,120}(TOKEN|SECRET|PASSWORD)"],
      "Environment scanned selectively for secret-looking keys"),
    R("exfil-tls-off", "network-exfil", "medium",
      [r"rejectUnauthorized\s*:\s*false", r"verify\s*=\s*False", r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0",
       r"curl\s+[^\n]*\s-k\b", r"InsecureSkipVerify\s*:\s*true"],
      "TLS verification disabled on outbound traffic"),
    R("hook-devcontainer", "autorun", "high",
      [r"\"(postCreateCommand|postStartCommand|initializeCommand)\"\s*:"],
      "Devcontainer lifecycle command runs automatically when the container is created",
      paths=r"devcontainer\.json$"),
    R("hook-githooks", "autorun", "medium",
      [r"."],
      "Executable hook shipped in the repo tree (.githooks/ or hooks/). "
      "*.sample files are excluded: they are git's own inert templates, "
      "present in every clone on earth, and git never executes them "
      "(faker-via-clone measured 14 false hits completing a chain)",
      paths=r"(^|/)(\.githooks|hooks)/[^/]+(?<!\.sample)$"),
    R("hook-direnv", "autorun", "high",
      [r"curl|wget|eval|source\s+https?"],
      ".envrc fetches or evaluates remote content on directory entry",
      paths=r"(^|/)\.envrc$"),
    R("obf-bytecode-shipped", "obfuscation", "medium",
      [r"."],
      "Compiled bytecode shipped without its source being obvious "
      "(opaque executable content; Trail of Bits bypass class)",
      exts=BYTECODE_EXTS),
    R("net-url-in-bytecode", "network-exfil", "medium",
      [r"https?://[^\s\"'<>]{4,}"],
      "URL in shipped bytecode's string table (its destination is part of "
      "the payload, not documentation)", exts=BYTECODE_EXTS),

    # --- fetch primitive: weak alone, completes chains -----------------------
    R("net-fetch-primitive", "network-exfil", "low",
      [r"axios\.(get|post|put|request)", r"requests\.(get|post|put|request)\s*\(",
       r"urlopen\s*\(", r"https?\.(get|request)\s*\(", r"XMLHttpRequest",
       r"Invoke-(WebRequest|RestMethod)"],
      "Network fetch primitive (context for chains)", exts=CODE_EXTS),
    R("net-fetch-js", "network-exfil", "low",
      [r"\bfetch\s*\("],
      "JS fetch() network primitive. Scoped to JS/TS only: in Ruby/Python "
      "fetch() is a hash/dict access, not the network (faker-ruby measured "
      "206 false hits)", exts={".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}),

    # --- environment / timing gating (sandbox evasion) -----------------------
    R("gate-env-ci", "evasion", "medium",
      [r"process\.env\.(CI|GITHUB_ACTIONS|GITLAB_CI|JENKINS_URL|BUILD_NUMBER)\b",
       r"os\.environ(\.get)?\(?\s*\[?\s*['\"](CI|GITHUB_ACTIONS|GITLAB_CI)['\"]",
       r"['\"]CI['\"]\s+in\s+os\.environ", r"env::var\(\s*\"(CI|GITHUB_ACTIONS)\""],
      "CI/environment detection (sandbox- and analysis-evasion shape)", exts=CODE_EXTS),
    R("gate-host-allowlist", "evasion", "medium",
      [r"(hostname\(\)|userInfo\(\)|getuser\(\)|whoami)[^\n]{0,100}(===|!==|==|includes\(|indexOf\()",
       r"(COMPUTERNAME|USERDOMAIN|SESSIONNAME)\b[^\n]{0,60}(==|===|!=)"],
      "Hostname/user allowlist check before acting (targeted-payload shape)", exts=CODE_EXTS),
    R("gate-date-bomb", "evasion", "low",
      [r"Date\.now\(\)\s*>\s*\d{10,}", r"new Date\(\)\s*>\s*new Date\(['\"]20\d\d",
       r"time\.time\(\)\s*>\s*\d{10,}", r"datetime\.now\(\)\s*>\s*datetime\(20\d\d"],
      "Date-gated execution (time-bomb shape)", exts=CODE_EXTS),
    R("gate-long-delay", "evasion", "low",
      [r"setTimeout\s*\([^)]*,\s*\d{5,}\s*\)", r"time\.sleep\s*\(\s*\d{2,}\s*\)",
       r"Thread\.sleep\s*\(\s*\d{5,}\s*\)"],
      "Long artificial delay before acting (analysis-timeout shape)", exts=CODE_EXTS),

    # --- git surfaces ----------------------------------------------------------
    R("git-submodule-file", "supply-chain", "high",
      [r"url\s*=\s*file://", r"url\s*=\s*https?://[^/\s:]+:[^@\s]+@"],
      ".gitmodules points at a local path or a credentialed URL",
      paths=r"(^|/)\.gitmodules$"),
    R("git-attributes-filter", "supply-chain", "medium",
      [r"\bfilter\s*=\s*[a-zA-Z]"],
      ".gitattributes declares a custom filter driver (runs on checkout/smudge)",
      paths=r"(^|/)\.gitattributes$"),
    R("git-lfs-pointer", "supply-chain", "info",
      [r"version https://git-lfs\.github\.com/spec/v1"],
      "Git LFS pointer: the real content is not in this tree (unscanned)"),
]
ALL_RULES = RULES + EXTRA_RULES
# Precompile every pattern once at load (prompt-injection rules are
# case-insensitive); the scan loop previously re-compiled per file.
for _rule in ALL_RULES:
    _flags = re.IGNORECASE if _rule["category"] == "prompt-injection" else 0
    _rule["compiled"] = [re.compile(p, _flags) for p in _rule["patterns"]]

# ---------------------------------------------------------------- engine ----
def line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1

def apply_rules(rel: str, text: str, res: ScanResult, origin: str = ""):
    ext = Path(rel).suffix.lower()
    variants = [("raw", text)]
    bases = [text]
    # Variant gates: the transforms are identity when their trigger shape is
    # absent, so skip the work (variant construction was ~19% of profiled
    # runtime on real trees).
    norm = text
    if STR_CONCAT.search(text):
        norm = normalize(text)
        if norm != text:
            variants.append(("normalized", norm))
            bases.append(norm)
    if ASSIGN_RE.search(text):
        prop = const_propagate(text)
        if prop != text and prop != norm:
            variants.append(("const-propagated", prop))
            bases.append(prop)
    # Decode base64/Tags content from BOTH the raw and the concatenation-
    # folded text (a blob split by string concatenation must still decode),
    # and decode one level deeper for nested wrapping. Capped for safety.
    seen_dec = set()
    frontier = list(bases)
    for _depth in range(2):
        nxt = []
        for b in frontier:
            for dec in decoded_variants(b):
                if dec not in seen_dec and len(variants) < 10:
                    seen_dec.add(dec)
                    variants.append(("decoded", dec))
                    nxt.append(dec)
        frontier = nxt
    seen = set()
    for rule in ALL_RULES:
        if rule["exts"] is not None and ext not in rule["exts"]:
            continue
        if rule["paths"] is not None and not re.search(rule["paths"], rel):
            continue
        if rule["id"] == "auto-whitespace-hiding":
            continue  # handled in the per-line pass
        for vname, vtext in variants:
            for pat in rule["compiled"]:
                try:
                    m = pat.search(vtext)
                except re.error:
                    continue
                if not m:
                    continue
                key = (rule["id"], rel)
                if key in seen:
                    break
                seen.add(key)
                line = line_of(vtext, m.start()) if vname == "raw" else None
                ev = re.sub(r"\s+", " ", m.group(0))[:140]
                res.add(Finding(rule["id"], rule["category"], rule["severity"], rel,
                                line, (f"[{vname}] " if vname != "raw" else "") + ev,
                                rule["note"]))
                break

ZIP_CONTAINER_EXTS = {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".whl",
                      ".epub", ".vsix", ".nupkg"}
MAX_NESTED_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_DEPTH = 2

def extract_strings(raw: bytes, min_len: int = 4) -> str:
    """Printable-string extraction for bytecode/binary content: ASCII runs
    plus UTF-16LE runs. A .pyc's string table carries its credential paths
    and URLs in the clear — scanning it is the difference between
    'inventoried' and 'inspected'."""
    out: list[str] = []
    cur = bytearray()
    for b in raw:
        if 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii"))
            cur = bytearray()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii"))
    cur = bytearray()
    i = 0
    while i + 1 < len(raw):
        b, z = raw[i], raw[i + 1]
        if z == 0 and 32 <= b < 127:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii"))
            cur = bytearray()
        i += 2
    if len(cur) >= min_len:
        out.append(cur.decode("ascii"))
    return "\n".join(out)

def _scan_nested_archive(fp: Path, rel: str, res: ScanResult,
                         file_cats: dict, depth: int):
    """Archives inside a tree are part of the tree: extract (same hardened
    path as top-level acquisition) and scan the contents with paths
    prefixed 'archive!/inner/path'. OOXML formats (.docx/.xlsx) are zips —
    their document.xml is agent-readable text and a known PI carrier."""
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="repogate-nested-"))
    try:
        if fp.suffix.lower() in ZIP_CONTAINER_EXTS:
            with zipfile.ZipFile(fp) as zf:
                safe_extract_zip(zf, tmp)
        else:
            with tarfile.open(fp) as tf:
                safe_extract_tar(tf, tmp)
        inner = scan_tree(str(tmp), res, prefix=rel + "!/", depth=depth + 1,
                          _top=False)
        for k, v in inner.items():
            file_cats.setdefault(k, set()).update(v)
        res.add(Finding("struct-nested-archive", "supply-chain", "info", rel,
                        None, "archive extracted and contents scanned",
                        "Nested archive contents are part of the scanned tree"))
    except Exception as e:
        res.files_skipped.append(f"{rel}: nested archive unreadable: {e}")
        res.add(Finding("struct-archive-unreadable", "supply-chain", "medium",
                        rel, None, f"archive could not be safely extracted: {e}",
                        "An archive that cannot be inspected dents coverage"))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

def scan_tree(root: str, res: ScanResult, prefix: str = "", depth: int = 0,
              _top: bool = True):
    rootp = Path(root)
    file_cats: dict[str, set] = {}
    mark = len(res.findings)
    for dirpath, dirnames, filenames in os.walk(rootp):
        dp = Path(dirpath)
        rel_dir = dp.relative_to(rootp).as_posix()
        if rel_dir.startswith(".git") and rel_dir not in (".git", ".git/hooks"):
            dirnames[:] = []
            continue
        for dname in list(dirnames):
            dpath = dp / dname
            if dpath.is_symlink():
                rel_l = dpath.relative_to(rootp).as_posix()
                tgt = os.readlink(dpath)
                outside = os.path.isabs(tgt) or ".." in Path(tgt).parts
                res.files_skipped.append(f"{rel_l}: symlinked directory not descended")
                res.add(Finding("struct-symlink-dir", "supply-chain",
                                "medium" if outside else "low", rel_l, None,
                                f"directory symlink -> {tgt}",
                                "Symlinked directories are not descended; their "
                                "content is unscanned and dents coverage"))
        for fn in filenames:
            fp = dp / fn
            rel = prefix + fp.relative_to(rootp).as_posix()
            res.files_total += 1
            if fp.is_symlink():
                target = os.readlink(fp)
                if os.path.isabs(target) or ".." in Path(target).parts:
                    res.add(Finding("struct-symlink-escape", "supply-chain", "medium",
                                    rel, None, f"symlink -> {target}",
                                    "Symlink points outside the tree"))
                continue
            low = fp.name.lower()
            is_archive = low.endswith((".zip", ".tar", ".tar.gz", ".tgz")) \
                or fp.suffix.lower() in ZIP_CONTAINER_EXTS
            if is_archive and depth < MAX_ARCHIVE_DEPTH:
                try:
                    if fp.stat().st_size <= MAX_NESTED_ARCHIVE_BYTES:
                        _scan_nested_archive(fp, rel, res, file_cats, depth)
                        continue
                except OSError:
                    pass
            kind = classify(fp)
            if kind == "bytecode":
                try:
                    raw = fp.read_bytes()
                except OSError as e:
                    res.files_skipped.append(f"{rel}: {e}")
                    continue
                res.files_scanned += 1
                before = len(res.findings)
                apply_rules(rel, extract_strings(raw), res)
                for f in res.findings[before:]:
                    file_cats.setdefault(rel, set()).add(f.category)
                continue
            if kind in ("binary",):
                res.add(Finding("struct-binary-present", "obfuscation", "info",
                                rel, None, f"binary file ({fp.stat().st_size} bytes)",
                                "Binary content inventoried, not content-scanned"))
                continue
            try:
                text, partial = read_for_scan(fp)
            except OSError as e:
                res.files_skipped.append(f"{rel}: {e}")
                continue
            if "\x00" in text or (text and text.count("\ufffd") / len(text) > 0.01):
                res.add(Finding("struct-binary-present", "obfuscation", "info",
                                rel, None, "binary content (misleading extension)",
                                "Binary content inventoried, not content-scanned"))
                continue
            res.files_scanned += 1
            if partial:
                res.files_partial += 1
            before = len(res.findings)
            for pat, fn_check in STRUCTURAL:
                if re.search(pat, rel):
                    fn_check(rel, text, res)
            apply_rules(rel, text, res)
            # per-line whitespace-hiding pass. Category is obfuscation, NOT
            # autorun: a long line in an SVG/logo/changelog is not something
            # that runs on open, and as an "autorun" leg it completed the
            # autorun-dropper chain in 9 of 12 benign repos (FP baseline 1).
            # Thresholds tightened the same pass: the space-run shape (the
            # real off-screen payload move) fires at any length; a bare long
            # line must exceed 2000 chars; locale data files are exempt.
            if not LOCALE_PATH.search(rel):
                for i, ln in enumerate(text.splitlines(), 1):
                    if len(ln) > 2000 or (len(ln) > 200 and re.search(r" {80,}\S", ln)):
                        res.add(Finding("auto-whitespace-hiding", "obfuscation", "high",
                                        rel, i, ln.strip()[:100],
                                        "Content pushed far off-screen by whitespace or "
                                        "extreme line length (payload hiding)"))
                        break
            if fp.stat().st_size > 1024 * 1024 and kind in TEXTY:
                res.add(Finding("obf-bulk-file", "obfuscation", "medium", rel, None,
                                f"text file of {fp.stat().st_size} bytes",
                                "Oversized text file (truncation-attack / bulk-hiding shape)"))
            for f in res.findings[before:]:
                file_cats.setdefault(rel, set()).add(f.category)
    if _top:
        demote_test_context(res, len(res.findings))
        apply_context_passes(res, rootp)
        run_chains(res, file_cats)
    return file_cats

# ---------------------------------------------------------------- chains ----
DEMOTE = {"critical": "high", "high": "medium", "medium": "low",
          "low": "info", "info": "info"}
TESTY_PATH = re.compile(r"(^|/)(tests?|__tests__|demo|examples?|fixtures?|testdata|samples?)(/|$)")
TESTY_FILENAME = re.compile(r"(_test\.(go|py|rs)$|test_[^/]*\.py$|_test\.py$|\.(test|spec)\.[jt]sx?$|_spec\.rb$|(^|/)Test[^/]*\.java$|Tests?\.cs$)")
CORPUS_PATH = re.compile(r"(^|/)(rules?|signatures?|patterns?|detections?|iocs?|yara)(/|\.|_|$)", re.I)
LOCALE_PATH = re.compile(
    r"(^|/)(locales?|i18n|langs?|translations?)(/|$)"
    r"|(^|/)[a-z]{2}(_[A-Z]{2}|-[A-Z]{2})?\.(ya?ml|json|po)$", re.I)
EXEC_CONFIG_PATH = re.compile(
    r"(^|/)(\.github/workflows/|\.circleci/)|(\.gitlab-ci|azure-pipelines)"
    r"\.ya?ml$|(^|/)package\.json$")
READ_SEMANTICS = re.compile(
    r"(open\s*\(|readFile|createReadStream|fs\.read|expanduser|Path\.home"
    r"|homedir|getenv|shutil|\bcat\s+|copyFile|read_text|read_bytes)")
CRED_REFERENCE_RULES = {"cred-ssh-aws", "cred-browser", "cred-keychain", "cred-files"}
NO_DEMOTE_CATS = {"prompt-injection", "lifecycle-hooks", "autorun", "ci", "persistence"}

def is_test_context(rel: str) -> bool:
    return bool(TESTY_PATH.search(rel) or TESTY_FILENAME.search(rel))

def demote_test_context(res: ScanResult, upto: int):
    """Findings in test/demo/example trees are demoted one severity level
    (they are usually specimens or test vectors) — except auto-run, hook,
    persistence, CI and prompt-injection findings, which stay live because
    opening/installing the tree triggers them regardless of folder name."""
    for f in res.findings[:upto]:
        if is_test_context(f.path):
            # NO_DEMOTE categories stay live in test/demo trees only near the
            # surface: a folderOpen task fires when its folder is opened as a
            # workspace, so depth >= 3 inside a test tree is a specimen, not
            # a live surface.
            deep_specimen = f.path.count("/") >= 3
            if f.category not in NO_DEMOTE_CATS or deep_specimen:
                f.severity = DEMOTE[f.severity]
                f.contextual = True
            f.note += " [context: test/demo]"

def apply_context_passes(res: ScanResult, rootp: Path):
    """Corpus + doc context. A signature corpus (a rules/yara/detections file
    tripping >=5 distinct rules) enumerates bad patterns for a living; its
    findings are listed but never scored. In a NON-skill repo, doc files are
    documentation: their findings demote one level and never score — the
    same text in a skill package (SKILL.md present) is agent-executable and
    keeps full weight. Known tradeoff: corpus status can be imitated by
    naming; the >=5-distinct-rules bar is the mitigation."""
    distinct: dict[str, set] = {}
    for f in res.findings:
        distinct.setdefault(f.path, set()).add(f.rule_id)
    # Skill scope = the subtree(s) containing a SKILL.md. Docs inside a skill
    # subtree are agent-executable (full weight); docs elsewhere in the same
    # repo are documentation even if the repo ships a skill somewhere.
    skill_dirs = set()
    if rootp.is_dir():
        for p in rootp.rglob("*"):
            if p.is_file() and p.name.lower() == "skill.md":
                d = p.parent.relative_to(rootp).as_posix()
                skill_dirs.add("" if d == "." else d)
    def in_skill_scope(rel: str) -> bool:
        return any(d == "" or rel == d or rel.startswith(d + "/") for d in skill_dirs)
    # Credential-reference precision (FP baseline 1): a bare mention of a
    # credential location (.netrc in an HTTP library, id_rsa in docs/tests)
    # is not credential access. Reference-rule findings stay live only when
    # the file shows read semantics; otherwise they list, demoted, unscored.
    text_cache: dict[str, str | None] = {}
    def file_text(rel: str):
        if rel not in text_cache:
            if "!" in rel or not rootp.is_dir():
                text_cache[rel] = None  # archive member: stay conservative
            else:
                try:
                    text_cache[rel] = (rootp / rel).read_text(
                        encoding="utf-8", errors="replace")
                except OSError:
                    text_cache[rel] = None
        return text_cache[rel]
    # Specimen-dense subtree (FP baseline 1, nuclei-templates class): a tree
    # whose PURPOSE is specimens defeats the per-file corpus test when it is
    # one-template-per-file. Gate hard so ordinary repos never qualify:
    # >=250 files with findings repo-wide, a top-level subtree with >=40
    # such files, >=55% of them tripping >=2 distinct rules.
    dense_subtrees = set()
    files_with_findings = {f.path for f in res.findings if not f.chain}
    if len(files_with_findings) >= 250:
        by_sub: dict[str, list] = {}
        for p in files_with_findings:
            parts = p.split("/")
            if len(parts) > 1:
                by_sub.setdefault(parts[0], []).append(p)
        for sub, paths in by_sub.items():
            if len(paths) >= 40:
                multi = sum(1 for p in paths if len(distinct.get(p, ())) >= 2)
                if multi / len(paths) >= 0.55:
                    dense_subtrees.add(sub)
    for f in res.findings:
        _is_build_file = Path(f.path).name in ("Makefile", "makefile",
                                               "GNUmakefile") \
            or f.path.endswith(".mk")
        if f.rule_id == "net-curl-pipe-shell" and not f.chain and _is_build_file:
            # curl|sh in build tooling runs only when a human runs make;
            # it is not an install/open/run surface. Demote, keep live
            # (cobra's lint-tool target measured: true pattern, wrong tier)
            f.severity = DEMOTE[f.severity]
            f.note += " [context: build tooling, explicit invocation only]"
        if f.path.split("/")[0] in dense_subtrees and not f.chain:
            f.contextual = True
            f.note += " [context: specimen-dense subtree]"
        elif f.rule_id == "obf-unicode-hidden" and LOCALE_PATH.search(f.path):
            # zero-width joiners/non-joiners are required orthography in
            # Persian/Arabic/Indic locale data, not smuggling
            f.contextual = True
            f.note += " [context: locale data]"
        elif f.rule_id in CRED_REFERENCE_RULES and not f.chain:
            t = file_text(f.path)
            if t is not None and not READ_SEMANTICS.search(t):
                f.severity = DEMOTE[f.severity]
                f.contextual = True
                f.note += " [context: credential reference, no read semantics]"
        if CORPUS_PATH.search(f.path) and len(distinct.get(f.path, ())) >= 5:
            f.contextual = True
            f.note += " [context: signature corpus]"
        elif classify(Path(f.path)) == "doc" and not f.chain \
                and not in_skill_scope(f.path):
            f.severity = DEMOTE[f.severity]
            f.contextual = True
            f.note += " [context: doc outside skill scope]"
        elif f.category == "prompt-injection" and not f.chain \
                and classify(Path(f.path)) == "code" \
                and not in_skill_scope(f.path):
            # agents read code comments, but in an ordinary repo a PI-shaped
            # comment is usually quoted/test text; inside a skill it is live
            f.severity = DEMOTE[f.severity]
            f.contextual = True
            f.note += " [context: prompt-injection in code outside skill scope]"

def run_chains(res: ScanResult, file_cats: dict):
    by_cat: dict[str, list] = {}
    cat_kinds: dict[str, set] = {}
    for f in res.findings:
        by_cat.setdefault(f.category, []).append(f)
        if f.path != "package-wide":
            cat_kinds.setdefault(f.category, set()).add(classify(Path(f.path)))
    def in_code(cat):
        return bool(cat_kinds.get(cat, set()) & {"code", "config"})
    def chain(rid, sev, cats, note, where="package-wide"):
        res.add(Finding(rid, "risk-chain", sev, where, None,
                        " + ".join(sorted(cats)), note, chain=True))
    # Same-file chains complete only in code/config files: a README that
    # *describes* a stealer is not a stealer (scanner-doc false positive).
    # Test files and signature corpora (rules/yara/detections files, whose
    # job is to enumerate bad patterns) likewise never complete chains —
    # their findings stay listed at full severity for a human to read.
    file_sev: dict[str, dict] = {}
    distinct_rules: dict[str, set] = {}
    for f in res.findings:
        if f.chain or f.contextual:
            continue  # demoted/contextual findings never complete chains
        distinct_rules.setdefault(f.path, set()).add(f.rule_id)
        cur = file_sev.setdefault(f.path, {})
        if SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[cur.get(f.category, "info")]:
            cur[f.category] = f.severity
    for rel, cats in file_cats.items():
        if classify(Path(rel)) not in ("code", "config", "bytecode"):
            continue
        if is_test_context(rel) or CORPUS_PATH.search(rel):
            continue
        if len(distinct_rules.get(rel, ())) >= 8:
            continue  # corpus-density: mega-files enumerate patterns; no chains
        net_sev = file_sev.get(rel, {}).get("network-exfil", "info")
        if SEVERITY_ORDER[net_sev] < SEVERITY_ORDER["medium"]:
            continue  # a bare fetch primitive is not egress
        if "credential-access" in cats and "network-exfil" in cats:
            chain("chain-stealer", "critical",
                  {"credential-access", "network-exfil"},
                  "STEALER chain: one file both reaches for credentials and "
                  "talks to the network", rel)
        if "network-exfil" in cats and "execution" in cats:
            chain("chain-dropper", "critical", {"network-exfil", "execution"},
                  "DROPPER chain: one file both fetches remote content and "
                  "executes code", rel)
    # Package-level chains use LIVE findings only: a leg sourced from a test
    # file, a demo subtree, or a signature corpus does not complete a chain
    # (a scanner's rules.go enumerates credential paths; it does not read
    # them). FP baseline 1 sharpened this: CONTEXTUAL findings (doc-demoted,
    # credential references without read semantics, locale data) never
    # complete chains either — chain-autorun-dropper fired in 9 of 12 benign
    # repos on demoted legs alone. Findings stay listed for a human to read.
    def live(f):
        return not f.contextual and not is_test_context(f.path) \
            and not CORPUS_PATH.search(f.path)
    live_cats = {f.category for f in res.findings if live(f)}
    # Package-level chain legs must sit on an EXECUTABLE surface: a code
    # file, or a config file that runs (CI workflow definitions,
    # package.json). Generic YAML/JSON/TOML data describing a capability
    # is not the capability — detection-template libraries are the
    # measured counterexample (their payloads are data about attacks).
    def on_exec_surface(f):
        return classify(Path(f.path)) == "code" \
            or bool(EXEC_CONFIG_PATH.search(f.path))
    def live_in_code(cat):
        return any(f.category == cat and live(f) and on_exec_surface(f)
                   for f in res.findings)
    cats_all = live_cats
    # Hook-dropper completes on a real network capability in code, or on any
    # network primitive inside the hook's own file (a hook that fetches its
    # "runtime" is the Mini-Shai-Hulud shape).
    net_in_code_strong = any(
        f.category == "network-exfil" and live(f)
        and classify(Path(f.path)) in ("code", "config")
        and SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER["medium"]
        for f in res.findings)
    hook_files = {f.path for f in res.findings if f.category == "lifecycle-hooks"}
    net_in_hook_file = any(f.category == "network-exfil" and f.path in hook_files
                           for f in res.findings)
    if "lifecycle-hooks" in cats_all and (net_in_code_strong or net_in_hook_file):
        chain("chain-hook-dropper", "critical", {"lifecycle-hooks", "network-exfil"},
              "HOOK DROPPER chain: an install-time hook plus network capability "
              "in the same package")
    if "autorun" in cats_all and (live_in_code("network-exfil") or live_in_code("execution")):
        chain("chain-autorun-dropper", "critical", {"autorun", "network-exfil/execution"},
              "AUTO-RUN DROPPER chain: something runs on open/install and the "
              "package can fetch or execute")
    pi_crit = any(f.category == "prompt-injection" and f.severity == "critical"
                  and live(f) for f in res.findings)
    if pi_crit and live_in_code("credential-access"):
        chain("chain-prompt-exfil", "critical", {"prompt-injection", "credential-access"},
              "PROMPT-INJECTION EXFIL chain: agent-directed theft instructions "
              "plus credential access in the same package")
    if "persistence" in cats_all and any(
            live_in_code(c) for c in ("network-exfil", "execution", "credential-access")):
        chain("chain-persistence-implant", "high", {"persistence", "..."},
              "PERSISTENCE IMPLANT chain: persistence mechanism plus another "
              "malicious capability")
    if "ci" in cats_all and live_in_code("credential-access"):
        chain("chain-ci-theft", "critical", {"ci", "credential-access"},
              "CI TOKEN THEFT chain: dangerous workflow surface plus credential access")
    # Cross-file chains (downgraded one level, GuardDog-style): the two
    # halves of a stealer/dropper split across files so no single file
    # completes the same-file chain.
    fired = {f.rule_id for f in res.findings if f.chain}
    def live_code_cat(cat, min_sev="low"):
        return {f.path for f in res.findings
                if f.category == cat and live(f)
                and on_exec_surface(f)
                and SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[min_sev]}
    # Cross-file stealer correlation requires a credential-STORE leg
    # (SSH/AWS keys, browser stores, OS keychains, or selective secret-key
    # harvesting). Generic .env / env references are ambient in all
    # software — with them as legs, this chain completed in requests,
    # django, pytest, prettier and vue alike (FP baseline 1, round 2).
    XFILE_CRED_RULES = {"cred-ssh-aws", "cred-browser", "cred-keychain",
                        "cred-keyword-filter"}
    def xfile_cred_files():
        return {f.path for f in res.findings
                if f.rule_id in XFILE_CRED_RULES and live(f)
                and on_exec_surface(f)}
    if "chain-stealer" not in fired:
        cred_files = xfile_cred_files()
        net_files = live_code_cat("network-exfil", "medium")
        if cred_files and net_files and not (len(cred_files) == 1 and cred_files == net_files):
            chain("chain-stealer-xfile", "high",
                  {"credential-access", "network-exfil"},
                  "STEALER chain (cross-file): credential access and network "
                  "egress live in different files of the same package")
        else:
            # weakest net leg (a bare fetch primitive) still completes the
            # shape when the package also has real execution: credential
            # store + egress + exec, split across files, is a stealer
            net_lo = live_code_cat("network-exfil")
            exec_md = live_code_cat("execution", "medium")
            if cred_files and net_lo and exec_md:
                chain("chain-stealer-xfile", "critical",
                      {"credential-access", "network-exfil", "execution"},
                      "STEALER chain (cross-file): credential access, network "
                      "egress, and execution split across files of one package")
            else:
                # private-key material is the sharpest leg: a package that
                # reads SSH private keys / AWS credentials in one file and
                # has any network egress in another is a stealer even with
                # no execution anywhere (pure read-and-send theft)
                key_files = {f.path for f in res.findings
                             if f.rule_id == "cred-ssh-aws" and live(f)
                             and on_exec_surface(f)}
                if key_files and net_lo and not (len(key_files) == 1
                                                 and key_files == net_lo):
                    chain("chain-stealer-xfile", "critical",
                          {"credential-access", "network-exfil"},
                          "STEALER chain (cross-file): private-key/credential "
                          "reads in one file, network egress in another")
    if "chain-dropper" not in fired:
        net_files = live_code_cat("network-exfil", "medium")
        exec_files = live_code_cat("execution")
        if net_files and exec_files and not (len(net_files) == 1 and net_files == exec_files):
            chain("chain-dropper-xfile", "high",
                  {"network-exfil", "execution"},
                  "DROPPER chain (cross-file): network fetch and code "
                  "execution live in different files of the same package")

# --------------------------------------------------------------- scoring ----
def score_and_verdict(res: ScanResult):
    live = [f for f in res.findings if not f.contextual]
    # Per-rule contribution cap: at most 5 findings of any one rule score.
    # Without it, a large benign repo saturates every category cap on sheer
    # repetition (faker-ruby: 206 files with the same low finding) while a
    # real malicious package — small, few files — is unaffected.
    by_rule: dict[str, list] = {}
    for f in live:
        by_rule.setdefault(f.rule_id, []).append(f)
    # Diminishing per-rule scoring: the FIRST finding of a rule carries the
    # signal at full weight; up to 4 repeats add +1 each; the rest list for
    # free. Capability count is not risk — a framework's 15th reflective
    # call is not 15x a stealer's one. Small malicious packages (1-3 files
    # per rule) are unaffected.
    per_cat: dict[str, int] = {}
    for rid, fs in by_rule.items():
        if rid.startswith("chain-"):
            for f in fs:
                per_cat[f.category] = per_cat.get(f.category, 0) \
                    + SEVERITY_WEIGHT[f.severity]
            continue
        fs.sort(key=lambda f: SEVERITY_ORDER[f.severity], reverse=True)
        for i, f in enumerate(fs[:5]):
            w = SEVERITY_WEIGHT[f.severity] if i == 0 else 1
            per_cat[f.category] = per_cat.get(f.category, 0) + w
    score = sum(min(v, CATEGORY_CAP) if k != "risk-chain" else v
                for k, v in per_cat.items())
    score = min(score, 100)
    # A lone critical forces BLOCK only on an executable surface (code,
    # bytecode, runnable config) or as a completed chain. A critical
    # string inside data — an index file naming a metadata-endpoint
    # template — is listed and scored, but data does not execute.
    def crit_surface(f):
        # Live prompt-injection criticals count on any surface: outside a
        # skill scope the context passes already demote PI findings to
        # contextual, so a LIVE PI critical is in agent-executable scope
        # by construction (the tags-block skill fixture is the case).
        return f.chain or f.category == "prompt-injection" \
            or classify(Path(f.path)) in ("code", "bytecode") \
            or bool(EXEC_CONFIG_PATH.search(f.path))
    has_critical = any(f.severity == "critical" and crit_surface(f)
                       for f in live)
    has_high = any(f.severity == "high" for f in live)
    if has_critical or score >= 70:
        verdict = "BLOCK"
    elif has_high or score >= 25:
        verdict = "REVIEW"
    else:
        verdict = "CLEAN"
    # Score-only BLOCKs do not survive bulk. Past ~500 scanned files the
    # accumulated weak signals describe a capability-rich codebase, not a
    # malware shape: vue, prettier, pytest and django all saturate the
    # score with zero chains and zero executable-surface criticals, while
    # every real malicious package in the fixture corpus is small AND
    # completes a chain or carries a surface critical — both of which
    # bypass this gate. Padding a stealer with junk files buys it only
    # REVIEW, where a human still reads the (chain-free) finding list.
    if verdict == "BLOCK" and not has_critical \
            and not any(f.chain for f in live) and res.files_scanned > 500:
        verdict = "REVIEW"
    texty_total = res.files_scanned + len(res.files_skipped)
    coverage = (res.files_scanned - res.files_partial) / texty_total if texty_total else 1.0
    if verdict != "BLOCK" and (coverage < 0.9 or res.files_partial > 0):
        verdict = "INCONCLUSIVE"
    return score, verdict, coverage

# ------------------------------------------------------------ acquisition ----
GITHUB_RE = re.compile(r"(?:https?://)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/(?:tree/)?([\w./-]+))?$")

MAX_ARCHIVE_MEMBERS = 20000
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_EXTRACT_TOTAL = 512 * 1024 * 1024

def _contained(dest: Path, target: Path) -> bool:
    dest_r = dest.resolve()
    return target == dest_r or dest_r in target.parents

def safe_extract_zip(zf: zipfile.ZipFile, dest: Path):
    infos = zf.infolist()
    if len(infos) > MAX_ARCHIVE_MEMBERS:
        raise ValueError("archive has too many members")
    total = 0
    for info in infos:
        if info.file_size > MAX_MEMBER_BYTES:
            raise ValueError(f"archive member too large: {info.filename}")
        if info.file_size > 10 * 1024 * 1024 and info.compress_size and \
                info.file_size / max(info.compress_size, 1) > 100:
            raise ValueError(f"archive member has bomb-like ratio: {info.filename}")
        total += info.file_size
        if total > MAX_EXTRACT_TOTAL:
            raise ValueError("archive expands beyond the total size cap")
        target = (dest / info.filename).resolve()
        if not _contained(dest, target):
            raise ValueError(f"archive path escape: {info.filename}")
    zf.extractall(dest)

def safe_extract_tar(tf: tarfile.TarFile, dest: Path):
    members = tf.getmembers()
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise ValueError("archive has too many members")
    total = 0
    for member in members:
        if member.size > MAX_MEMBER_BYTES:
            raise ValueError(f"archive member too large: {member.name}")
        total += max(member.size, 0)
        if total > MAX_EXTRACT_TOTAL:
            raise ValueError("archive expands beyond the total size cap")
        target = (dest / member.name).resolve()
        if not _contained(dest, target):
            raise ValueError(f"archive path escape: {member.name}")
        if member.issym() or member.islnk():
            link = (target.parent / member.linkname).resolve()
            if not _contained(dest, link):
                raise ValueError(f"archive link escape: {member.name}")
        if member.isdev() or member.isfifo():
            raise ValueError(f"archive contains a device/fifo member: {member.name}")
    try:
        tf.extractall(dest, filter="data")
    except TypeError:
        tf.extractall(dest)

def acquire(target: str, workdir: Path, res: ScanResult) -> Path:
    """Return the directory (or file) to scan. Quarantine-first: remote and
    archive content lands in workdir and is only ever read."""
    p = Path(target)
    if p.is_dir():
        return p
    if p.is_file() and p.suffix not in (".zip", ".gz", ".tgz", ".tar"):
        return p
    if p.is_file():
        dest = workdir / "extracted"
        dest.mkdir(parents=True, exist_ok=True)
        if zipfile.is_zipfile(p):
            with zipfile.ZipFile(p) as zf:
                safe_extract_zip(zf, dest)
        else:
            with tarfile.open(p) as tf:
                safe_extract_tar(tf, dest)
        return dest
    m = GITHUB_RE.match(target.strip())
    if m:
        owner, repo, ref = m.group(1), m.group(2), m.group(3) or "HEAD"
        headers = {"User-Agent": f"repogate/{VERSION}", "Accept": "application/vnd.github+json"}
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        try:
            meta_req = urllib.request.Request(
                f"https://api.github.com/repos/{owner}/{repo}", headers=headers)
            with urllib.request.urlopen(meta_req, timeout=30) as r:
                meta = json.load(r)
            res.trust = {"source": f"github.com/{owner}/{repo}",
                         "created_at": meta.get("created_at"),
                         "stars": meta.get("stargazers_count"),
                         "archived": meta.get("archived"),
                         "license": (meta.get("license") or {}).get("spdx_id"),
                         "note": "trust signals are context only; they never clear findings"}
        except Exception as e:  # metadata is best-effort context
            res.trust = {"source": f"github.com/{owner}/{repo}", "meta_error": str(e)}
        tar_req = urllib.request.Request(
            f"https://api.github.com/repos/{owner}/{repo}/tarball/{ref}", headers=headers)
        dest = workdir / "extracted"
        dest.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(tar_req, timeout=120) as r:
            blob = r.read()
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
            safe_extract_tar(tf, dest)
        subs = [d for d in dest.iterdir() if d.is_dir()]
        return subs[0] if len(subs) == 1 else dest
    raise ValueError(f"cannot acquire target: {target}")

# --------------------------------------------------------------- reporting ----
def render_text(res: ScanResult, score: int, verdict: str, coverage: float) -> str:
    lines = [f"RepoGate {VERSION} — {res.target}",
             f"VERDICT: {verdict}   score: {score}/100   coverage: {coverage:.0%} "
             f"({res.files_scanned} files scanned, {res.files_partial} partial, "
             f"{len(res.files_skipped)} skipped)"]
    if res.trust:
        lines.append(f"Trust context: {json.dumps(res.trust)}")
    if res.files_skipped:
        lines.append("Skipped: " + "; ".join(res.files_skipped[:10]))
    chains = [f for f in res.findings if f.chain]
    rest = [f for f in res.findings if not f.chain]
    if chains:
        lines.append("\nRISK CHAINS:")
        for f in chains:
            lines.append(f"  [{f.severity.upper()}] {f.rule_id} @ {f.path} — {f.note}")
    if rest:
        lines.append("\nFINDINGS:")
        for f in sorted(rest, key=lambda x: -SEVERITY_ORDER[x.severity]):
            loc = f"{f.path}:{f.line}" if f.line else f.path
            lines.append(f"  [{f.severity.upper():8}] {f.rule_id} @ {loc}\n"
                         f"             {f.evidence}\n             {f.note}")
    if not res.findings:
        lines.append("\nNo findings.")
    lines.append("\nA CLEAN verdict means nothing was found by these rules — "
                 "it is not a guarantee of safety.")
    return "\n".join(lines)

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="RepoGate — read-only pre-clone/pre-run repo & skill scanner")
    ap.add_argument("target", help="local dir, archive, file, or github.com/owner/repo URL")
    ap.add_argument("--json", metavar="PATH", help="also write a JSON report to PATH")
    ap.add_argument("--version", action="version", version=f"repogate {VERSION}")
    args = ap.parse_args(argv)
    res = ScanResult(target=args.target)
    workdir = Path(tempfile.mkdtemp(prefix="repogate-quarantine-"))
    try:
        root = acquire(args.target, workdir, res)
        if root.is_file():
            res.files_total = 1
            res.files_scanned = 1
            text, _ = read_for_scan(root)
            for pat, fn_check in STRUCTURAL:
                if re.search(pat, root.name):
                    fn_check(root.name, text, res)
            apply_rules(root.name, text, res)
            run_chains(res, {root.name: {f.category for f in res.findings}})
        else:
            scan_tree(str(root), res)
    except Exception as e:
        print(f"repogate: error: {e}", file=sys.stderr)
        return 3
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    score, verdict, coverage = score_and_verdict(res)
    try:
        print(render_text(res, score, verdict, coverage))
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except Exception:
            pass
    if args.json:
        payload = {"tool": "repogate", "version": VERSION, "target": res.target,
                   "verdict": verdict, "score": score, "coverage": coverage,
                   "trust": res.trust,
                   "findings": [vars(f) for f in res.findings]}
        Path(args.json).write_text(json.dumps(payload, indent=2))
    return {"CLEAN": 0, "REVIEW": 1, "INCONCLUSIVE": 1, "BLOCK": 2}[verdict]

if __name__ == "__main__":
    sys.exit(main())
