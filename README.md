# dev-audit

[![npm](https://img.shields.io/npm/v/@0xjitsu/dev-audit?color=blue)](https://www.npmjs.com/package/@0xjitsu/dev-audit)
[![license](https://img.shields.io/github/license/0xjitsu/dev-audit)](./LICENSE)
[![platform](https://img.shields.io/badge/platform-macOS-black)](https://github.com/0xjitsu/dev-audit)

Scan your macOS dev machine in seconds. Get a scored report across 7 domains. Auto-fix issues with one flag.

```
╔══════════════════════════════════════════════════╗
║  dev-audit v2.0.0 — Workstation Audit            ║
╚══════════════════════════════════════════════════╝

  ■■■■■■■■□□ Security .......................... B (78/100)
  ■■■■■■■■■■ Shell ............................. A (95/100)
  ■■■■■■□□□□ Tooling ........................... C (62/100)
  ■■■■■■■■■□ Git ............................... A (92/100)
  ■■■■■□□□□□ Performance ....................... D (48/100)
  ■■■■■■■■□□ macOS ............................. B (82/100)
  ■■■■■■■□□□ Hygiene ........................... B (75/100)

  Overall Grade: B (76/100)

─── CRITICAL (1) ───────────────────────────────────
  1. [Security] Stripe live key in shell history
     Fix: sed -i '' '/sk_live_/d' ~/.zsh_history
```

## Quick Start

Three ways to run — pick your favorite:

```bash
# 1. npx (zero install, one-shot)
npx @0xjitsu/dev-audit

# 2. Claude Code plugin
claude plugin add --from https://github.com/0xjitsu/dev-audit
# then: /dev-audit

# 3. Direct (clone and run)
git clone https://github.com/0xjitsu/dev-audit.git
bash dev-audit/bin/dev-audit.sh
```

## What It Checks

| Domain | Checks | Examples |
|--------|--------|---------|
| **Security** | Secrets in history, .env permissions, SSH, FileVault, SIP, Gatekeeper, .gitignore, commit signing | `sk_live_` in `~/.zsh_history`, world-readable `.env` files |
| **Shell** | Startup time, PATH duplicates, completions, plaintext tokens | >500ms startup, missing `compinit` |
| **Tooling** | 10 modern CLI tools | fzf, ripgrep, bat, eza, fd, delta, zoxide, direnv, mise, jq |
| **Git** | Performance config, signing, pager | fsmonitor, untrackedCache, histogram diff |
| **Performance** | Swap pressure, Ollama, Spotlight indexing | 89% swap, node_modules indexed |
| **macOS** | Developer defaults | Key repeat, Dock speed, .DS_Store |
| **Hygiene** | Caches, outdated packages, Xcode CLT | 5 GB npm cache, outdated CLT |

## Modes

```bash
dev-audit                # Scan and report (default)
dev-audit --fix          # Scan and auto-fix safe issues
dev-audit --json         # Machine-parseable JSON output
dev-audit --self-heal    # Install weekly auto-audit (Sundays 4 AM)
dev-audit --uninstall    # Remove the scheduled audit
dev-audit --no-color     # Plain text (for pipes/logs)
```

### `--fix` (Safe Auto-Fix)

Only applies non-destructive fixes:
- `.env` file permissions → 600
- Spotlight exclusion for `node_modules`
- Git performance config (fsmonitor, untrackedCache, histogram)
- Global `.gitignore` (blocks `.env`, `.pem`, `.key`)
- macOS defaults (show extensions, prevent `.DS_Store`)

Does **NOT** auto-fix: secret scrubbing, tool installation, SSH config, commit signing — these are reported for manual action.

### `--json` (CI/Automation)

```bash
dev-audit --json | jq .grade    # "B"
dev-audit --json | jq .score    # 76
```

```json
{
  "version": "2.0.0",
  "timestamp": "2026-03-24T10:00:00Z",
  "hostname": "macbook",
  "grade": "B",
  "score": 76,
  "domains": { "Security": { "score": 78, "grade": "B" }, ... },
  "findings": [ ... ],
  "finding_count": 12,
  "has_critical": false
}
```

Exit codes: `0` = all clear, `1` = has findings, `2` = has critical findings.

### `--self-heal` (Scheduled Audit)

Installs a macOS LaunchAgent that runs `dev-audit --fix --json` every Sunday at 4 AM.

- Results logged to `~/Reports/dev-audit/audit.log`
- Automatically fixes drift (new node_modules, loose .env permissions)
- Remove anytime: `dev-audit --uninstall`

## Scoring

Each domain gets 0-100. Deductions per finding:

| Severity | Deduction | Examples |
|----------|-----------|---------|
| CRITICAL | -25 to -30 | Exposed secrets, FileVault off |
| HIGH | -15 to -20 | Missing .gitignore, plaintext tokens, swap >80% |
| MEDIUM | -10 to -15 | Slow startup, missing tools, no signing |
| LOW | -5 | PATH dupes, missing defaults |

Overall grade = average of all domains: **A** (90+), **B** (75+), **C** (60+), **D** (40+), **F** (<40).

## Universal Install

| Method | Command | Audience |
|--------|---------|----------|
| **npx** | `npx @0xjitsu/dev-audit` | Any developer with Node.js |
| **Claude Code** | `claude plugin add --from https://github.com/0xjitsu/dev-audit` | Claude Code users |
| **Direct** | `bash <(curl -sL https://raw.githubusercontent.com/0xjitsu/dev-audit/main/bin/dev-audit.sh)` | Anyone with a terminal |
| **Clone** | `git clone` + `bash bin/dev-audit.sh` | Contributors |

## Requirements

- macOS (Apple Silicon or Intel)
- Homebrew (optional, for tool installation fixes)
- Node.js (optional, only for `npx` method)

## Philosophy

- **Non-destructive by default** — always reports first
- **`--fix` is safe** — only applies reversible, non-controversial changes
- **Scored, not binary** — nuanced grading, not just pass/fail
- **Zero dependencies** — the shell script needs nothing but bash
- **Self-healing** — schedule it and forget it

## License

MIT
