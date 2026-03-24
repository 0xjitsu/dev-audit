# dev-audit

A Claude Code plugin that performs a comprehensive macOS developer workstation audit — security hardening, shell optimization, modern CLI tooling, performance tuning, and cleanup.

Run `/dev-audit` and get a full report with one-command fixes.

## What It Checks

| Domain | What | Examples |
|--------|------|---------|
| **Security** | Exposed secrets, SSH hygiene, macOS security, git safety | Tokens in shell history, world-readable .env files, missing .gitignore |
| **Shell** | Startup time, PATH issues, completions | Duplicate PATH entries, missing compinit, slow startup |
| **Tooling** | Modern CLI tools | fzf, ripgrep, bat, eza, delta, direnv, mise, zoxide |
| **Git** | Performance config, signing, diff viewer | fsmonitor, untrackedCache, commit signing, delta |
| **Performance** | Memory pressure, Spotlight, background processes | Swap usage, node_modules indexing, Ollama/Docker |
| **macOS** | Developer-optimized defaults | Key repeat, Dock speed, .DS_Store prevention |
| **Hygiene** | Package managers, caches, MCP/plugin health | npm cache, Homebrew cleanup, failed MCP connections |

## Install

```bash
claude plugin add --from /path/to/dev-audit
```

Or from GitHub:

```bash
claude plugin add --from https://github.com/0xjitsu/dev-audit
```

## Usage

```
/dev-audit
```

The skill will:
1. Scan all 7 domains in parallel
2. Report findings by severity (CRITICAL > HIGH > MEDIUM > LOW)
3. Show what's already optimized
4. Ask which fixes to apply
5. Generate a single script for approved fixes

## Philosophy

- **Non-destructive by default** — reports first, fixes on approval
- **Copy-pasteable fixes** — every finding includes the exact command
- **Severity-driven** — prioritized so you fix what matters most first
- **macOS-native** — uses Keychain, launchctl, defaults, Spotlight APIs
- **No dependencies** — works with just a shell and Claude Code

## What Gets Fixed (Examples)

### Security
- Scrubs leaked tokens from shell history
- Moves plaintext secrets to macOS Keychain
- Creates global .gitignore to block .env/.pem/.key commits
- Hardens SSH config (UseKeychain, HashKnownHosts)
- Enables git commit signing with SSH keys

### Performance
- Unloads memory-heavy background processes (Ollama, Docker)
- Excludes node_modules from Spotlight indexing
- Applies git fsmonitor + untrackedCache (50-80% faster git status)
- Cleans npm/Homebrew/browser caches

### Tooling
- Installs modern CLI replacements: `fzf`, `ripgrep`, `bat`, `eza`, `fd`, `delta`, `zoxide`, `direnv`, `mise`
- Configures shell integration (completions, aliases, git delta)
- Deduplicates PATH entries

### macOS
- Faster key repeat and initial delay
- Instant Dock auto-hide
- Show all file extensions
- Prevent .DS_Store on network/USB volumes

## Requirements

- macOS (tested on Sequoia/Tahoe, Apple Silicon)
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code/overview) CLI
- Homebrew (for tool installation)

## License

MIT
