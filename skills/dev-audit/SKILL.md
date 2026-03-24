---
description: "Full-stack macOS developer workstation audit — security, shell, tooling, performance, and cleanup. Scored report with auto-fix. Run /dev-audit to scan."
user_invocable: true
---

# /dev-audit — macOS Developer Workstation Audit

You are a senior platform engineer and security architect. Perform a comprehensive audit of this macOS developer workstation across 7 domains. Be thorough but non-destructive — **report everything first, then offer to fix**.

**Standalone script also available:** If the user prefers a non-interactive audit, they can run `bash bin/dev-audit.sh` directly. The script supports `--fix`, `--json`, `--self-heal`, and `--uninstall` flags.

## Audit Protocol

Run each domain's checks in parallel where possible. For each finding, report:
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **What**: The specific issue
- **Why**: Impact on security, speed, or capability
- **Fix**: The exact command (copy-pasteable)

Group results into: "Immediate Action Required" (CRITICAL/HIGH) and "Recommended Improvements" (MEDIUM/LOW).

After presenting the full report, ask: "Which fixes should I apply? (all / critical-only / pick specific numbers / none)"

---

## Domain 1: Security Hardening

### 1.1 Exposed Secrets
```bash
# Shell history secrets
grep -iE '(sk_live|sk_test|ghp_|gho_|xoxb-|xoxp-|AKIA|password|secret.*=|token.*=|api.key.*=|bearer)' ~/.zsh_history 2>/dev/null | wc -l

# Plaintext tokens in dotfiles
grep -rlE '(sk_live|sk_test|ghp_|gho_|xoxb-|AKIA)' ~/.zshrc ~/.bashrc ~/.profile ~/.bash_profile 2>/dev/null

# .env files with loose permissions
find ~ -maxdepth 4 -name '.env*' -not -path '*/node_modules/*' -not -path '*/.git/*' -exec stat -f "%Lp %N" {} \; 2>/dev/null | grep -v '^600'

# Sensitive files in Downloads (common leak vector)
find ~/Downloads -maxdepth 2 -name '.env*' -o -name '*.pem' -o -name '*.key' -o -name 'credentials*' -o -name 'service-account*' 2>/dev/null
```

**Fixes:**
- Scrub secrets from history: `sed -i '' '/sk_live_/d; /ghp_/d; /xoxb-/d' ~/.zsh_history`
- Fix permissions: `find ~ -maxdepth 4 -name '.env*' -not -path '*/node_modules/*' -exec chmod 600 {} \;`
- Move tokens to macOS Keychain: `security add-generic-password -a $USER -s TOKEN_NAME -w "token_value"`
- Reference in .zshrc: `export TOKEN="$(security find-generic-password -a $USER -s TOKEN_NAME -w 2>/dev/null)"`

### 1.2 SSH Key Hygiene
```bash
# List keys with algorithms
for f in ~/.ssh/*.pub; do ssh-keygen -l -f "$f" 2>/dev/null; done

# Check permissions
stat -f "%Lp %N" ~/.ssh/* 2>/dev/null

# Check SSH config
cat ~/.ssh/config 2>/dev/null || echo "NO SSH CONFIG (should be hardened)"
```

**Fixes:**
- Create hardened SSH config:
```
Host *
  AddKeysToAgent yes
  UseKeychain yes
  IdentityFile ~/.ssh/id_ed25519
  HashKnownHosts yes
  ServerAliveInterval 60
  ServerAliveCountMax 3
```
- Fix permissions: `chmod 700 ~/.ssh && chmod 600 ~/.ssh/id_* && chmod 644 ~/.ssh/*.pub`
- Generate modern key if missing: `ssh-keygen -t ed25519 -C "user@machine"`

### 1.3 macOS System Security
```bash
fdesetup status                    # FileVault (disk encryption)
csrutil status                     # SIP (System Integrity Protection)
spctl --status                     # Gatekeeper
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null  # Firewall
```

### 1.4 Git Security
```bash
# Global .gitignore (prevents accidental secret commits)
git config --global core.excludesFile || echo "NO GLOBAL GITIGNORE (HIGH risk)"

# Commit signing
git config --global commit.gpgsign || echo "COMMITS NOT SIGNED"

# Token scopes (if gh CLI available)
gh auth status 2>&1
```

**Fixes:**
- Create global .gitignore:
```bash
cat > ~/.gitignore_global << 'EOF'
.env
.env.*
*.pem
*.key
*.p12
credentials.json
service-account*.json
.npmrc
.netrc
.DS_Store
node_modules/
EOF
git config --global core.excludesFile ~/.gitignore_global
```
- Enable commit signing: `git config --global commit.gpgsign true && git config --global gpg.format ssh && git config --global user.signingkey ~/.ssh/id_ed25519.pub`

---

## Domain 2: Shell & Terminal Optimization

### 2.1 Startup Time
```bash
# Profile shell startup (run 3x for average)
for i in 1 2 3; do time zsh -i -c exit 2>&1; done
```

**Target:** < 100ms warm start. If > 200ms, check for heavy plugin managers or slow eval statements.

### 2.2 PATH Analysis
```bash
# Check for duplicates
echo $PATH | tr ':' '\n' | sort | uniq -d

# Check for nonexistent directories
echo $PATH | tr ':' '\n' | while read d; do [ ! -d "$d" ] && echo "MISSING: $d"; done
```

### 2.3 Completions
```bash
# Check if compinit is loaded
grep -q 'compinit' ~/.zshrc && echo "compinit: YES" || echo "compinit: MISSING (add: autoload -Uz compinit && compinit)"
```

---

## Domain 3: Modern CLI Tooling

Check if state-of-the-art tools are installed. These replace slow/limited defaults:

```bash
declare -A tools=(
  [fzf]="Fuzzy finder — Ctrl+R history search, Ctrl+T file finder"
  [rg]="ripgrep — 10-100x faster than grep for code search"
  [fd]="Modern find — faster, friendlier syntax"
  [bat]="Modern cat — syntax highlighting, git integration"
  [eza]="Modern ls — icons, git status, tree view"
  [delta]="Git diff viewer — syntax highlighting, side-by-side"
  [zoxide]="Smart cd — learns your directories, z shortcut"
  [direnv]="Per-project env vars — auto-load .envrc on cd"
  [mise]="Runtime version manager — Node/Python/Go per project"
  [jq]="JSON processor — essential for API work"
  [lazygit]="Git TUI — visual staging, branching, rebasing"
)

for tool in "${!tools[@]}"; do
  which "$tool" &>/dev/null && echo "OK $tool" || echo "MISSING $tool — ${tools[$tool]}"
done
```

**One-command install for all missing tools:**
```bash
brew install fzf ripgrep fd bat eza git-delta zoxide direnv mise jq lazygit
```

**Shell integration (add to .zshrc):**
```bash
eval "$(fzf --zsh)"
eval "$(zoxide init zsh)"
eval "$(direnv hook zsh)"
eval "$(mise activate zsh)"

alias ls='eza --icons --group-directories-first'
alias ll='eza -la --icons --group-directories-first --git'
alias cat='bat --paging=never'
```

**Git delta config:**
```bash
git config --global core.pager delta
git config --global delta.navigate true
git config --global delta.side-by-side true
git config --global delta.line-numbers true
```

---

## Domain 4: Git Performance

```bash
# Check current config
git config --global core.fsmonitor       || echo "MISSING: fsmonitor (50-80% faster git status)"
git config --global core.untrackedCache  || echo "MISSING: untrackedCache"
git config --global fetch.prune          || echo "MISSING: fetch.prune"
git config --global diff.algorithm       || echo "MISSING: diff.algorithm (use histogram)"
```

**Fixes:**
```bash
git config --global core.fsmonitor true
git config --global core.untrackedCache true
git config --global fetch.prune true
git config --global pull.rebase true
git config --global diff.algorithm histogram
```

---

## Domain 5: Memory & Performance

### 5.1 Swap Pressure
```bash
sysctl vm.swapusage
# If swap used > 50% of total, investigate top memory consumers
```

### 5.2 Top Memory Consumers
```bash
ps aux --sort=-%mem | head -11
```

### 5.3 Heavy Background Processes
```bash
# Check for Ollama (often holds 4-18 GB RAM when idle)
pgrep -fl ollama && echo "WARNING: Ollama running — unload if not using local LLMs"

# Check for Docker Desktop
pgrep -fl docker && echo "Docker Desktop running — consider Colima for lower memory"
```

### 5.4 Spotlight Indexing node_modules
```bash
# Count unexcluded node_modules
find ~ -maxdepth 4 -name 'node_modules' -type d -not -path '*/node_modules/*/node_modules' 2>/dev/null | while read d; do
  [ ! -f "$d/.metadata_never_index" ] && echo "UNINDEXED: $d"
done
```

**Fix:** `find ~ -maxdepth 4 -name 'node_modules' -type d -not -path '*/node_modules/*/node_modules' -exec touch {}/.metadata_never_index \; 2>/dev/null`

---

## Domain 6: macOS Defaults

Check and recommend developer-optimized macOS settings:

```bash
# Key repeat speed (developer productivity)
defaults read NSGlobalDomain KeyRepeat 2>/dev/null || echo "DEFAULT (slow)"
defaults read NSGlobalDomain InitialKeyRepeat 2>/dev/null || echo "DEFAULT (slow)"

# Dock performance
defaults read com.apple.dock autohide-delay 2>/dev/null || echo "DEFAULT (has delay)"

# Finder
defaults read NSGlobalDomain AppleShowAllExtensions 2>/dev/null || echo "HIDDEN extensions"

# Prevent .DS_Store on network/USB
defaults read com.apple.desktopservices DSDontWriteNetworkStores 2>/dev/null || echo "WRITES .DS_Store on network"
```

**Fixes:**
```bash
defaults write NSGlobalDomain KeyRepeat -int 2
defaults write NSGlobalDomain InitialKeyRepeat -int 15
defaults write com.apple.dock autohide-delay -float 0
defaults write com.apple.dock autohide-time-modifier -float 0.3
defaults write com.apple.dock launchanim -bool false
defaults write NSGlobalDomain AppleShowAllExtensions -bool true
defaults write com.apple.desktopservices DSDontWriteNetworkStores -bool true
defaults write com.apple.desktopservices DSDontWriteUSBStores -bool true
killall Dock
```

---

## Domain 7: Package & Cache Hygiene

### 7.1 Homebrew
```bash
brew doctor 2>&1 | head -5
brew outdated 2>&1
brew autoremove --dry-run 2>&1
du -sh $(brew --cache) 2>/dev/null
```

### 7.2 Caches
```bash
du -sh ~/.npm/_cacache ~/Library/Caches/Arc ~/Library/Caches/ms-playwright 2>/dev/null
```

**Fixes:**
```bash
npm cache clean --force
brew cleanup --prune=all
brew autoremove
```

### 7.3 Claude Code Plugins (if applicable)
```bash
# Check for failed MCP connections
claude mcp list 2>&1 | grep -E 'Failed|error'

# Check for disabled but installed plugins
cat ~/.claude/settings.json 2>/dev/null | python3 -c "import json,sys; d=json.load(sys.stdin); [print(f'DISABLED: {k}') for k,v in d.get('enabledPlugins',{}).items() if not v]"
```

---

## Output Format

Present results as a structured report:

```
## Dev Audit Report — [hostname] — [date]

### System Info
- Machine: [model]
- macOS: [version]
- RAM: [amount]
- Disk: [used/total]

### Immediate Action Required (CRITICAL/HIGH)
| # | Severity | Domain | Issue | Fix |
|---|----------|--------|-------|-----|
| 1 | CRITICAL | Security | ... | `command` |

### Recommended Improvements (MEDIUM/LOW)
| # | Severity | Domain | Issue | Fix |
|---|----------|--------|-------|-----|
| 1 | MEDIUM | Tooling | ... | `command` |

### Already Optimized
- [list of things that passed checks]

### Quick Fix Script
[Single script that applies all approved fixes]
```

Then ask: **"Which fixes should I apply? (all / critical-only / pick numbers / none)"**
