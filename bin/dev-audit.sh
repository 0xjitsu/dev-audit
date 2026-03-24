#!/usr/bin/env bash
# dev-audit — macOS Developer Workstation Audit
# https://github.com/0xjitsu/dev-audit
set -uo pipefail

VERSION="2.0.0"
MODE="report"  # report | fix | json | self-heal | uninstall
FINDINGS=()
FIXES=()
SCORES=()
HAS_CRITICAL=0

# ── Colors ──────────────────────────────────────────────────────────
RED='\033[0;31m'    YELLOW='\033[0;33m'  BLUE='\033[0;34m'
GREEN='\033[0;32m'  GRAY='\033[0;90m'    BOLD='\033[1m'
DIM='\033[2m'       RESET='\033[0m'      CYAN='\033[0;36m'

# ── Helpers ─────────────────────────────────────────────────────────
no_color() { RED=''; YELLOW=''; BLUE=''; GREEN=''; GRAY=''; BOLD=''; DIM=''; RESET=''; CYAN=''; }

log()      { [[ "$MODE" != "json" ]] && printf "%b\n" "$1"; }
finding()  {
  local sev="$1" domain="$2" msg="$3" fix="${4:-}"
  FINDINGS+=("${sev}|${domain}|${msg}|${fix}")
  [[ "$sev" == "CRITICAL" ]] && HAS_CRITICAL=1
}
add_fix()  { FIXES+=("$1"); }

severity_color() {
  case "$1" in
    CRITICAL) echo -n "$RED" ;;
    HIGH)     echo -n "$YELLOW" ;;
    MEDIUM)   echo -n "$BLUE" ;;
    LOW)      echo -n "$GRAY" ;;
  esac
}

progress_bar() {
  local sc="${1:-0}" filled=0 empty=10 i=0
  filled=$((sc / 10))
  empty=$((10 - filled))
  printf "${GREEN}"
  for ((i=0; i<filled; i++)); do printf "■"; done
  printf "${GRAY}"
  for ((i=0; i<empty; i++)); do printf "□"; done
  printf "${RESET}"
}

grade_for() {
  local s=$1
  if   ((s >= 90)); then echo "A"
  elif ((s >= 75)); then echo "B"
  elif ((s >= 60)); then echo "C"
  elif ((s >= 40)); then echo "D"
  else echo "F"
  fi
}

# ── Parse Args ──────────────────────────────────────────────────────
usage() {
  cat <<EOF
dev-audit v${VERSION} — macOS Developer Workstation Audit

Usage: dev-audit [OPTIONS]

Options:
  --fix         Apply safe, non-destructive fixes automatically
  --json        Output results as JSON (for CI/automation)
  --self-heal   Install weekly scheduled audit with auto-fix
  --uninstall   Remove the scheduled audit LaunchAgent
  --no-color    Disable colored output
  -h, --help    Show this help

Examples:
  dev-audit                    # Scan and report
  dev-audit --fix              # Scan and auto-fix safe issues
  dev-audit --json | jq .grade # Get letter grade
  dev-audit --self-heal        # Install weekly auto-audit
EOF
  exit 0
}

for arg in "$@"; do
  case "$arg" in
    --fix)       MODE="fix" ;;
    --json)      MODE="json"; no_color ;;
    --self-heal) MODE="self-heal" ;;
    --uninstall) MODE="uninstall" ;;
    --no-color)  no_color ;;
    -h|--help)   usage ;;
  esac
done

# ── Platform Check ──────────────────────────────────────────────────
if [[ "$(uname)" != "Darwin" ]]; then
  echo "Error: dev-audit only supports macOS." >&2
  exit 1
fi

# ── Banner ──────────────────────────────────────────────────────────
banner() {
  log ""
  log "${CYAN}╔══════════════════════════════════════════════════╗${RESET}"
  log "${CYAN}║${RESET}  ${BOLD}dev-audit${RESET} v${VERSION} — Workstation Audit            ${CYAN}║${RESET}"
  log "${CYAN}╚══════════════════════════════════════════════════╝${RESET}"
  log ""
}

# ════════════════════════════════════════════════════════════════════
# DOMAIN 1: SECURITY
# ════════════════════════════════════════════════════════════════════
domain_security() {
  local score=100

  # 1.1 Secrets in shell history
  local hist_file="${HISTFILE:-$HOME/.zsh_history}"
  if [[ -f "$hist_file" ]]; then
    local secret_count
    secret_count=$(grep -ciE '(sk_live|sk_test_|ghp_|gho_|xoxb-|xoxp-|AKIA[A-Z0-9]|password\s*=|secret\s*=)' "$hist_file" 2>/dev/null || echo 0)
    if ((secret_count > 0)); then
      finding "CRITICAL" "Security" "${secret_count} potential secrets found in shell history" \
        "sed -i '' '/sk_live_/d; /sk_test_/d; /ghp_/d; /xoxb-/d; /AKIA/d' ${hist_file}"
      score=$((score - 30))
    fi
  fi

  # 1.2 World-readable .env files
  local bad_envs
  bad_envs=$(find "$HOME" -maxdepth 3 -name '.env*' -not -path '*/node_modules/*' -not -path '*/.git/*' -not -path '*/Library/*' \
    -exec stat -f "%Lp %N" {} \; 2>/dev/null | grep -v '^600' | grep -v '^$' || true)
  if [[ -n "$bad_envs" ]]; then
    local env_count
    env_count=$(echo "$bad_envs" | wc -l | tr -d ' ')
    finding "HIGH" "Security" "${env_count} .env files with loose permissions (should be 600)" \
      "find ~ -maxdepth 4 -name '.env*' -not -path '*/node_modules/*' -exec chmod 600 {} \\;"
    score=$((score - 15))
  fi

  # 1.3 .env files in Downloads
  local dl_envs
  dl_envs=$(find "$HOME/Downloads" -maxdepth 2 -name '.env*' -o -name '*.pem' -o -name '*.key' 2>/dev/null || true)
  if [[ -n "$dl_envs" ]]; then
    finding "CRITICAL" "Security" "Sensitive files found in Downloads folder" \
      "rm -i $(echo "$dl_envs" | tr '\n' ' ')"
    score=$((score - 25))
  fi

  # 1.4 SSH config
  if [[ ! -f "$HOME/.ssh/config" ]] || [[ ! -s "$HOME/.ssh/config" ]]; then
    finding "MEDIUM" "Security" "SSH config missing or empty (no hardening)" \
      "printf 'Host *\n  AddKeysToAgent yes\n  UseKeychain yes\n  IdentityFile ~/.ssh/id_ed25519\n  HashKnownHosts yes\n' > ~/.ssh/config && chmod 600 ~/.ssh/config"
    score=$((score - 5))
  fi

  # 1.5 SSH key algorithm
  if [[ -f "$HOME/.ssh/id_rsa" ]] && [[ ! -f "$HOME/.ssh/id_ed25519" ]]; then
    finding "MEDIUM" "Security" "Using RSA key only (ED25519 recommended)" \
      "ssh-keygen -t ed25519 -C \"\$(whoami)@\$(hostname)\""
    score=$((score - 5))
  fi

  # 1.6 macOS security checks
  if command -v fdesetup &>/dev/null; then
    fdesetup status 2>/dev/null | grep -q "On" || { finding "CRITICAL" "Security" "FileVault disk encryption is OFF" "sudo fdesetup enable"; score=$((score - 30)); }
  fi
  csrutil status 2>/dev/null | grep -q "enabled" || { finding "HIGH" "Security" "SIP (System Integrity Protection) is disabled" "csrutil enable (requires Recovery Mode)"; score=$((score - 20)); }
  spctl --status 2>/dev/null | grep -q "enabled" || { finding "HIGH" "Security" "Gatekeeper is disabled" "sudo spctl --master-enable"; score=$((score - 15)); }

  # 1.7 Global .gitignore
  if ! /opt/homebrew/bin/git config --global core.excludesFile &>/dev/null 2>&1 && ! git config --global core.excludesFile &>/dev/null 2>&1; then
    finding "HIGH" "Security" "No global .gitignore (risk of committing .env/.pem files)" \
      "echo -e '.env\n.env.*\n*.pem\n*.key\n.DS_Store\nnode_modules/' > ~/.gitignore_global && git config --global core.excludesFile ~/.gitignore_global"
    score=$((score - 10))
  fi

  # 1.8 Commit signing
  local gpgsign
  gpgsign=$(git config --global commit.gpgsign 2>/dev/null || echo "")
  if [[ "$gpgsign" != "true" ]]; then
    finding "MEDIUM" "Security" "Git commits are not signed" \
      "git config --global commit.gpgsign true && git config --global gpg.format ssh && git config --global user.signingkey ~/.ssh/id_ed25519.pub"
    score=$((score - 5))
  fi

  ((score < 0)) && score=0
  SCORES+=("Security|$score")
}

# ════════════════════════════════════════════════════════════════════
# DOMAIN 2: SHELL
# ════════════════════════════════════════════════════════════════════
domain_shell() {
  local score=100

  # 2.1 Startup time (skip if it would hang — use ZDOTDIR trick to isolate)
  local ms=0
  if command -v perl &>/dev/null; then
    local start_ns end_ns
    start_ns=$(perl -MTime::HiRes=time -e 'printf "%.0f\n", time*1000')
    ZDOTDIR="$HOME" zsh --no-rcs -i -c 'source ~/.zshrc 2>/dev/null; exit' </dev/null &>/dev/null &
    local zsh_pid=$!
    # Wait max 5 seconds
    local waited=0
    while kill -0 "$zsh_pid" 2>/dev/null && ((waited < 50)); do
      sleep 0.1
      ((waited++)) || true
    done
    kill "$zsh_pid" 2>/dev/null || true
    wait "$zsh_pid" 2>/dev/null || true
    end_ns=$(perl -MTime::HiRes=time -e 'printf "%.0f\n", time*1000')
    ms=$((end_ns - start_ns))
    ((ms > 5000)) && ms=0  # If we timed out, skip this check
  fi
  if ((ms > 500)); then
    finding "MEDIUM" "Shell" "Shell startup is slow (${ms}ms, target <200ms)" ""
    score=$((score - 15))
  elif ((ms > 200)); then
    finding "LOW" "Shell" "Shell startup is ${ms}ms (could be faster)" ""
    score=$((score - 5))
  fi

  # 2.2 PATH duplicates
  local dupes
  dupes=$(echo "$PATH" | tr ':' '\n' | sort | uniq -d | wc -l | tr -d ' ')
  if ((dupes > 0)); then
    finding "LOW" "Shell" "${dupes} duplicate entries in PATH" "Deduplicate PATH entries in ~/.zshrc"
    score=$((score - 5))
  fi

  # 2.3 compinit
  if [[ -f "$HOME/.zshrc" ]]; then
    grep -q 'compinit' "$HOME/.zshrc" 2>/dev/null || {
      finding "MEDIUM" "Shell" "compinit not loaded in .zshrc (completions may not work)" \
        "echo 'autoload -Uz compinit && compinit' >> ~/.zshrc"
      score=$((score - 10))
    }
  fi

  # 2.4 Plaintext tokens in .zshrc
  if grep -qE '(ghp_|sk_live|sk_test|xoxb-)' "$HOME/.zshrc" 2>/dev/null; then
    finding "HIGH" "Shell" "Plaintext tokens found in .zshrc (use macOS Keychain instead)" \
      "security add-generic-password -a \$USER -s TOKEN_NAME -w 'token_value'"
    score=$((score - 20))
  fi

  ((score < 0)) && score=0
  SCORES+=("Shell|$score")
}

# ════════════════════════════════════════════════════════════════════
# DOMAIN 3: TOOLING
# ════════════════════════════════════════════════════════════════════
domain_tooling() {
  local score=100
  local missing=()
  local tools=(
    "fzf:Fuzzy finder (Ctrl+R history, Ctrl+T files)"
    "rg:ripgrep (fast code search)"
    "fd:Modern find replacement"
    "bat:Modern cat with syntax highlighting"
    "eza:Modern ls with icons and git status"
    "delta:Git diff viewer with syntax highlighting"
    "zoxide:Smart cd that learns your directories"
    "direnv:Per-project env var auto-loading"
    "mise:Runtime version manager (Node/Python/Go)"
    "jq:JSON processor"
  )

  for entry in "${tools[@]}"; do
    local tool="${entry%%:*}"
    local desc="${entry#*:}"
    if ! command -v "$tool" &>/dev/null; then
      missing+=("$tool")
      score=$((score - 10))
    fi
  done

  if ((${#missing[@]} > 0)); then
    local install_cmd="brew install ${missing[*]}"
    finding "HIGH" "Tooling" "${#missing[@]} modern CLI tools missing: ${missing[*]}" "$install_cmd"
  fi

  ((score < 0)) && score=0
  SCORES+=("Tooling|$score")
}

# ════════════════════════════════════════════════════════════════════
# DOMAIN 4: GIT
# ════════════════════════════════════════════════════════════════════
domain_git() {
  local score=100

  # 4.1 fsmonitor
  local fsmon
  fsmon=$(git config --global core.fsmonitor 2>/dev/null || echo "")
  if [[ "$fsmon" != "true" ]]; then
    finding "MEDIUM" "Git" "fsmonitor not enabled (50-80% slower git status)" \
      "git config --global core.fsmonitor true"
    score=$((score - 15))
  fi

  # 4.2 untrackedCache
  local ucache
  ucache=$(git config --global core.untrackedCache 2>/dev/null || echo "")
  if [[ "$ucache" != "true" ]]; then
    finding "LOW" "Git" "untrackedCache not enabled" \
      "git config --global core.untrackedCache true"
    score=$((score - 5))
  fi

  # 4.3 diff algorithm
  local diffalg
  diffalg=$(git config --global diff.algorithm 2>/dev/null || echo "")
  if [[ "$diffalg" != "histogram" ]]; then
    finding "LOW" "Git" "Using default diff algorithm (histogram is better)" \
      "git config --global diff.algorithm histogram"
    score=$((score - 5))
  fi

  # 4.4 fetch.prune
  local prune
  prune=$(git config --global fetch.prune 2>/dev/null || echo "")
  if [[ "$prune" != "true" ]]; then
    finding "LOW" "Git" "fetch.prune not enabled (stale remote branches accumulate)" \
      "git config --global fetch.prune true"
    score=$((score - 5))
  fi

  # 4.5 delta pager
  local pager
  pager=$(git config --global core.pager 2>/dev/null || echo "")
  if [[ "$pager" != "delta" ]] && command -v delta &>/dev/null; then
    finding "LOW" "Git" "delta installed but not configured as git pager" \
      "git config --global core.pager delta && git config --global delta.side-by-side true && git config --global delta.line-numbers true"
    score=$((score - 5))
  fi

  ((score < 0)) && score=0
  SCORES+=("Git|$score")
}

# ════════════════════════════════════════════════════════════════════
# DOMAIN 5: PERFORMANCE
# ════════════════════════════════════════════════════════════════════
domain_performance() {
  local score=100

  # 5.1 Swap pressure
  local swap_used swap_total
  swap_used=$(sysctl vm.swapusage 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="used") print $(i+2)}' | sed 's/[^0-9.]//g' || echo "0")
  swap_total=$(sysctl vm.swapusage 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="total") print $(i+2)}' | sed 's/[^0-9.]//g' || echo "1")
  if [[ -n "$swap_total" ]] && [[ "$swap_total" != "0" ]]; then
    local swap_pct
    swap_pct=$(awk "BEGIN {printf \"%d\", ($swap_used / $swap_total) * 100}" 2>/dev/null || echo 0)
    if ((swap_pct > 80)); then
      finding "HIGH" "Performance" "Swap ${swap_pct}% full (${swap_used}M / ${swap_total}M) — system is memory-thrashing" "Close unused apps; run: sudo purge"
      score=$((score - 25))
    elif ((swap_pct > 50)); then
      finding "MEDIUM" "Performance" "Swap ${swap_pct}% used" "Consider closing memory-heavy apps"
      score=$((score - 10))
    fi
  fi

  # 5.2 Ollama running
  if pgrep -q ollama 2>/dev/null; then
    finding "MEDIUM" "Performance" "Ollama is running (holds 4-18 GB RAM when idle)" \
      "launchctl unload ~/Library/LaunchAgents/homebrew.mxcl.ollama.plist"
    score=$((score - 15))
  fi

  # 5.3 Spotlight indexing node_modules (limit search depth for speed)
  local unindexed=0
  while IFS= read -r d; do
    [[ -d "$d" ]] && [[ ! -f "$d/.metadata_never_index" ]] && ((unindexed++))
  done < <(find "$HOME" -maxdepth 3 -name 'node_modules' -type d -not -path '*/node_modules/*' 2>/dev/null)
  if ((unindexed > 0)); then
    finding "HIGH" "Performance" "${unindexed} node_modules dirs being indexed by Spotlight" \
      "find ~ -maxdepth 4 -name 'node_modules' -type d -not -path '*/node_modules/*/node_modules' -exec touch {}/.metadata_never_index \\;"
    score=$((score - 15))
  fi

  ((score < 0)) && score=0
  SCORES+=("Performance|$score")
}

# ════════════════════════════════════════════════════════════════════
# DOMAIN 6: MACOS DEFAULTS
# ════════════════════════════════════════════════════════════════════
domain_macos() {
  local score=100

  # 6.1 Key repeat
  local kr
  kr=$(defaults read NSGlobalDomain KeyRepeat 2>/dev/null || echo "")
  if [[ -z "$kr" ]] || ((kr > 3)); then
    finding "MEDIUM" "macOS" "Key repeat is slow (current: ${kr:-default}, recommended: 2)" \
      "defaults write NSGlobalDomain KeyRepeat -int 2 && defaults write NSGlobalDomain InitialKeyRepeat -int 15"
    score=$((score - 10))
  fi

  # 6.2 Show all file extensions
  local ext
  ext=$(defaults read NSGlobalDomain AppleShowAllExtensions 2>/dev/null || echo "0")
  if [[ "$ext" != "1" ]]; then
    finding "LOW" "macOS" "File extensions hidden in Finder" \
      "defaults write NSGlobalDomain AppleShowAllExtensions -bool true"
    score=$((score - 5))
  fi

  # 6.3 .DS_Store on network
  local dsnet
  dsnet=$(defaults read com.apple.desktopservices DSDontWriteNetworkStores 2>/dev/null || echo "0")
  if [[ "$dsnet" != "1" ]]; then
    finding "LOW" "macOS" ".DS_Store files created on network volumes" \
      "defaults write com.apple.desktopservices DSDontWriteNetworkStores -bool true && defaults write com.apple.desktopservices DSDontWriteUSBStores -bool true"
    score=$((score - 5))
  fi

  # 6.4 Dock animation
  local dockanim
  dockanim=$(defaults read com.apple.dock launchanim 2>/dev/null || echo "1")
  if [[ "$dockanim" == "1" ]]; then
    finding "LOW" "macOS" "Dock launch animation enabled (wastes CPU)" \
      "defaults write com.apple.dock launchanim -bool false && killall Dock"
    score=$((score - 5))
  fi

  ((score < 0)) && score=0
  SCORES+=("macOS|$score")
}

# ════════════════════════════════════════════════════════════════════
# DOMAIN 7: HYGIENE
# ════════════════════════════════════════════════════════════════════
domain_hygiene() {
  local score=100

  # 7.1 npm cache
  local npm_cache_size
  npm_cache_size=$(du -sm "$HOME/.npm/_cacache" 2>/dev/null | awk '{print $1}' || echo 0)
  if ((npm_cache_size > 1000)); then
    finding "MEDIUM" "Hygiene" "npm cache is ${npm_cache_size}MB" "npm cache clean --force"
    score=$((score - 10))
  fi

  # 7.2 Homebrew
  if command -v brew &>/dev/null; then
    local brew_cache_size
    brew_cache_size=$(du -sm "$(brew --cache)" 2>/dev/null | awk '{print $1}' || echo 0)
    if ((brew_cache_size > 500)); then
      finding "LOW" "Hygiene" "Homebrew cache is ${brew_cache_size}MB" "brew cleanup --prune=all"
      score=$((score - 5))
    fi

    local outdated
    outdated=$(brew outdated 2>/dev/null | wc -l | tr -d ' ')
    if ((outdated > 5)); then
      finding "MEDIUM" "Hygiene" "${outdated} outdated Homebrew packages" "brew upgrade"
      score=$((score - 10))
    fi
  fi

  # 7.3 Xcode CLT (fast check — avoids slow brew doctor)
  if command -v xcode-select &>/dev/null; then
    local clt_path
    clt_path=$(xcode-select -p 2>/dev/null || echo "")
    if [[ -z "$clt_path" ]] || [[ ! -d "$clt_path" ]]; then
      finding "HIGH" "Hygiene" "Xcode Command Line Tools not installed" \
        "sudo xcode-select --install"
      score=$((score - 15))
    fi
  fi

  ((score < 0)) && score=0
  SCORES+=("Hygiene|$score")
}

# ════════════════════════════════════════════════════════════════════
# REPORT
# ════════════════════════════════════════════════════════════════════
report() {
  local total=0 count=0
  log ""

  # Domain scores
  for entry in "${SCORES[@]}"; do
    local domain="${entry%%|*}" sc="${entry#*|}"
    local grade
    grade=$(grade_for "$sc")
    local dots
    dots=$(printf '%*s' $((40 - ${#domain})) '' | tr ' ' '.')
    log "  $(progress_bar "$sc") ${BOLD}${domain}${RESET} ${DIM}${dots}${RESET} ${BOLD}${grade}${RESET} (${sc}/100)"
    total=$((total + sc))
    count=$((count + 1))
  done

  local avg=$((total / count))
  local overall_grade
  overall_grade=$(grade_for "$avg")

  log ""
  log "  ${BOLD}Overall Grade: ${overall_grade} (${avg}/100)${RESET}"
  log ""

  # Findings by severity
  local crits=() highs=() meds=() lows=()
  for f in "${FINDINGS[@]}"; do
    local sev="${f%%|*}"
    case "$sev" in
      CRITICAL) crits+=("$f") ;;
      HIGH)     highs+=("$f") ;;
      MEDIUM)   meds+=("$f") ;;
      LOW)      lows+=("$f") ;;
    esac
  done

  local num=1
  if ((${#crits[@]} > 0)); then
    log "${RED}─── CRITICAL (${#crits[@]}) ───────────────────────────────────${RESET}"
    for f in "${crits[@]}"; do
      IFS='|' read -r sev domain msg fix <<< "$f"
      log "  ${RED}${num}.${RESET} [${domain}] ${msg}"
      [[ -n "$fix" ]] && log "     ${GREEN}Fix: ${fix}${RESET}"
      ((num++))
    done
    log ""
  fi

  if ((${#highs[@]} > 0)); then
    log "${YELLOW}─── HIGH (${#highs[@]}) ────────────────────────────────────────${RESET}"
    for f in "${highs[@]}"; do
      IFS='|' read -r sev domain msg fix <<< "$f"
      log "  ${YELLOW}${num}.${RESET} [${domain}] ${msg}"
      [[ -n "$fix" ]] && log "     ${GREEN}Fix: ${fix}${RESET}"
      ((num++))
    done
    log ""
  fi

  if ((${#meds[@]} > 0)); then
    log "${BLUE}─── MEDIUM (${#meds[@]}) ──────────────────────────────────────${RESET}"
    for f in "${meds[@]}"; do
      IFS='|' read -r sev domain msg fix <<< "$f"
      log "  ${BLUE}${num}.${RESET} [${domain}] ${msg}"
      [[ -n "$fix" ]] && log "     ${GREEN}Fix: ${fix}${RESET}"
      ((num++))
    done
    log ""
  fi

  if ((${#lows[@]} > 0)); then
    log "${GRAY}─── LOW (${#lows[@]}) ─────────────────────────────────────────${RESET}"
    for f in "${lows[@]}"; do
      IFS='|' read -r sev domain msg fix <<< "$f"
      log "  ${GRAY}${num}.${RESET} [${domain}] ${msg}"
      [[ -n "$fix" ]] && log "     ${GREEN}Fix: ${fix}${RESET}"
      ((num++))
    done
    log ""
  fi

  if ((${#FINDINGS[@]} == 0)); then
    log "  ${GREEN}All clear — no issues found.${RESET}"
  fi

  log "${DIM}Found ${#FINDINGS[@]} issues across 7 domains.${RESET}"
}

# ════════════════════════════════════════════════════════════════════
# JSON OUTPUT
# ════════════════════════════════════════════════════════════════════
json_output() {
  local total=0 count=0
  local domains_json="{"
  for entry in "${SCORES[@]}"; do
    local domain="${entry%%|*}" sc="${entry#*|}"
    total=$((total + sc))
    count=$((count + 1))
    [[ "$domains_json" != "{" ]] && domains_json+=","
    domains_json+="\"${domain}\": {\"score\": ${sc}, \"grade\": \"$(grade_for "$sc")\"}"
  done
  domains_json+="}"

  local avg=$((total / count))
  local findings_json="["
  local first=true
  for f in "${FINDINGS[@]}"; do
    IFS='|' read -r sev domain msg fix <<< "$f"
    [[ "$first" != "true" ]] && findings_json+=","
    first=false
    # Escape JSON strings
    msg="${msg//\\/\\\\}"; msg="${msg//\"/\\\"}"
    fix="${fix//\\/\\\\}"; fix="${fix//\"/\\\"}"
    findings_json+="{\"severity\":\"${sev}\",\"domain\":\"${domain}\",\"message\":\"${msg}\",\"fix\":\"${fix}\"}"
  done
  findings_json+="]"

  cat <<EOF
{
  "version": "${VERSION}",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "hostname": "$(hostname -s)",
  "grade": "$(grade_for "$avg")",
  "score": ${avg},
  "domains": ${domains_json},
  "findings": ${findings_json},
  "finding_count": ${#FINDINGS[@]},
  "has_critical": ${HAS_CRITICAL}
}
EOF
}

# ════════════════════════════════════════════════════════════════════
# FIX MODE
# ════════════════════════════════════════════════════════════════════
apply_fixes() {
  log ""
  log "${BOLD}Applying safe fixes...${RESET}"
  log ""

  local applied=0

  # Fix .env permissions
  find "$HOME" -maxdepth 4 -name '.env*' -not -path '*/node_modules/*' -not -path '*/.git/*' \
    -exec chmod 600 {} \; 2>/dev/null && {
    log "  ${GREEN}✓${RESET} Fixed .env file permissions to 600"
    ((applied++))
  }

  # Spotlight exclusions for node_modules
  local nm_fixed=0
  while IFS= read -r d; do
    if [[ -d "$d" ]] && [[ ! -f "$d/.metadata_never_index" ]]; then
      touch "$d/.metadata_never_index" && ((nm_fixed++))
    fi
  done < <(find "$HOME" -maxdepth 4 -name 'node_modules' -type d -not -path '*/node_modules/*/node_modules' 2>/dev/null)
  if ((nm_fixed > 0)); then
    log "  ${GREEN}✓${RESET} Excluded ${nm_fixed} node_modules from Spotlight"
    ((applied++))
  fi

  # Git config
  local git_cmd="git"
  command -v /opt/homebrew/bin/git &>/dev/null && git_cmd="/opt/homebrew/bin/git"
  local changed=0
  [[ "$($git_cmd config --global core.fsmonitor 2>/dev/null)" != "true" ]] && $git_cmd config --global core.fsmonitor true && ((changed++))
  [[ "$($git_cmd config --global core.untrackedCache 2>/dev/null)" != "true" ]] && $git_cmd config --global core.untrackedCache true && ((changed++))
  [[ "$($git_cmd config --global fetch.prune 2>/dev/null)" != "true" ]] && $git_cmd config --global fetch.prune true && ((changed++))
  [[ "$($git_cmd config --global diff.algorithm 2>/dev/null)" != "histogram" ]] && $git_cmd config --global diff.algorithm histogram && ((changed++))
  if ((changed > 0)); then
    log "  ${GREEN}✓${RESET} Applied ${changed} git performance settings"
    ((applied++))
  fi

  # Global .gitignore
  if ! $git_cmd config --global core.excludesFile &>/dev/null; then
    printf '.env\n.env.*\n*.pem\n*.key\n.DS_Store\nnode_modules/\n' > "$HOME/.gitignore_global"
    $git_cmd config --global core.excludesFile "$HOME/.gitignore_global"
    log "  ${GREEN}✓${RESET} Created global .gitignore"
    ((applied++))
  fi

  # macOS defaults
  defaults write NSGlobalDomain AppleShowAllExtensions -bool true 2>/dev/null && {
    log "  ${GREEN}✓${RESET} Show all file extensions in Finder"
    ((applied++))
  }
  defaults write com.apple.desktopservices DSDontWriteNetworkStores -bool true 2>/dev/null && {
    log "  ${GREEN}✓${RESET} Disabled .DS_Store on network volumes"
    ((applied++))
  }

  log ""
  log "${BOLD}Applied ${applied} fixes.${RESET}"
}

# ════════════════════════════════════════════════════════════════════
# SELF-HEAL
# ════════════════════════════════════════════════════════════════════
self_heal() {
  local script_path
  script_path="$(cd "$(dirname "$0")" && pwd)/dev-audit.sh"
  local plist_label="com.devaudit.scheduled"
  local plist_path="$HOME/Library/LaunchAgents/${plist_label}.plist"
  local log_dir="$HOME/Reports/dev-audit"

  mkdir -p "$log_dir"

  cat > "$plist_path" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${plist_label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>${script_path}</string>
    <string>--fix</string>
    <string>--json</string>
  </array>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Weekday</key>
    <integer>0</integer>
    <key>Hour</key>
    <integer>4</integer>
    <key>Minute</key>
    <integer>0</integer>
  </dict>
  <key>StandardOutPath</key>
  <string>${log_dir}/audit.log</string>
  <key>StandardErrorPath</key>
  <string>${log_dir}/audit.err</string>
  <key>RunAtLoad</key>
  <false/>
</dict>
</plist>
PLIST

  launchctl unload "$plist_path" 2>/dev/null || true
  launchctl load "$plist_path"

  log "${GREEN}✓${RESET} Self-healing installed!"
  log "  Schedule: Every Sunday at 4:00 AM"
  log "  Logs: ${log_dir}/audit.log"
  log "  Remove: dev-audit --uninstall"
}

uninstall_heal() {
  local plist_path="$HOME/Library/LaunchAgents/com.devaudit.scheduled.plist"
  if [[ -f "$plist_path" ]]; then
    launchctl unload "$plist_path" 2>/dev/null || true
    rm -f "$plist_path"
    log "${GREEN}✓${RESET} Self-healing LaunchAgent removed."
  else
    log "No self-healing LaunchAgent found."
  fi
}

# ════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════
main() {
  case "$MODE" in
    self-heal) self_heal; exit 0 ;;
    uninstall) uninstall_heal; exit 0 ;;
  esac

  [[ "$MODE" != "json" ]] && banner

  # Run all domain checks
  domain_security
  domain_shell
  domain_tooling
  domain_git
  domain_performance
  domain_macos
  domain_hygiene

  # Output
  case "$MODE" in
    json)
      json_output
      ;;
    fix)
      report
      apply_fixes
      ;;
    *)
      report
      ;;
  esac

  # Exit code
  if ((HAS_CRITICAL)); then exit 2
  elif ((${#FINDINGS[@]} > 0)); then exit 1
  else exit 0
  fi
}

main
