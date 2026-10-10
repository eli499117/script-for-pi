#!/usr/bin/env bash
# secure-pi.sh - Harden + provision Raspberry Pi OS Lite (bookworm, arm64).
# Non-interactive, idempotent. Safe over Pi Connect (outbound tunnel;
# UFW deny-incoming does not break it). Skips by design: sysctl, users,
# password policy, /tmp tmpfs, IPv6, docker/VPN, rpi-connect.
# Usage: sudo ./secure-pi.sh [--dry-run] [--ssh-port N] [--force]
set -euo pipefail

# ---------------------------------------------------------------- globals ---
SSH_PORT=22
DRY_RUN=0
BACKUP_ROOT="/var/backups/secure-pi"
TIMESTAMP="$(date +%Y%m%dT%H%M%S)"

APPLIED=()
SKIPPED=()
WARNINGS=()

# ------------------------------------------------------------- color logs ---
# tput-safe: colors only when stdout is a tty and tput exists; else plain.
if command -v tput >/dev/null 2>&1 && [ -t 1 ]; then
    C_INFO="$(tput bold 2>/dev/null || true)$(tput setaf 4 2>/dev/null || true)"
    C_OK="$(tput bold 2>/dev/null || true)$(tput setaf 2 2>/dev/null || true)"
    C_WARN="$(tput bold 2>/dev/null || true)$(tput setaf 3 2>/dev/null || true)"
    C_ERR="$(tput bold 2>/dev/null || true)$(tput setaf 1 2>/dev/null || true)"
    C_RESET="$(tput sgr0 2>/dev/null || true)"
else C_INFO="" C_OK="" C_WARN="" C_ERR="" C_RESET=""; fi

log()  { printf '%s[info]%s %s\n' "$C_INFO" "$C_RESET" "$*"; }
ok()   { printf '%s[ok]%s %s\n' "$C_OK" "$C_RESET" "$*"; APPLIED+=("$*"); }
warn() { printf '%s[warn]%s %s\n' "$C_WARN" "$C_RESET" "$*" >&2; WARNINGS+=("$*"); }
die() {
    # $1 = exit code, rest = message. Exit 2 = fatal config validation.
    local code="$1"; shift
    printf '%s[fatal]%s %s\n' "$C_ERR" "$C_RESET" "$*" >&2
    exit "$code"
}
skip() { printf '%s[skip]%s %s\n' "$C_INFO" "$C_RESET" "$*"; SKIPPED+=("$*"); }

# -------------------------------------------------------------- core utils ---
# run: every mutating call goes through here so --dry-run changes nothing.
run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] %s\n' "$*"
        return 0
    fi
    "$@"
}

# run_allow_fail: for individually-guarded steps (service disables, auditd
# load) where one failure must not abort the run under set -e.
run_allow_fail() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] %s\n' "$*"
        return 0
    fi
    "$@" || return $?
}

backup_file() {
    # Copy existing file to $BACKUP_ROOT/<relpath>.<timestamp> before touch.
    local src="$1"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] backup %s -> %s/%s.%s\n' "$src" "$BACKUP_ROOT" "${src#/}" "$TIMESTAMP"
        return 0
    fi
    if [ ! -e "$src" ]; then
        return 0
    fi
    local dest="${BACKUP_ROOT}/${src#/}.${TIMESTAMP}"
    mkdir -p "$(dirname "$dest")"
    cp -a "$src" "$dest"
    log "backup: $src -> $dest"
}

# write_file: atomic idempotent write ($1 = path, stdin = content).
# Backs up first, skips rewrite when content already matches.
write_file() {
    local dest="$1"
    local tmp
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] write %s\n' "$dest"
        return 0
    fi
    tmp="$(mktemp)"
    cat > "$tmp"
    if [ -f "$dest" ] && cmp -s "$tmp" "$dest"; then
        rm -f "$tmp"
        log "unchanged: $dest"
        return 0
    fi
    backup_file "$dest"
    mkdir -p "$(dirname "$dest")"
    cat "$tmp" > "$dest"
    chmod 644 "$dest"
    rm -f "$tmp"
    log "wrote: $dest"
}

pkg_installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "ok installed"; }

unit_exists() {
    # Existence check so image variance (missing units) never aborts the run.
    systemctl list-unit-files --no-legend 2>/dev/null | grep -q "^${1}[[:space:]]"
}

service_active() { systemctl is-active --quiet "$1" 2>/dev/null; }

print_list() { # $1 = label, rest = items
    local label="$1"; shift
    printf '%s (%d):\n' "$label" "$#"
    local item
    for item in "$@"; do printf '  - %s\n' "$item"; done
}
usage() {
    cat <<EOF
Usage: secure-pi.sh [OPTIONS]

Harden + provision Raspberry Pi OS Lite (bookworm). Must run as root
except with --dry-run.

Options:
  --dry-run      Print every planned action, change nothing, root not required.
  --ssh-port N   Firewall + fail2ban port (default 22). sshd stays on 22
                 unless you reconfigure it separately. Future-proofing only.
  --help         Show this usage and exit.
EOF
}

# ------------------------------------------------------------------- args ---
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        --ssh-port)
            [ $# -ge 2 ] || { usage >&2; exit 1; }
            case "$2" in
                ''|*[!0-9]*) printf 'error: --ssh-port needs a number\n' >&2; exit 1 ;;
            esac
            if [ "$2" -lt 1 ] || [ "$2" -gt 65535 ]; then
                printf 'error: --ssh-port out of range 1-65535\n' >&2; exit 1
            fi
            SSH_PORT="$2"; shift 2 ;;
        --help) usage; exit 0 ;;
        --*) printf 'error: unknown option %s\n' "$1" >&2; usage >&2; exit 1 ;;
        *) printf 'error: unexpected argument %s\n' "$1" >&2; usage >&2; exit 1 ;;
    esac
done

# -------------------------------------------------------------- root check ---
if [ "$DRY_RUN" -eq 1 ]; then
    if [ "$(id -u)" -ne 0 ]; then
        warn "dry-run as non-root: printing planned actions only, no changes."
    fi
else
    if [ "$(id -u)" -ne 0 ]; then
        die 1 "must run as root (use sudo). Try --dry-run to preview without root."
    fi
fi

export DEBIAN_FRONTEND=noninteractive

# ============================================================ 1. system =====
step_system() {
    log "== system update =="
    run apt-get update
    run apt-get -y full-upgrade
    run apt-get install -y ufw fail2ban auditd audispd-plugins unattended-upgrades
    run apt-get -y autoremove
    ok "system updated; base packages installed"
}

# ============================================================ 2. sshd =======
step_ssh() {
    log "== SSH hardening (STANDARD) =="
    local conf="/etc/ssh/sshd_config"
    local dropin="/etc/ssh/sshd_config.d/99-hardening.conf"

    # Bookworm sshd reads drop-ins via a top Include line; ensure it exists
    # so our 99-hardening.conf actually takes effect.
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] ensure Include line in %s; write %s\n' "$conf" "$dropin"
    else
        if ! grep -q '^Include /etc/ssh/sshd_config.d/\*\.conf' "$conf" 2>/dev/null; then
            backup_file "$conf"
            printf '%s\n' "Include /etc/ssh/sshd_config.d/*.conf" >> "$conf"
            log "appended Include line to $conf (original backed up)"
        fi
    fi

    write_file "$dropin" <<EOF
# secure-pi: SSH policy. Managed by secure-pi.sh - do not hand-edit.
# Password-only auth per user request; no idle timeout.
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
UseDNS no
EOF

    # Validate BEFORE reload: a broken sshd over a remote session = bricked box.
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] sshd -t && systemctl reload ssh\n'
    else
        if command -v sshd >/dev/null 2>&1; then
            if ! sshd -t; then
                warn "sshd -t failed; old config kept in place, backups under $BACKUP_ROOT"
                die 2 "sshd config validation failed; inspect $BACKUP_ROOT and fix manually"
            fi
            # reload, never restart: keeps the current remote session alive.
            run systemctl reload ssh
        else
            warn "sshd binary not found (openssh-server not installed); drop-in written, validation skipped"
        fi
    fi
    ok "sshd hardened (drop-in written, config validated, reloaded)"
}

# ============================================================ 3. ufw ========
step_ufw() {
    log "== UFW firewall =="
    # Pi Connect dials OUTBOUND, so default-deny incoming does not affect it.
    run ufw default deny incoming
    run ufw default allow outgoing
    # Allow (rate-limited) SSH before enabling, or enable locks us out.
    run ufw limit "${SSH_PORT}/tcp"
    run ufw --force enable
    ok "ufw enabled (deny-in, allow-out, limit ${SSH_PORT}/tcp)"
}

# ============================================================ 4. fail2ban ===
step_fail2ban() {
    log "== fail2ban =="
    write_file "/etc/fail2ban/jail.d/99-securepi.local" <<EOF
# secure-pi: local fail2ban policy. Managed by secure-pi.sh.
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = ${SSH_PORT}

[recidive]
enabled = true
bantime = 1w
findtime = 1d
maxretry = 3
EOF
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] fail2ban-client -t && systemctl enable --now fail2ban\n'
    else
        # Validate before (re)start: a bad jail config can silently ban nobody
        # or, worse, fail open on the daemon. Restore + abort on failure.
        if ! fail2ban-client -t; then
            die 2 "fail2ban config validation failed; backups under $BACKUP_ROOT"
        fi
        run systemctl enable --now fail2ban
        run systemctl restart fail2ban || die 2 "fail2ban restart failed after valid config"
    fi
    ok "fail2ban configured (sshd + recidive)"
}

# ============================================================ 5. auto-updates
step_unattended() {
    log "== unattended-upgrades =="
    write_file "/etc/apt/apt.conf.d/20auto-upgrades" <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    write_file "/etc/apt/apt.conf.d/52unattended-upgrades-local" <<'EOF'
# secure-pi: never auto-reboot. A surprise reboot kills remote
# Raspberry Pi Connect sessions with no one on site to recover.
Unattended-Upgrade::Automatic-Reboot "false";
EOF
    run systemctl enable --now unattended-upgrades
    # The APT::Periodic flags above run under apt-daily-upgrade.timer;
    # the oneshot service alone schedules nothing.
    run systemctl enable --now apt-daily-upgrade.timer || warn "apt-daily-upgrade.timer not found; periodic flags still apply via apt-daily"
    ok "unattended-upgrades enabled (no auto-reboot)"
}

# ============================================================ 6. audit ======
step_audit_journal() {
    log "== auditd + journald =="
    write_file "/etc/audit/rules.d/99-securepi.rules" <<'EOF'
# secure-pi: minimal audit watchlist (SD-card conscious, high-signal only).
-D
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system
EOF
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] augenrules --load; systemctl enable --now auditd\n'
    else
        # Some kernels (containers, custom builds) lack audit support;
        # a hard failure here must not kill the whole provisioning run.
        if ! run_allow_fail augenrules --load; then
            warn "augenrules --load failed (kernel may lack audit support); continuing"
        fi
        if ! run_allow_fail systemctl enable --now auditd; then
            warn "could not enable auditd; continuing"
        fi
    fi
    write_file "/etc/systemd/journald.conf.d/99-securepi.conf" <<'EOF'
[Journal]
Storage=persistent
SystemMaxUse=200M
RuntimeMaxUse=50M
EOF
    # Persistent journal needs the dir to exist; caps keep SD-card use bounded.
    run mkdir -p /var/log/journal
    # Apply journald changes now (safe: journald just reopens its logs).
    run systemctl restart systemd-journald || warn "could not restart journald; caps apply on next boot"
    ok "auditd rules + persistent journald (200M/50M caps) configured"
}

# ============================================================ 7. time =======
step_time() {
    log "== time sync =="
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] systemctl enable --now systemd-timesyncd (unless chrony active)\n'
        return 0
    fi
    if unit_exists "systemd-timesyncd.service"; then
        run systemctl enable --now systemd-timesyncd
        ok "systemd-timesyncd enabled"
    elif service_active "chrony.service" || service_active "chronyd.service"; then
        # Never break working time sync: chrony already owns it, leave it.
        skip "chrony active, leaving time sync untouched"
    else
        warn "no systemd-timesyncd unit and no active chrony; time sync unverified"
    fi
}

# ============================================================ 8. services ===
step_disable_services() {
    log "== disable unused services =="
    # NEVER here: ssh/sshd, rpi-connect, systemd-timesyncd, networking.
    local svc
    for svc in avahi-daemon.service bluetooth.service triggerhappy.service hciuart.service serial-getty@ttyS0.service; do
        if [ "$DRY_RUN" -eq 1 ]; then
            printf '[dry-run] disable --now + mask %s (if present)\n' "$svc"
            continue
        fi
        # Template instances (serial-getty@ttyS0) never appear in
        # list-unit-files; is-enabled finds them when the symlink exists.
        if ! unit_exists "$svc" && ! systemctl is-enabled "$svc" >/dev/null 2>&1; then
            skip "$svc absent on this image"
            continue
        fi
        # Individually guarded: one odd unit must not abort the run.
        if run_allow_fail systemctl disable --now "$svc"; then
            run_allow_fail systemctl mask "$svc" || warn "could not mask $svc"
            ok "disabled+masked $svc"
        else
            warn "could not disable $svc; continuing"
        fi
    done
}

# ============================================================ 9. toolchain ==
step_toolchain() {
    log "== toolchain =="
    local target_user target_home
    # Auto-detect the invoking human: sudo exposes them as SUDO_USER.
    # Plain whoami under sudo would report "root" and install the node
    # toolchain/rustup into /root instead of the real user's home.
    if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
        target_user="$SUDO_USER"
    else
        target_user="$(whoami)"
    fi
    if [ "$target_user" = "root" ]; then
        target_home="/root"
    else
        target_home="$(getent passwd "$target_user" | cut -d: -f6)"
        [ -n "$target_home" ] || target_home="/home/$target_user"
    fi
    log "target user: $target_user ($target_home)"

    # Warn-only disk check: 2GB floor before heavy installs, never abort.
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] check free disk on / >= 2GB\n'
    else
        local avail_kb
        avail_kb="$(df --output=avail -k / | tail -n 1 | tr -d ' ')"
        if [ -n "$avail_kb" ] && [ "$avail_kb" -lt 2097152 ]; then
            warn "free disk on / under 2GB; toolchain install may fail"
        fi
    fi

    # apt everything first: one transaction, then language toolchains.
    run apt-get install -y git curl ca-certificates unzip jq tmux htop ripgrep \
        build-essential python3 python3-venv python3-pip default-jdk gh
    ok "apt toolchain packages installed"

    # Per-user installs MUST run as the target user, never root: nvm/rustup
    # install into $HOME and patch that user's .bashrc; as root they would
    # pollute /root and leave the real user without the toolchain.
    # Node + npm via nvm: always the latest release (the nvm installer
    # writes its own PATH lines into .bashrc), then npm itself upgraded to
    # latest. Replaces the old bun-based toolchain; npm is now the package manager.
    run runuser -u "$target_user" -- bash -c 'curl -fsSL https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash'
    ok "nvm installed for $target_user"
    run runuser -u "$target_user" -- bash -c 'export NVM_DIR="$HOME/.nvm"; . "$NVM_DIR/nvm.sh"; nvm install node; nvm alias default node'
    ok "latest node installed for $target_user"
    run runuser -u "$target_user" -- bash -c 'export NVM_DIR="$HOME/.nvm"; . "$NVM_DIR/nvm.sh"; npm install -g npm@latest'
    ok "npm upgraded to latest for $target_user"
    run runuser -u "$target_user" -- bash -c 'export NVM_DIR="$HOME/.nvm"; . "$NVM_DIR/nvm.sh"; npm install -g vercel'
    ok "vercel CLI installed for $target_user (npm)"
    # opencode: official installer, per-user, binary lands in
    # $HOME/.opencode/bin (the installer also appends its own PATH line).
    run runuser -u "$target_user" -- bash -c 'curl -fsSL https://opencode.ai/v2/install | bash'
    ok "opencode installed for $target_user"
    run runuser -u "$target_user" -- bash -c "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal"
    ok "rustup stable/minimal installed for $target_user"

    # Idempotent PATH marker in the target user's .bashrc. nvm manages its
    # own PATH lines; we only need cargo + opencode bin here.
    local bashrc="${target_home}/.bashrc"
    local marker='export PATH="$HOME/.cargo/bin:$HOME/.opencode/bin:$PATH"'
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] ensure PATH marker in %s (drop legacy bun marker)\n' "$bashrc"
    else
        # Remove the legacy bun marker left by older versions of this script.
        # Fixed-string match on the marker prefix only: never touches lines
        # a user added by hand (e.g. their own BUN_INSTALL exports).
        if [ -f "$bashrc" ] && grep -qF 'export PATH="$HOME/.bun/bin' "$bashrc" 2>/dev/null; then
            backup_file "$bashrc"
            run runuser -u "$target_user" -- bash -c "grep -vF 'export PATH=\"\$HOME/.bun/bin' '$bashrc' > '$bashrc.sp' && mv '$bashrc.sp' '$bashrc'"
            log "removed legacy bun PATH marker from $bashrc"
        fi
        if [ -f "$bashrc" ] && grep -qF '.opencode/bin' "$bashrc"; then
            log "PATH marker already in $bashrc"
        else
            backup_file "$bashrc"
            if [ "$target_user" = "root" ]; then
                printf '%s\n' "$marker" >> "$bashrc"
            else
                # Append as the user so ownership stays correct.
                run runuser -u "$target_user" -- bash -c "printf '%s\n' '$marker' >> '$bashrc'"
            fi
            log "appended PATH marker to $bashrc"
        fi
    fi

    # Version proof (informational; individual misses warn, not fail).
    # node/npm/vercel live inside nvm, so source nvm.sh before calling them.
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] print versions: node, npm, rustc, vercel, opencode, gh\n'
    else
        run_allow_fail runuser -u "$target_user" -- bash -c 'export NVM_DIR="$HOME/.nvm"; . "$NVM_DIR/nvm.sh"; node --version' || warn "node version check failed"
        run_allow_fail runuser -u "$target_user" -- bash -c 'export NVM_DIR="$HOME/.nvm"; . "$NVM_DIR/nvm.sh"; npm --version' || warn "npm version check failed"
        run_allow_fail runuser -u "$target_user" -- "$target_home/.cargo/bin/rustc" --version || warn "rustc version check failed"
        run_allow_fail runuser -u "$target_user" -- bash -c 'export NVM_DIR="$HOME/.nvm"; . "$NVM_DIR/nvm.sh"; vercel --version' || warn "vercel version check failed"
        run_allow_fail runuser -u "$target_user" -- "$target_home/.opencode/bin/opencode" --version || warn "opencode version check failed"
        run_allow_fail gh --version || warn "gh version check failed"
    fi
}

# ============================================================ 10. skills ===
# Install agent skills via the official skills.sh CLI. MUST run after
# step_toolchain: npx (from nvm) is required. Copies land in the target
# user's ~/.agents/skills, which OpenCode reads as a global source.
step_skills() {
    log "== agent skills (skills.sh) =="
    local specs=(
        vercel-labs/skills:find-skills
        anthropics/skills:frontend-design
        vercel-labs/agent-skills:web-design-guidelines
        juliusbrussee/caveman:caveman
        anthropics/skills:skill-creator
        leonxlnx/taste-skill:minimalist-ui
        supabase/agent-skills:supabase
        shadcn-ui/ui:shadcn
        anthropics/skills:pptx
        cursor/plugins:unslop
    )
    local spec
    for spec in "${specs[@]}"; do
        install_skill "$spec"
    done
}

# ------------------------------------------------------- skill installer ---
# Install one agent skill from skills.sh via the official CLI, as the
# target user, as the final provisioning stage. Each call is individually
# guarded so one unavailable repo cannot abort the run (see AGENTS.md:
# "run_allow_fail is for one call; loops need their own || guard").
# $1 = repo:skill (e.g. vercel-labs/skills:find-skills).
install_skill() {
    local spec="$1" repo skill log="${TMPDIR:-/tmp}/skill-$$.log"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '[dry-run] skill: %s\n' "$spec"
        return 0
    fi
    repo="${spec%%:*}"
    skill="${spec##*:}"
    # Success signal = CLI exit status (exactly one skill per call). The log
    # is post-mortem only: do NOT grep the pretty output for success text —
    # it prints a unicode checkmark line ("✓ <skill> (copied)") that is not
    # a stable grep target and would false-warn on every success.
    # nvm lands node/npx/vercel in the user's own nvm dir, so source nvm.sh
    # first: a bare runuser shell has none of them on PATH.
    if run_allow_fail runuser -u "$target_user" -- bash -c "export NVM_DIR=\"\$HOME/.nvm\"; . \"\$NVM_DIR/nvm.sh\"; npx --yes skills@latest add $repo --skill $skill --full-depth --global --agent opencode --yes" >>"$log" 2>&1; then
        ok "skill installed: $skill ($repo)"
        rm -f "$log"
    else
        warn "skill install failed: $skill ($repo) — see $log"
    fi
}

# ------------------------------------------------------------------ main ----
main() {
    log "secure-pi start (ssh-port=${SSH_PORT}, dry-run=${DRY_RUN})"
    step_system
    step_ssh
    step_ufw
    step_fail2ban
    step_unattended
    step_audit_journal
    step_time
    step_disable_services
    step_toolchain
    step_skills

    printf '\n===== SUMMARY =====\n'
    if [ "${#APPLIED[@]}" -gt 0 ]; then print_list "Applied" "${APPLIED[@]}"; else printf 'Applied (0):\n'; fi
    if [ "${#SKIPPED[@]}" -gt 0 ]; then print_list "Skipped" "${SKIPPED[@]}"; else printf 'Skipped (0):\n'; fi
    if [ "${#WARNINGS[@]}" -gt 0 ]; then print_list "Warnings" "${WARNINGS[@]}"; else printf 'Warnings (0):\n'; fi
    printf '\nNext steps:\n'
    printf '  1. Keep this SSH session open; open a SECOND session to verify login works.\n'
    printf '  2. Check: ufw status verbose, fail2ban-client status sshd, auditctl -s.\n'
    printf '  3. Log out/in as the target user so ~/.bashrc PATH takes effect.\n'
    printf '  4. Verify agent skills landed: ls ~/.agents/skills (OpenCode reads it as a global source).\n'
    if [ "$DRY_RUN" -eq 1 ]; then
        printf 'DRY-RUN: no changes were made.\n'
    else
        printf 'Backups under %s\n' "$BACKUP_ROOT"
    fi
}

main "$@"
