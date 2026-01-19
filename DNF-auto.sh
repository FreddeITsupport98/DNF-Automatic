#!/bin/sh
#
# Auto-reexec under bash if not already running under bash, so that the rest
# of this script can rely on bash-specific features (arrays, [[, etc.), even
# when invoked as "sh DNF-auto.sh".
if [ -z "${BASH_VERSION:-}" ]; then
    exec /usr/bin/env bash "$0" "$@"
fi

#       VERSION 59 - Fedora/DNF polish, scripted uninstaller, external config, and hardening
# This script installs the DNF auto-helper with a safe uninstaller,
# an external configuration file, and improved systemd hardening.
# It replaces 'sudo' with 'pkexec' in the Python script so dnf refresh/preview
# can run under Polkit without spurious password prompts or failures.
#
# MUST be run with sudo or as root.

# --- 1. Strict Mode & Config ---
set -euo pipefail

# --- Logging / Configuration Defaults ---
LOG_DIR="/var/log/dnf-auto"
LOG_FILE="${LOG_DIR}/install-$(date +%Y%m%d-%H%M%S).log"
STATUS_FILE="${LOG_DIR}/last-status.txt"
MAX_LOG_FILES=10  # Keep only the last 10 log files (overridable via /etc/dnf-auto.conf)
MAX_LOG_SIZE_MB=50  # Maximum size for a single log file in MB (overridable)

# Accumulator for any configuration warnings so we can surface them
# once at the end of installation.
CONFIG_WARNINGS=()

# Timer intervals (in minutes) for downloader and notifier (1,5,10,15,30,60)
DL_TIMER_INTERVAL_MINUTES=1
NT_TIMER_INTERVAL_MINUTES=1

# Global config file (optional but recommended for advanced users)
CONFIG_FILE="/etc/dnf-auto.conf"

# Feature toggles (may be overridden by CONFIG_FILE)
ENABLE_FLATPAK_UPDATES="true"
ENABLE_SNAP_UPDATES="true"
ENABLE_SOAR_UPDATES="true"
ENABLE_BREW_UPDATES="true"
ENABLE_PIPX_UPDATES="true"  # new: pipx-based Python CLI updates

# Notifier cache / snooze defaults (also overridable via CONFIG_FILE)
CACHE_EXPIRY_MINUTES="10"
SNOOZE_SHORT_HOURS="1"   # used by the "1h" snooze button
SNOOZE_MEDIUM_HOURS="4"  # used by the "4h" snooze button
SNOOZE_LONG_HOURS="24"   # used by the "1d" snooze button

# Create log directory
mkdir -p "${LOG_DIR}"
chmod 755 "${LOG_DIR}"

# Cleanup old log files (keep only the last MAX_LOG_FILES)
cleanup_old_logs() {
    log_debug "Cleaning up old log files in ${LOG_DIR}..."
    
    # Count install log files
    local log_count=$(find "${LOG_DIR}" -name "install-*.log" 2>/dev/null | wc -l)
    
    if [ "$log_count" -gt "$MAX_LOG_FILES" ]; then
        log_info "Found $log_count log files, removing oldest to keep only $MAX_LOG_FILES"
        find "${LOG_DIR}" -name "install-*.log" -type f -printf '%T+ %p\n' | \
            sort | head -n -"$MAX_LOG_FILES" | cut -d' ' -f2- | \
            while read -r old_log; do
                log_debug "Removing old log: $old_log"
                rm -f "$old_log"
            done
        log_success "Old logs cleaned up"
    else
        log_debug "Log count ($log_count) is within limit ($MAX_LOG_FILES)"
    fi
    
    # Also cleanup service logs that are too large
    if [ -d "${LOG_DIR}/service-logs" ]; then
        find "${LOG_DIR}/service-logs" -name "*.log" -type f -size +"${MAX_LOG_SIZE_MB}M" | \
            while read -r large_log; do
                log_info "Rotating large log file: $large_log"
                mv "$large_log" "${large_log}.old"
                touch "$large_log"
            done
    fi
}

# Initialize log file
echo "==============================================" | tee "${LOG_FILE}"
echo "DNF Auto-Helper Installation Log" | tee -a "${LOG_FILE}"
echo "Started: $(date)" | tee -a "${LOG_FILE}"
echo "Log file: ${LOG_FILE}" | tee -a "${LOG_FILE}"
echo "==============================================" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"

# Logging functions
log_info() {
    echo "[INFO] $(date '+%H:%M:%S') $*" | tee -a "${LOG_FILE}"
}

log_success() {
    echo "[SUCCESS] $(date '+%H:%M:%S') $*" | tee -a "${LOG_FILE}"
}

log_error() {
    echo "[ERROR] $(date '+%H:%M:%S') $*" | tee -a "${LOG_FILE}" >&2
}

log_debug() {
    echo "[DEBUG] $(date '+%H:%M:%S') $*" | tee -a "${LOG_FILE}"
}

log_command() {
    local cmd="$*"
    log_debug "Executing: $cmd"
    if eval "$cmd" >> "${LOG_FILE}" 2>&1; then
        log_success "Command succeeded: $cmd"
        return 0
    else
        local exit_code=$?
        log_error "Command failed (exit code $exit_code): $cmd"
        return $exit_code
    fi
}

# Load external configuration if present, otherwise create a default template.
load_config() {
    if [ -f "${CONFIG_FILE}" ]; then
        log_info "Loading configuration from ${CONFIG_FILE}"
# shellcheck source=/etc/dnf-auto.conf
        . "${CONFIG_FILE}"
    else
        log_info "No configuration found at ${CONFIG_FILE}; generating default config"
        cat > "${CONFIG_FILE}" << 'EOF'
# dnf-auto-helper configuration
#
# All values in this file are read by the installer at runtime. You can
# safely edit them and re-run:
#   sudo ./DNF-auto.sh install
# to apply changes. Invalid values fall back to safe defaults and are
# reported in the install log and last-status.txt.
#
# Boolean flags must be "true" or "false" (case-insensitive).

# ---------------------------------------------------------------------
# Post-update helpers (run AFTER a manual "sudo dnf upgrade")
# ---------------------------------------------------------------------

# ENABLE_FLATPAK_UPDATES
# If true, run "pkexec flatpak update -y" after a successful dnf upgrade
# so Flatpak apps/runtimes are upgraded together with system packages.
ENABLE_FLATPAK_UPDATES=true

# ENABLE_SNAP_UPDATES
# If true, run "pkexec snap refresh" after a system upgrade so Snap
# packages are refreshed along with the system. Requires snapd to be
# installed.
ENABLE_SNAP_UPDATES=true

# ENABLE_SOAR_UPDATES
# If true and "soar" is installed, check GitHub for the latest *stable*
# Soar release, update if a newer version exists, then run "soar sync"
# and "soar update" to refresh Soar-managed applications.
ENABLE_SOAR_UPDATES=true

# ENABLE_BREW_UPDATES
# If true and Homebrew is installed, run "brew update" followed by
# "brew outdated --quiet" and "brew upgrade" when there are outdated
# formulae. When false, Homebrew is left entirely to the user.
ENABLE_BREW_UPDATES=true

# ENABLE_PIPX_UPDATES
# If true and pipx is installed for the user, run "pipx upgrade-all"
# after a dnf-based system upgrade so that Python command-line tools
# (yt-dlp, black, ansible, httpie, etc.) are upgraded in their isolated
# environments. When false, pipx-based tools are left entirely to the
# user.
ENABLE_PIPX_UPDATES=true

# ---------------------------------------------------------------------
# Timer intervals for downloader / notifier / verification
# ---------------------------------------------------------------------

# DL_TIMER_INTERVAL_MINUTES
# How often (in minutes) the *root* downloader (dnf-autodownload.timer)
# should run. Allowed values (MUST be one of these exact integers):
#   1,5,10,15,30,60
#   1  = every minute (minutely)
#   5  = every 5 minutes
#   10 = every 10 minutes
#   15 = every 15 minutes
#   30 = every 30 minutes
#   60 = every hour (hourly)
# Any other value is treated as invalid and will be reset to a safe default.
DL_TIMER_INTERVAL_MINUTES=1

# NT_TIMER_INTERVAL_MINUTES
# How often (in minutes) the *user* notifier (dnf-notify-user.timer)
# should run to check for updates and send notifications.
# Uses the same allowed values and rules as above (MUST be exactly one of
# 1,5,10,15,30,60; anything else falls back to a safe default).
NT_TIMER_INTERVAL_MINUTES=1

# VERIFY_TIMER_INTERVAL_MINUTES
# How often (in minutes) the verification/auto-repair timer
# (dnf-auto-verify.timer) should run.
# these exact integers): 1,5,10,15,30,60.
#   1  = every minute (minutely)
#   5  = every 5 minutes
#   10 = every 10 minutes
#   15 = every 15 minutes
#   30 = every 30 minutes
#   60 = every hour (hourly)
# Any other value is treated as invalid and will be reset to a safe default.
VERIFY_TIMER_INTERVAL_MINUTES=60

# ---------------------------------------------------------------------
# Installer log retention
# ---------------------------------------------------------------------

# MAX_LOG_FILES
# Maximum number of install-*.log files to keep under /var/log/dnf-auto.
# Older logs beyond this count are deleted automatically on each install.
MAX_LOG_FILES=10

# MAX_LOG_SIZE_MB
# Maximum size (in megabytes) for individual service logs under
# /var/log/dnf-auto/service-logs.
# *.old when they exceed this size.
MAX_LOG_SIZE_MB=50

# ---------------------------------------------------------------------
# Notifier cache and snooze behaviour
# ---------------------------------------------------------------------

# CACHE_EXPIRY_MINUTES
# The notifier caches the result of the dnf preview command to avoid
# hitting dnf too often.
# a cached result is considered valid before forcing a fresh check.
# Higher values = fewer dnf runs but potentially more stale info.
CACHE_EXPIRY_MINUTES=10

# SNOOZE_SHORT_HOURS / SNOOZE_MEDIUM_HOURS / SNOOZE_LONG_HOURS
# Durations (in hours) used by the Snooze buttons in the desktop
# notification. The labels remain "1h", "4h" and "1d", but you can
# change how long each actually snoozes notifications.
SNOOZE_SHORT_HOURS=1
SNOOZE_MEDIUM_HOURS=4
SNOOZE_LONG_HOURS=24

# ---------------------------------------------------------------------
# Package-manager lock handling and downloader behaviour
# ---------------------------------------------------------------------

# LOCK_RETRY_MAX_ATTEMPTS
# How many times the "Ready to install" helper should retry when
# another DNF/PackageKit instance holds the system management lock
# before giving up and showing a message. Each attempt waits a
# little longer than the previous one.
LOCK_RETRY_MAX_ATTEMPTS=10

# LOCK_RETRY_INITIAL_DELAY_SECONDS
# Base delay (in seconds) used for the first lock retry. Subsequent
# retries add this delay again (1,2,3,... style). Set to 0 to disable
# waiting and fail fast when the lock is held.
LOCK_RETRY_INITIAL_DELAY_SECONDS=1

# LOCK_REMINDER_ENABLED
# When "true", the user-space notifier shows a small desktop notification
# whenever DNF/PackageKit is locked by another process, and will repeat this
# reminder on each notifier run while the lock is present.
#
# When "false", lock situations are still logged to
# ~/.local/share/dnf-notify/notifier-detailed.log and reflected in
# last-run-status.txt, but no desktop popup is shown.
#
# Valid values: true / false (case-sensitive). Default: true.
LOCK_REMINDER_ENABLED=true

# NO_UPDATES_REMINDER_REPEAT_ENABLED
# When "true", the notifier may re-show identical "No updates found" messages
# on subsequent checks while the system remains fully up to date.
# When "false", the "No updates" notification is shown once per state and
# then suppressed until the update state changes.
#
# Valid values: true / false (case-sensitive). Default: true.
NO_UPDATES_REMINDER_REPEAT_ENABLED=true

# UPDATES_READY_REMINDER_REPEAT_ENABLED
# When "true", the notifier may re-show identical "Updates ready" messages
# on subsequent checks while the same snapshot / update set is still pending.
# When "false", the "Updates ready" notification is shown once per state and
# then suppressed until a new snapshot or different set of updates is detected.
#
# Valid values: true / false (case-sensitive). Default: true.
UPDATES_READY_REMINDER_REPEAT_ENABLED=true

# VERIFY_NOTIFY_USER_ENABLED
# When "true", the periodic verification/auto-repair service sends a
# desktop notification to the primary user when it detects and fixes
# at least one problem. When "false", verification still runs and logs
# repairs to /var/log/dnf-auto but does not notify on the desktop.
#
# Valid values: true / false (case-sensitive). Default: true.
VERIFY_NOTIFY_USER_ENABLED=true

# DOWNLOADER_DOWNLOAD_MODE
# Controls how the background downloader behaves (value is case-sensitive):
#   full        - (default) run a full "dnf upgrade --downloadonly" pass
#                 to prefetch all packages into the cache.
#   detect-only - only run a non-interactive preview to detect whether
#                 updates are available; no pre-download is done.
# Any other value is treated as invalid and will be reported in the
# installer log, then reset to the safe default "full".
DOWNLOADER_DOWNLOAD_MODE=full

# DUP_EXTRA_FLAGS
# Extra arguments appended to every dnf-based update invocation run by this
# helper, both for the background downloader and the notifier preview. This
# is useful for flags like "--refresh" or repo selection switches.
#
# IMPORTANT:
#   - Do NOT include "--non-interactive", "--download-only" or "--dry-run"
#     here; those are added automatically by the helper where needed.
#   - If you set multiple flags, write them exactly as you would on the
#         command line, for example:
#         DUP_EXTRA_FLAGS="--allow-vendor-change --no-allow-vendor-change"
#
# By default we include "--refresh" so every background check behaves like
# "dnf upgrade --refresh --assumeno", ensuring all enabled repositories
# are freshly consulted.
DUP_EXTRA_FLAGS="--refresh"
EOF
        # Ensure config file has safe permissions (root-writable only)
        chmod 644 "${CONFIG_FILE}" || true
# NOTE: The downloader, notifier, and verification timer schedules are
# derived from DL_TIMER_INTERVAL_MINUTES, NT_TIMER_INTERVAL_MINUTES, and
# VERIFY_TIMER_INTERVAL_MINUTES in this file. After changing these values,
# re-run:
#   sudo ./DNF-auto.sh install
# so the systemd units are regenerated with the new schedule.
    fi

    # Basic numeric validation with safe fallbacks so a broken config
    # never crashes the installer.
    validate_int() {
        local name="$1" default="$2" value
        # shellcheck disable=SC2154
        eval "value=\"\${$name:-}\""
        if ! [[ "$value" =~ ^[0-9]+$ ]] || [ "$value" -le 0 ]; then
            local msg="Invalid or missing $name='$value' in ${CONFIG_FILE}, using default $default"
            log_info "$msg"
            CONFIG_WARNINGS+=("$msg")
            eval "$name=$default"
        fi
    }

    # Basic boolean validation for true/false style flags. When the key is
    # completely unset we quietly use the default without logging a warning,
    # so older configs without newer flags do not spam the logs.
    validate_bool_flag() {
        local name="$1" default="$2" value lower
        eval "value=\"\${$name:-}\""
        if [ -z "$value" ]; then
            eval "$name=$default"
            return
        fi
        lower="${value,,}"
        case "$lower" in
            true|false)
                eval "$name=$lower"
                ;;
            *)
                local msg="Invalid $name='$value' in ${CONFIG_FILE}, using default $default"
                log_info "$msg"
                CONFIG_WARNINGS+=("$msg")
                eval "$name=$default"
                ;;
        esac
    }

    validate_int MAX_LOG_FILES 10
    validate_int MAX_LOG_SIZE_MB 50
    validate_int CACHE_EXPIRY_MINUTES 10
    validate_int SNOOZE_SHORT_HOURS 1
    validate_int SNOOZE_MEDIUM_HOURS 4
    validate_int SNOOZE_LONG_HOURS 24
    validate_int LOCK_RETRY_MAX_ATTEMPTS 10
    validate_int LOCK_RETRY_INITIAL_DELAY_SECONDS 1

    # Validate enumerated string options with safe fallbacks so typos
    # in the config are reported clearly in the log and do not break
    # the installer.
    validate_mode() {
        local name="$1" default="$2" allowed_pattern="$3" value raw_value
        eval "value=\"\${$name:-}\""
        raw_value="$value"
        # Normalise by stripping CR, surrounding whitespace, and simple outer quotes
        value="$(printf '%s' "$value" | tr -d '\r' | sed -e 's/^\s*//' -e 's/\s*$//' -e 's/^"//' -e 's/"$//')"

        # If empty after normalisation -> use default
        if [ -z "$value" ]; then
            local msg="Missing $name in ${CONFIG_FILE}, using default '$default'"
            log_info "$msg"
            CONFIG_WARNINGS+=("$msg")
            eval "$name=$default"
            return
        fi

        # Split allowed_pattern on '|' and compare literally (no globbing)
        local IFS='|'
        local allowed ok=0
        for allowed in $allowed_pattern; do
            if [ "$value" = "$allowed" ]; then
                ok=1
                break
            fi
        done

        if [ "$ok" -eq 1 ]; then
            # Valid value, store normalised form
            eval "$name=$value"
        else
            local msg="Invalid $name='$raw_value' in ${CONFIG_FILE} (allowed: $allowed_pattern); using default '$default'"
            log_info "$msg"
            CONFIG_WARNINGS+=("$msg")
            eval "$name=$default"
        fi
    }

    # Validate timer intervals (minutes) for downloader/notifier/verification:
    # allow only 1,5,10,15,30,60 minutes to keep systemd OnCalendar
    # expressions simple and predictable.
    validate_interval() {
        local name="$1" default="$2" value
        eval "value=\"\${$name:-}\""
        if ! [[ "$value" =~ ^[0-9]+$ ]]; then
            local msg="Invalid $name='$value' in ${CONFIG_FILE}, using default $default"
            log_info "$msg"
            CONFIG_WARNINGS+=("$msg")
            eval "$name=$default"
            return
        fi
        case "$value" in
            1|5|10|15|30|60) ;;
            *)
                local msg="Unsupported $name='$value' in ${CONFIG_FILE} (allowed: 1,5,10,15,30,60); using default $default"
                log_info "$msg"
                CONFIG_WARNINGS+=("$msg")
                eval "$name=$default"
                ;;
        esac
    }

    validate_interval DL_TIMER_INTERVAL_MINUTES 1
    validate_interval NT_TIMER_INTERVAL_MINUTES 1
    validate_interval VERIFY_TIMER_INTERVAL_MINUTES 60
    validate_bool_flag VERIFY_NOTIFY_USER_ENABLED true

    # Log effective configuration summary for easier diagnostics
    log_debug "Effective configuration after validation:"
    log_debug "  DL_TIMER_INTERVAL_MINUTES=${DL_TIMER_INTERVAL_MINUTES}"
    log_debug "  NT_TIMER_INTERVAL_MINUTES=${NT_TIMER_INTERVAL_MINUTES}"
    log_debug "  VERIFY_TIMER_INTERVAL_MINUTES=${VERIFY_TIMER_INTERVAL_MINUTES}"
    log_debug "  CACHE_EXPIRY_MINUTES=${CACHE_EXPIRY_MINUTES}"
    log_debug "  SNOOZE_SHORT_HOURS=${SNOOZE_SHORT_HOURS}"
    log_debug "  SNOOZE_MEDIUM_HOURS=${SNOOZE_MEDIUM_HOURS}"
    log_debug "  SNOOZE_LONG_HOURS=${SNOOZE_LONG_HOURS}"
    log_debug "  LOCK_RETRY_MAX_ATTEMPTS=${LOCK_RETRY_MAX_ATTEMPTS}"
    log_debug "  LOCK_RETRY_INITIAL_DELAY_SECONDS=${LOCK_RETRY_INITIAL_DELAY_SECONDS}"
    log_debug "  VERIFY_NOTIFY_USER_ENABLED=${VERIFY_NOTIFY_USER_ENABLED}"
    log_debug "  DOWNLOADER_DOWNLOAD_MODE=${DOWNLOADER_DOWNLOAD_MODE}"
    log_debug "  DUP_EXTRA_FLAGS=${DUP_EXTRA_FLAGS}"

    # DOWNLOADER_DOWNLOAD_MODE must be spelled exactly "full" or
    # "detect-only" (case-sensitive). Anything else is reported as
    # invalid and reset to the safe default "full".
    validate_mode DOWNLOADER_DOWNLOAD_MODE full "full|detect-only"

    # Detect older/stale config files that are missing newer keys.
    # We do NOT overwrite the config automatically; instead we collect
    # warnings and suggest using the reset helper so the user can
# consciously regenerate `/etc/dnf-auto.conf`.
    local missing_keys=()

    # Helper: record a key as missing if it is not defined at all.
    _mark_missing_key() {
        local key="$1"
        if [ -z "${!key+x}" ]; then
            missing_keys+=("$key")
        fi
    }

    # Keys introduced in newer versions that we depend on for full
    # functionality. Add new ones here as the project evolves.
    _mark_missing_key "DUP_EXTRA_FLAGS"
    _mark_missing_key "LOCK_RETRY_MAX_ATTEMPTS"
    _mark_missing_key "LOCK_RETRY_INITIAL_DELAY_SECONDS"
    _mark_missing_key "DOWNLOADER_DOWNLOAD_MODE"
    _mark_missing_key "LOCK_REMINDER_ENABLED"
    _mark_missing_key "NO_UPDATES_REMINDER_REPEAT_ENABLED"
    _mark_missing_key "UPDATES_READY_REMINDER_REPEAT_ENABLED"

    if [ "${#missing_keys[@]}" -gt 0 ]; then
        local keys_joined
        keys_joined="${missing_keys[*]}"
        local msg
            msg="${CONFIG_FILE} appears to be from an older version (missing keys: ${keys_joined}). Run 'sudo dnf-auto-helper --reset-config' to regenerate it with the latest options."
        log_info "$msg"
        CONFIG_WARNINGS+=("$msg")

        # Log a short, per-key feature description so the user knows
        # what functionality is affected.
        log_info "Missing configuration keys and related features:"
        for key in "${missing_keys[@]}"; do
            case "$key" in
                DUP_EXTRA_FLAGS)
                    log_info "  - DUP_EXTRA_FLAGS: controls extra flags added to every 'dnf upgrade' run (background downloader and notifier), e.g. --allow-vendor-change."
                    ;;
                LOCK_RETRY_MAX_ATTEMPTS)
                    log_info "  - LOCK_RETRY_MAX_ATTEMPTS: how many times the Ready-to-Install helper retries when the package manager is locked before giving up."
                    ;;
                LOCK_RETRY_INITIAL_DELAY_SECONDS)
                    log_info "  - LOCK_RETRY_INITIAL_DELAY_SECONDS: base delay (in seconds) between lock retries for the Ready-to-Install helper."
                    ;;
                DOWNLOADER_DOWNLOAD_MODE)
                    log_info "  - DOWNLOADER_DOWNLOAD_MODE: controls whether the background helper only detects updates (detect-only) or also pre-downloads them (full)."
                    ;;
                *)
                    log_info "  - ${key}: (no description available)"
                    ;;
            esac
        done

        # Provide safe defaults for keys we rely on at runtime so the
        # installer and services do not break even with a stale config.
        for key in "${missing_keys[@]}"; do
            case "$key" in
                DUP_EXTRA_FLAGS)
                    # Match template default: always refresh repositories
                    DUP_EXTRA_FLAGS="--refresh"
                    ;;
                LOCK_RETRY_MAX_ATTEMPTS)
                    LOCK_RETRY_MAX_ATTEMPTS=10
                    ;;
                LOCK_RETRY_INITIAL_DELAY_SECONDS)
                    LOCK_RETRY_INITIAL_DELAY_SECONDS=1
                    ;;
                DOWNLOADER_DOWNLOAD_MODE)
                    DOWNLOADER_DOWNLOAD_MODE="full"
                    ;;
            esac
        done
    fi
}

# Status update function
update_status() {
    local status="$1"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $status" | tee "${STATUS_FILE}" | tee -a "${LOG_FILE}"
}

# Trap errors and log them
trap 'log_error "Script failed at line $LINENO with exit code $?"; update_status "FAILED: Installation encountered an error at line $LINENO"; exit 1' ERR

# --- Root/System Service Config ---
DL_SERVICE_NAME="dnf-autodownload"
DL_SERVICE_FILE="/etc/systemd/system/${DL_SERVICE_NAME}.service"
DL_TIMER_FILE="/etc/systemd/system/${DL_SERVICE_NAME}.timer"

CLEANUP_SERVICE_NAME="dnf-cache-cleanup"
CLEANUP_SERVICE_FILE="/etc/systemd/system/${CLEANUP_SERVICE_NAME}.service"
CLEANUP_TIMER_FILE="/etc/systemd/system/${CLEANUP_SERVICE_NAME}.timer"

# Periodic verification / auto-repair service (root)
VERIFY_SERVICE_NAME="dnf-auto-verify"
VERIFY_SERVICE_FILE="/etc/systemd/system/${VERIFY_SERVICE_NAME}.service"
VERIFY_TIMER_FILE="/etc/systemd/system/${VERIFY_SERVICE_NAME}.timer"

# --- User Service Config ---
NT_SERVICE_NAME="dnf-notify-user"
NT_SCRIPT_NAME="dnf-notify-updater.py"
INSTALL_SCRIPT_NAME="dnf-run-install"
VIEW_CHANGES_SCRIPT_NAME="dnf-view-changes"

# --- 2. Sanity Checks & User Detection ---
update_status "Running sanity checks..."
log_info ">>> Running Sanity Checks..."
log_debug "EUID: $EUID"

if [ "$EUID" -ne 0 ]; then
  log_error "This script must be run with sudo or as root."
  update_status "FAILED: Script not run as root"
  exit 1
fi
log_success "Root privileges confirmed"

# Load configuration now that we have root privileges (for /etc writes)
load_config

if [ -z "${SUDO_USER:-}" ]; then
    log_error "Could not detect the user. Please run with 'sudo', not as pure root."
    update_status "FAILED: SUDO_USER not detected"
    exit 1
fi
log_success "Detected user: $SUDO_USER"

SUDO_USER_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
log_debug "User home directory: $SUDO_USER_HOME"

if [ ! -d "$SUDO_USER_HOME" ]; then
    log_error "Could not find home directory for user $SUDO_USER."
    update_status "FAILED: User home directory not found"
    exit 1
fi
log_success "User home directory found: $SUDO_USER_HOME"

# Define user-level paths
USER_CONFIG_DIR="$SUDO_USER_HOME/.config/systemd/user"
USER_BIN_DIR="$SUDO_USER_HOME/.local/bin"
NT_SERVICE_FILE="$USER_CONFIG_DIR/${NT_SERVICE_NAME}.service"
NT_TIMER_FILE="$USER_CONFIG_DIR/${NT_SERVICE_NAME}.timer"
NOTIFY_SCRIPT_PATH="$USER_BIN_DIR/${NT_SCRIPT_NAME}"
INSTALL_SCRIPT_PATH="$USER_BIN_DIR/${INSTALL_SCRIPT_NAME}"
VIEW_CHANGES_SCRIPT_PATH="$USER_BIN_DIR/${VIEW_CHANGES_SCRIPT_NAME}"

# --- Helper: Self-check syntax for this script and the notifier ---
run_self_check() {
    log_info ">>> Running self-check (syntax)..."
    update_status "Running syntax checks..."

    # Check bash syntax of this installer
    log_debug "Checking bash syntax of $0"
    if ! bash -n "$0" >> "${LOG_FILE}" 2>&1; then
        log_error "Self-check FAILED: bash syntax error in $0"
        update_status "FAILED: Bash syntax error in installer script"
        exit 1
    fi
    log_success "Bash syntax check passed for installer"

    # Check Python notifier syntax if it already exists
    if [ -f "$NOTIFY_SCRIPT_PATH" ]; then
        log_debug "Checking Python syntax of $NOTIFY_SCRIPT_PATH"
        if ! python3 -m py_compile "$NOTIFY_SCRIPT_PATH" >> "${LOG_FILE}" 2>&1; then
            log_error "Self-check FAILED: Python syntax error in $NOTIFY_SCRIPT_PATH"
            update_status "FAILED: Python syntax error in notifier script"
            exit 1
        fi
        log_success "Python syntax check passed for notifier"
    else
        log_info "Python notifier $NOTIFY_SCRIPT_PATH not found yet (first install?)"
    fi

    log_success "Self-check passed"
    update_status "Syntax checks completed successfully"
}

# --- Function: Run Verification (used by both install and --verify modes) ---
run_verification_only() {
    # This function contains all the verification logic
    # It can be called standalone or as part of installation
    
    VERIFICATION_FAILED=0
    REPAIR_ATTEMPTS=0
    MAX_REPAIR_ATTEMPTS=3
    
    log_info ">>> Running advanced installation verification and auto-repair..."
    update_status "Verifying installation..."

# Helper function for advanced repair with retry logic
attempt_repair() {
    local check_name="$1"
    local repair_command="$2"
    local verify_command="$3"
    local max_attempts="${4:-2}"

    # Before attempting any repair, clear potential "failed" states on
    # the core units we manage so systemd is willing to restart them.
    # This is safe to run even when we're repairing something else.
    systemctl reset-failed "${DL_SERVICE_NAME}.service" "${DL_SERVICE_NAME}.timer" \
        >> "${LOG_FILE}" 2>&1 || true
    if [ -n "${SUDO_USER:-}" ] && [ -n "${USER_BUS_PATH:-}" ]; then
        sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" \
            systemctl --user reset-failed \
                "${NT_SERVICE_NAME}.service" "${NT_SERVICE_NAME}.timer" \
                >> "${LOG_FILE}" 2>&1 || true
    fi

    REPAIR_ATTEMPTS=$((REPAIR_ATTEMPTS + 1))  # Track that we're attempting a repair

    for i in $(seq 1 $max_attempts); do
        log_info "  → Repair attempt $i/$max_attempts: $check_name"
        if eval "$repair_command" >> "${LOG_FILE}" 2>&1; then
            sleep 0.5  # Brief pause for system to stabilize
            if eval "$verify_command" &>/dev/null; then
                log_success "  ✓ Repaired successfully on attempt $i"
                return 0
            fi
        fi
    done
    log_error "  ✗ Failed to repair after $max_attempts attempts"
    return 1
}

# Check 1: System service is active and healthy
log_debug "[1/12] Checking system downloader service..."
if systemctl is-active "${DL_SERVICE_NAME}.timer" &>/dev/null; then
    # Additional health check: verify it's enabled
    if systemctl is-enabled "${DL_SERVICE_NAME}.timer" &>/dev/null; then
        log_success "✓ System downloader timer is active and enabled"
    else
        log_error "✗ System downloader timer is active but NOT enabled (won't survive reboot)"
        if attempt_repair "enable timer for persistence" \
            "systemctl unmask ${DL_SERVICE_NAME}.timer >/dev/null 2>&1 || true; systemctl enable ${DL_SERVICE_NAME}.timer" \
            "systemctl is-enabled ${DL_SERVICE_NAME}.timer"; then
            log_success "  ✓ Timer is now enabled for persistence"
        else
            VERIFICATION_FAILED=1
        fi
    fi
else
    log_error "✗ System downloader timer is NOT active"
    # Try comprehensive repair (including unmask in case the unit was masked)
    if attempt_repair "restart system downloader" \
        "systemctl unmask ${DL_SERVICE_NAME}.timer >/dev/null 2>&1 || true; systemctl daemon-reload && systemctl enable --now ${DL_SERVICE_NAME}.timer" \
        "systemctl is-active ${DL_SERVICE_NAME}.timer" 3; then
        log_success "  ✓ System downloader timer repaired"
    else
        log_error "  → Attempting nuclear option: recreating service files..."
        # Service file should exist from earlier in install, but verify
        if [ ! -f "${DL_SERVICE_FILE}" ] || [ ! -f "${DL_TIMER_FILE}" ]; then
            log_error "  ✗ CRITICAL: Service files missing - installation may have failed"
            VERIFICATION_FAILED=1
        else
            systemctl daemon-reload >> "${LOG_FILE}" 2>&1
            systemctl enable --now "${DL_SERVICE_NAME}.timer" >> "${LOG_FILE}" 2>&1
            sleep 1
            if systemctl is-active "${DL_SERVICE_NAME}.timer" &>/dev/null; then
                log_success "  ✓ Nuclear repair successful"
            else
                log_error "  ✗ CRITICAL: Cannot start system timer - check permissions"
                VERIFICATION_FAILED=1
            fi
        fi
    fi
fi

# Check 2: User service is active and healthy
log_debug "[2/12] Checking user notifier service..."
if sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user is-active "${NT_SERVICE_NAME}.timer" &>/dev/null; then
    # Check if enabled
    if sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user is-enabled "${NT_SERVICE_NAME}.timer" &>/dev/null; then
        log_success "✓ User notifier timer is active and enabled"
        # Deep health check: verify it's actually triggering
        NEXT_TRIGGER=$(sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user list-timers "${NT_SERVICE_NAME}.timer" 2>/dev/null | grep -o "left" || echo "")
        if [ -n "$NEXT_TRIGGER" ]; then
            log_success "  ✓ Timer has upcoming triggers scheduled"
        else
            log_error "  ⚠ Warning: Timer is active but no triggers scheduled"
            log_info "  → Restarting to reset trigger schedule..."
            sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user restart "${NT_SERVICE_NAME}.timer" >> "${LOG_FILE}" 2>&1
        fi
    else
        log_error "✗ User timer is active but NOT enabled"
        if attempt_repair "enable user timer" \
            "sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS=$USER_BUS_PATH systemctl --user unmask ${NT_SERVICE_NAME}.timer >/dev/null 2>&1 || true; sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS=$USER_BUS_PATH systemctl --user enable ${NT_SERVICE_NAME}.timer" \
            "sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS=$USER_BUS_PATH systemctl --user is-enabled ${NT_SERVICE_NAME}.timer"; then
            log_success "  ✓ User timer enabled"
        else
            VERIFICATION_FAILED=1
        fi
    fi
else
    log_error "✗ User notifier timer is NOT active"
    # Multi-stage repair process
    log_info "  → Stage 1: Daemon reload and restart..."
    if attempt_repair "restart user service" \
        "sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS=$USER_BUS_PATH systemctl --user unmask ${NT_SERVICE_NAME}.timer >/dev/null 2>&1 || true; sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS=$USER_BUS_PATH systemctl --user daemon-reload && sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS=$USER_BUS_PATH systemctl --user enable --now ${NT_SERVICE_NAME}.timer" \
        "sudo -u $SUDO_USER DBUS_SESSION_BUS_ADDRESS=$USER_BUS_PATH systemctl --user is-active ${NT_SERVICE_NAME}.timer" 3; then
        log_success "  ✓ User notifier timer repaired"
    else
        log_error "  → Stage 2: Checking for service file corruption..."
        if [ ! -f "${NT_SERVICE_FILE}" ] || [ ! -f "${NT_TIMER_FILE}" ]; then
            log_error "  ✗ CRITICAL: User service files missing"
            VERIFICATION_FAILED=1
        else
            # Check file permissions
            if [ ! -r "${NT_SERVICE_FILE}" ] || [ ! -r "${NT_TIMER_FILE}" ]; then
                log_error "  ⚠ Service files have wrong permissions"
                chown "$SUDO_USER:$SUDO_USER" "${NT_SERVICE_FILE}" "${NT_TIMER_FILE}" >> "${LOG_FILE}" 2>&1
                chmod 644 "${NT_SERVICE_FILE}" "${NT_TIMER_FILE}" >> "${LOG_FILE}" 2>&1
            fi
            
            # Final attempt
            log_info "  → Stage 3: Nuclear option - full service reset..."
            sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user stop "${NT_SERVICE_NAME}.timer" >> "${LOG_FILE}" 2>&1 || true
            sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user disable "${NT_SERVICE_NAME}.timer" >> "${LOG_FILE}" 2>&1 || true
            sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user unmask "${NT_SERVICE_NAME}.timer" >> "${LOG_FILE}" 2>&1 || true
            sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user daemon-reload >> "${LOG_FILE}" 2>&1
            sleep 1
            sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user enable --now "${NT_SERVICE_NAME}.timer" >> "${LOG_FILE}" 2>&1
            sleep 1
            
            if sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user is-active "${NT_SERVICE_NAME}.timer" &>/dev/null; then
                log_success "  ✓ Nuclear repair successful - user timer now active"
            else
                log_error "  ✗ CRITICAL: All repair attempts failed"
                log_error "  → This may indicate a DBUS or systemd user session issue"
                log_info "  → Try: loginctl enable-linger $SUDO_USER"
                VERIFICATION_FAILED=1
            fi
        fi
    fi
fi

# Check 3: Python script exists and is executable
log_debug "Checking Python notifier script..."
if [ -x "${NOTIFY_SCRIPT_PATH}" ]; then
    log_success "✓ Python notifier script is executable"
    # Check Python syntax
    if python3 -m py_compile "${NOTIFY_SCRIPT_PATH}" &>/dev/null; then
        log_success "✓ Python script syntax is valid"
    else
        log_error "✗ Python script has syntax errors"
        log_error "  → Cannot auto-fix: syntax errors require manual intervention"
        VERIFICATION_FAILED=1
    fi
else
    log_error "✗ Python notifier script is missing or not executable"
    if [ -f "${NOTIFY_SCRIPT_PATH}" ]; then
        log_info "  → Attempting to fix: making script executable..."
        chmod +x "${NOTIFY_SCRIPT_PATH}" >> "${LOG_FILE}" 2>&1
        chown "$SUDO_USER:$SUDO_USER" "${NOTIFY_SCRIPT_PATH}" >> "${LOG_FILE}" 2>&1
        if [ -x "${NOTIFY_SCRIPT_PATH}" ]; then
            log_success "  ✓ Fixed: Python script is now executable"
        else
            log_error "  ✗ Failed to make Python script executable"
            VERIFICATION_FAILED=1
        fi
    else
        log_error "  → Cannot auto-fix: file is completely missing"
        VERIFICATION_FAILED=1
    fi
fi

# Check 4: Downloader script exists and is executable
log_debug "Checking downloader script..."
if [ -x "$DOWNLOADER_SCRIPT" ]; then
    log_success "✓ Downloader script is executable"
    # Check bash syntax
    if bash -n "$DOWNLOADER_SCRIPT" &>/dev/null; then
        log_success "✓ Downloader script syntax is valid"
    else
        log_error "✗ Downloader script has syntax errors"
        VERIFICATION_FAILED=1
    fi
else
    log_error "✗ Downloader script is missing or not executable"
    VERIFICATION_FAILED=1
fi

# Check 5: Shell wrapper exists
log_debug "Checking dnf wrapper script..."
if [ -x "$DNF_WRAPPER_PATH" ]; then
    log_success "✓ DNF wrapper script is executable"
else
    log_error "✗ DNF wrapper script is missing or not executable"
    VERIFICATION_FAILED=1
fi

# Check 6: Fish shell integration (if Fish is installed)
if [ -d "$SUDO_USER_HOME/.config/fish" ]; then
    log_debug "Checking Fish shell integration..."
    if [ -f "$SUDO_USER_HOME/.config/fish/conf.d/dnf-wrapper.fish" ]; then
        log_success "✓ Fish shell wrapper is installed"
    else
        log_error "✗ Fish shell wrapper is missing"
        VERIFICATION_FAILED=1
    fi
fi

# Check 7: No old Python processes running
log_debug "Checking for stale Python processes..."
if pgrep -f "dnf-notify-updater.py" &>/dev/null; then
    PROCESS_COUNT=$(pgrep -f "dnf-notify-updater.py" | wc -l)
    if [ $PROCESS_COUNT -gt 1 ]; then
        log_error "⚠ Warning: $PROCESS_COUNT Python notifier processes running (expected 0-1)"
        log_info "  → Attempting to fix: killing stale processes..."
        pkill -9 -f "dnf-notify-updater.py" >> "${LOG_FILE}" 2>&1
        sleep 1
        if pgrep -f "dnf-notify-updater.py" &>/dev/null; then
            NEW_COUNT=$(pgrep -f "dnf-notify-updater.py" | wc -l)
            log_info "  ✓ Fixed: Reduced to $NEW_COUNT process(es)"
        else
            log_success "  ✓ Fixed: All stale processes killed"
        fi
    else
        log_success "✓ Python notifier process count is normal"
    fi
else
    log_success "✓ No stale Python processes detected"
fi

# Check 8: Python bytecode cache is clear
log_debug "Checking Python bytecode cache..."
if find "$SUDO_USER_HOME/.local/bin" -name "*.pyc" -o -name "__pycache__" 2>/dev/null | grep -q .; then
    log_error "⚠ Warning: Python bytecode cache exists (may cause issues)"
    log_info "  → Attempting to fix: clearing bytecode cache..."
    find "$SUDO_USER_HOME/.local/bin" -name "*.pyc" -delete >> "${LOG_FILE}" 2>&1
    find "$SUDO_USER_HOME/.local/bin" -type d -name "__pycache__" -exec rm -rf {} + >> "${LOG_FILE}" 2>&1 || true
    if find "$SUDO_USER_HOME/.local/bin" -name "*.pyc" -o -name "__pycache__" 2>/dev/null | grep -q .; then
        log_error "  ✗ Failed to clear bytecode cache completely"
    else
        log_success "  ✓ Fixed: Python bytecode cache cleared"
    fi
else
    log_success "✓ Python bytecode cache is clean"
fi

# Check 9: Log directories exist
log_debug "Checking log directories..."
if [ -d "${LOG_DIR}" ] && [ -d "${USER_LOG_DIR}" ]; then
    log_success "✓ Log directories exist"
else
    log_error "✗ Log directories are missing"
    VERIFICATION_FAILED=1
fi

# Check 10: Status file exists
log_debug "Checking status file..."
if [ -f "/var/log/dnf-auto/download-status.txt" ]; then
    CURRENT_STATUS=$(cat /var/log/dnf-auto/download-status.txt)
    log_success "✓ Status file exists (current: $CURRENT_STATUS)"
else
    log_info "ℹ Status file will be created on first run"
fi

# Check 11: Stale DNF/RPM lock cleanup
log_debug "[11/12] Checking for stale DNF/RPM lock files..."

# Check dnf.pid for stale locks
if [ -f "/var/run/dnf.pid" ] || [ -f "/run/dnf.pid" ]; then
    DNF_LOCK_FILE="/var/run/dnf.pid"
    [ -f "/run/dnf.pid" ] && DNF_LOCK_FILE="/run/dnf.pid"
    DNF_LOCK_PID=$(cat "$DNF_LOCK_FILE" 2>/dev/null || echo "")
    if [ -n "$DNF_LOCK_PID" ]; then
        if ! kill -0 "$DNF_LOCK_PID" 2>/dev/null; then
            log_error "⚠ Warning: Found stale dnf lock at $DNF_LOCK_FILE (PID $DNF_LOCK_PID is not running)"
            log_info "  → Attempting to remove stale lock file..."
            if rm -f "$DNF_LOCK_FILE" >> "${LOG_FILE}" 2>&1; then
                log_success "  ✓ Removed stale dnf lock file"
            else
                log_error "  ✗ Failed to remove stale dnf lock file"
                VERIFICATION_FAILED=1
            fi
        else
            log_debug "  → dnf lock PID $DNF_LOCK_PID is alive; leaving lock in place"
        fi
    fi
else
    log_debug "No dnf lock file present"
fi

# Check RPM database lock as well (may indicate another package tool is active)
if [ -f "/var/lib/rpm/.rpm.lock" ] && command -v fuser >/dev/null 2>&1; then
    if ! fuser "/var/lib/rpm/.rpm.lock" >/dev/null 2>&1; then
        log_debug "RPM lock file exists but no active owner detected"
    else
        log_debug "RPM lock file is currently held by another process; leaving it in place"
    fi
fi

# Check 12: Root filesystem free space and cleanup
log_debug "[12/12] Checking root filesystem free space..."
ROOT_FREE_MB=$(df -Pm / 2>/dev/null | awk 'NR==2 {print $4}')
if [ -n "$ROOT_FREE_MB" ] && [ "$ROOT_FREE_MB" -lt 1024 ]; then
    log_error "⚠ Warning: Low free space on / (only ${ROOT_FREE_MB}MB available; minimum 1024MB recommended)"
    log_info "  → Attempting to free space with 'dnf clean all'..."
    if dnf clean all >> "${LOG_FILE}" 2>&1; then
        sleep 1
        ROOT_FREE_MB_AFTER=$(df -Pm / 2>/dev/null | awk 'NR==2 {print $4}')
        if [ -n "$ROOT_FREE_MB_AFTER" ] && [ "$ROOT_FREE_MB_AFTER" -ge 1024 ]; then
            log_success "  ✓ Free space after cleanup: ${ROOT_FREE_MB_AFTER}MB (>= 1024MB)"
        else
            log_error "  ✗ Still low on space after cleanup (currently ${ROOT_FREE_MB_AFTER:-unknown}MB)"
            VERIFICATION_FAILED=1
        fi
    else
        log_error "  ✗ 'dnf clean all' failed; please free space manually"
        VERIFICATION_FAILED=1
    fi
else
    log_success "✓ Root filesystem has sufficient free space (${ROOT_FREE_MB:-unknown}MB)"
fi

# Calculate repair statistics
PROBLEMS_FOUND=$REPAIR_ATTEMPTS
PROBLEMS_FIXED=$((REPAIR_ATTEMPTS - VERIFICATION_FAILED))

echo "" | tee -a "${LOG_FILE}"
echo "==============================================" | tee -a "${LOG_FILE}"
echo "Verification Summary:" | tee -a "${LOG_FILE}"
echo "  - Checks performed: 12" | tee -a "${LOG_FILE}"
echo "  - Problems detected: $PROBLEMS_FOUND" | tee -a "${LOG_FILE}"
echo "  - Problems auto-fixed: $PROBLEMS_FIXED" | tee -a "${LOG_FILE}"
echo "  - Remaining issues: $VERIFICATION_FAILED" | tee -a "${LOG_FILE}"
echo "==============================================" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"

if [ $VERIFICATION_FAILED -eq 0 ]; then
    log_success ">>> All verification checks passed! ✓"
    if [ $PROBLEMS_FOUND -gt 0 ]; then
        log_success "  ✓ Auto-repair fixed $PROBLEMS_FIXED issue(s)"
    fi
else
    log_error ">>> $VERIFICATION_FAILED verification check(s) failed!"
    log_error "  → Auto-repair attempted but could not fix all issues"
    log_info "  → Review logs: ${LOG_FILE}"
    if [ "${#CONFIG_WARNINGS[@]}" -gt 0 ] 2>/dev/null; then
        log_info "  → Config warnings detected; consider: sudo dnf-auto-helper --reset-config"
    fi
    log_info "  → Common fixes:"
    log_info "     - Check systemd permissions: sudo loginctl enable-linger $SUDO_USER"
    log_info "     - Verify DBUS session: echo \$DBUS_SESSION_BUS_ADDRESS"
    log_info "     - Re-run installation: sudo $0 install"
fi
echo "" | tee -a "${LOG_FILE}"

# Optionally notify the primary user when auto-repair fixed issues.
# This is primarily intended for the periodic dnf-auto-verify.timer
# service, but also applies when --verify is run manually.
if [ "$PROBLEMS_FIXED" -gt 0 ] && [[ "${VERIFY_NOTIFY_USER_ENABLED,,}" == "true" ]]; then
    if command -v notify-send >/dev/null 2>&1; then
        local summary details
        summary="Fixed ${PROBLEMS_FIXED} issue(s) with the update system"
        if [ "$VERIFICATION_FAILED" -gt 0 ]; then
            details="Some issues remain; see ${LOG_FILE} for details."
        else
            details="All detected issues were repaired successfully."
        fi

        if [ -n "${SUDO_USER:-}" ] && [ -n "${USER_BUS_PATH:-}" ]; then
            sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" \
                notify-send -u normal -t 15000 \
                -i "dialog-information" \
                "${summary}" "${details}" \
                >> "${LOG_FILE}" 2>&1 || true
        fi
    fi
fi

    # Return exit code based on verification results
    return $VERIFICATION_FAILED
}

# --- Helper: Config reset mode (CLI) ---
run_reset_config_only() {
    log_info ">>> Resetting dnf-auto-helper configuration to defaults..."

    echo "" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "  dnf-auto-helper Config Reset" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "This will replace ${CONFIG_FILE} with a fresh default configuration" | tee -a "${LOG_FILE}"
    echo "while keeping a timestamped backup copy alongside it." | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"

    read -p "Are you sure you want to reset ${CONFIG_FILE} to defaults? [y/N]: " -r CONFIRM
    echo
    if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
        log_info "Config reset aborted by user. No changes made."
        update_status "ABORTED: Config reset cancelled by user"
        return 0
    fi

    # Backup existing config if present
    if [ -f "${CONFIG_FILE}" ]; then
        TS="$(date +%Y%m%d-%H%M%S)"
        BACKUP="${CONFIG_FILE}.bak-${TS}"
        if cp -f "${CONFIG_FILE}" "${BACKUP}" >> "${LOG_FILE}" 2>&1; then
            log_info "Backed up existing config to ${BACKUP}"
        else
            log_error "Failed to back up existing config to ${BACKUP} (continuing)"
        fi
    fi

    # Rewrite a fresh default config by removing it and letting load_config
    # regenerate the template.
    rm -f "${CONFIG_FILE}" >> "${LOG_FILE}" 2>&1 || true
    load_config

    log_success "Configuration reset to defaults in ${CONFIG_FILE}"
update_status "SUCCESS: dnf-auto-helper configuration reset to defaults"

    echo "" | tee -a "${LOG_FILE}"
    echo "You can now re-run installation to apply the new settings:" | tee -a "${LOG_FILE}"
echo "  sudo ./DNF-auto.sh install" | tee -a "${LOG_FILE}"
}

# --- Helper: Soar-only installation mode (CLI) ---
run_soar_install_only() {
    log_info ">>> Soar installation helper mode..."
    update_status "Running Soar installation helper..."

    SOAR_PRESENT=0

    # Detect Soar for the target user in common locations
    if sudo -u "$SUDO_USER" command -v soar >/dev/null 2>&1; then
        SOAR_PRESENT=1
    elif [ -x "$SUDO_USER_HOME/.local/bin/soar" ]; then
        SOAR_PRESENT=1
    elif [ -d "$SUDO_USER_HOME/pkgforge" ] && \
         find "$SUDO_USER_HOME/pkgforge" -maxdepth 1 -type f -name 'soar*' -perm -u+x 2>/dev/null | grep -q .; then
        SOAR_PRESENT=1
    fi

    if [ "$SOAR_PRESENT" -eq 1 ]; then
        log_success "Soar already appears to be installed for user $SUDO_USER"
        echo "Soar appears to be installed for user $SUDO_USER." | tee -a "${LOG_FILE}"
        echo "Try: sudo -u $SUDO_USER soar --help" | tee -a "${LOG_FILE}"
        return 0
    fi

    if ! command -v curl >/dev/null 2>&1; then
        log_error "curl is required to install Soar but is not installed."
        echo "Install curl with: sudo dnf install curl" | tee -a "${LOG_FILE}"
        return 1
    fi

    SOAR_INSTALL_CMD='curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh'

    echo "" | tee -a "${LOG_FILE}"
    echo "This will run the official Soar installer as user $SUDO_USER:" | tee -a "${LOG_FILE}"
    echo "  $SOAR_INSTALL_CMD" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"

    if sudo -u "$SUDO_USER" bash -lc "$SOAR_INSTALL_CMD"; then
        log_success "Soar installation finished for user $SUDO_USER"
        echo "" | tee -a "${LOG_FILE}"
        echo "You can now run: sudo -u $SUDO_USER soar sync" | tee -a "${LOG_FILE}"
        return 0
    else
        local rc=$?
        log_error "Soar installer exited with code $rc"
        return $rc
    fi
}

# --- Helper: Uninstall core dnf-auto-helper components ---
run_uninstall_helper_only() {
log_info ">>> Uninstalling dnf-auto-helper core components..."

    echo "" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
echo "  dnf-auto-helper Uninstall" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "This will remove timers, services, helper binaries, logs, and user" | tee -a "${LOG_FILE}"
echo "scripts/aliases installed by dnf-auto-helper for user $SUDO_USER." | tee -a "${LOG_FILE}"
echo "The installer script (DNF-auto.sh) and your Soar/Homebrew installs" | tee -a "${LOG_FILE}"
    echo "will be left untouched. It also does NOT remove snapd, Flatpak, Soar," | tee -a "${LOG_FILE}"
    echo "Homebrew itself, or any dnf configuration such as /etc/dnf/dnf.conf." | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"

    # Handle dry-run and non-interactive flags from the CLI dispatcher.
    if [ "${UNINSTALL_DRY_RUN:-0}" -eq 1 ]; then
        log_info "Dry-run mode active: NO changes will be made."
        echo "" | tee -a "${LOG_FILE}"
        echo "The following items WOULD be removed if you run without --dry-run:" | tee -a "${LOG_FILE}"
        echo "  - System services/timers: dnf-autodownload.service, dnf-autodownload.timer" | tee -a "${LOG_FILE}"
        echo "    dnf-cache-cleanup.service, dnf-cache-cleanup.timer" | tee -a "${LOG_FILE}"
        echo "    dnf-auto-verify.service, dnf-auto-verify.timer" | tee -a "${LOG_FILE}"
echo "  - Root binaries: /usr/local/bin/dnf-download-with-progress, /usr/local/bin/dnf-auto-helper" | tee -a "${LOG_FILE}"
        echo "  - User units: $SUDO_USER_HOME/.config/systemd/user/dnf-notify-user.service/timer" | tee -a "${LOG_FILE}"
echo "  - Helper scripts: $SUDO_USER_HOME/.local/bin/dnf-notify-updater.py, dnf-run-install," | tee -a "${LOG_FILE}"
echo "    dnf-with-ps, dnf-view-changes, dnf-soar-install-helper" | tee -a "${LOG_FILE}"
        if [ "${UNINSTALL_KEEP_LOGS:-0}" -eq 1 ]; then
            echo "  - Logs under $LOG_DIR would be LEFT IN PLACE (--keep-logs)" | tee -a "${LOG_FILE}"
        else
            echo "  - Logs under $LOG_DIR (other than the current log) and notifier caches" | tee -a "${LOG_FILE}"
        fi
        echo "" | tee -a "${LOG_FILE}"
        echo "Run again WITHOUT --dry-run to actually uninstall." | tee -a "${LOG_FILE}"
update_status "DRY-RUN: dnf-auto-helper uninstall (no changes made)"
        return 0
    fi

    if [ "${UNINSTALL_ASSUME_YES:-0}" -ne 1 ]; then
read -p "Are you sure you want to uninstall dnf-auto-helper components? [y/N]: " -r CONFIRM
        echo
        if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
            log_info "Uninstall aborted by user. No changes made."
update_status "ABORTED: dnf-auto-helper uninstall cancelled by user"
            return 0
        fi
    else
        log_info "Non-interactive mode: proceeding without confirmation (--yes)."
    fi

update_status "Uninstalling dnf-auto-helper components..."

    # 1. Stop and disable root timers/services
    log_debug "Disabling root timers and services..."
    # DNF-based units
    systemctl disable --now dnf-autodownload.timer >> "${LOG_FILE}" 2>&1 || true
    systemctl disable --now dnf-cache-cleanup.timer >> "${LOG_FILE}" 2>&1 || true
    systemctl disable --now dnf-auto-verify.timer >> "${LOG_FILE}" 2>&1 || true
    systemctl stop dnf-autodownload.service >> "${LOG_FILE}" 2>&1 || true
    systemctl stop dnf-cache-cleanup.service >> "${LOG_FILE}" 2>&1 || true
    systemctl stop dnf-auto-verify.service >> "${LOG_FILE}" 2>&1 || true

    # 2. Stop and disable user timer/service
    if [ -n "${SUDO_USER:-}" ]; then
        log_debug "Disabling user timer and service for $SUDO_USER..."
        # DNF-based user units
        sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u "$SUDO_USER")/bus" \
            systemctl --user disable --now dnf-notify-user.timer >> "${LOG_FILE}" 2>&1 || true
        sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u "$SUDO_USER")/bus" \
            systemctl --user stop dnf-notify-user.service >> "${LOG_FILE}" 2>&1 || true
    fi

    # 3. Remove systemd unit files and root binaries
    log_debug "Removing root systemd units and binaries..."
    # DNF-based units
    rm -f /etc/systemd/system/dnf-autodownload.service >> "${LOG_FILE}" 2>&1 || true
    rm -f /etc/systemd/system/dnf-autodownload.timer >> "${LOG_FILE}" 2>&1 || true
    rm -f /etc/systemd/system/dnf-cache-cleanup.service >> "${LOG_FILE}" 2>&1 || true
    rm -f /etc/systemd/system/dnf-cache-cleanup.timer >> "${LOG_FILE}" 2>&1 || true
    rm -f /etc/systemd/system/dnf-auto-verify.service >> "${LOG_FILE}" 2>&1 || true
    rm -f /etc/systemd/system/dnf-auto-verify.timer >> "${LOG_FILE}" 2>&1 || true
    rm -f /usr/local/bin/dnf-download-with-progress >> "${LOG_FILE}" 2>&1 || true
    rm -f /usr/local/bin/dnf-auto-helper >> "${LOG_FILE}" 2>&1 || true

    # 4. Remove user-level scripts and systemd units
    if [ -n "${SUDO_USER_HOME:-}" ]; then
        log_debug "Removing user scripts and units under $SUDO_USER_HOME..."
        # DNF-based user units and helpers
        rm -f "$SUDO_USER_HOME/.config/systemd/user/dnf-notify-user.service" >> "${LOG_FILE}" 2>&1 || true
        rm -f "$SUDO_USER_HOME/.config/systemd/user/dnf-notify-user.timer" >> "${LOG_FILE}" 2>&1 || true
        rm -f "$SUDO_USER_HOME/.local/bin/dnf-notify-updater.py" >> "${LOG_FILE}" 2>&1 || true
        rm -f "$SUDO_USER_HOME/.local/bin/dnf-run-install" >> "${LOG_FILE}" 2>&1 || true
        rm -f "$SUDO_USER_HOME/.local/bin/dnf-with-ps" >> "${LOG_FILE}" 2>&1 || true
        rm -f "$SUDO_USER_HOME/.local/bin/dnf-view-changes" >> "${LOG_FILE}" 2>&1 || true
        rm -f "$SUDO_USER_HOME/.local/bin/dnf-soar-install-helper" >> "${LOG_FILE}" 2>&1 || true

        # Remove bash/zsh aliases we added (non-fatal if missing)
        # Also remove newer DNF wrapper aliases if present
        sed -i '/# DNF wrapper for auto service check/d' "$SUDO_USER_HOME/.bashrc" 2>>"${LOG_FILE}" || true
        sed -i "/alias dnf='$DNF_WRAPPER_PATH'/d" "$SUDO_USER_HOME/.bashrc" 2>>"${LOG_FILE}" || true
        sed -i '/# DNF wrapper for auto service check/d' "$SUDO_USER_HOME/.zshrc" 2>>"${LOG_FILE}" || true
        sed -i "/alias dnf='$DNF_WRAPPER_PATH'/d" "$SUDO_USER_HOME/.zshrc" 2>>"${LOG_FILE}" || true
        # Remove command aliases for the helper CLI
        sed -i '/# dnf-auto-helper command alias/d' "$SUDO_USER_HOME/.bashrc" 2>>"${LOG_FILE}" || true
        sed -i '/alias dnf-auto-helper=/d' "$SUDO_USER_HOME/.bashrc" 2>>"${LOG_FILE}" || true
        sed -i '/# dnf-auto-helper command alias/d' "$SUDO_USER_HOME/.zshrc" 2>>"${LOG_FILE}" || true
        sed -i '/alias dnf-auto-helper=/d' "$SUDO_USER_HOME/.zshrc" 2>>"${LOG_FILE}" || true
    fi

    # 5. Remove logs and caches
    if [ "${UNINSTALL_KEEP_LOGS:-0}" -eq 1 ]; then
        log_info "Leaving all logs under $LOG_DIR intact (--keep-logs requested)."
    else
        # Keep the current uninstall log file so we don't break logging while
        # this function is still running, but remove other helper logs and
        # caches.
        log_debug "Removing logs and caches (preserving this uninstall log)..."
        if [ -d "$LOG_DIR" ]; then
            # Delete all files in $LOG_DIR except the current LOG_FILE
            find "$LOG_DIR" -maxdepth 1 -type f ! -name "$(basename "$LOG_FILE")" -delete >> "${LOG_FILE}" 2>&1 || true
            # Remove any service sub-logs directory completely
            rm -rf "$LOG_DIR/service-logs" >> "${LOG_FILE}" 2>&1 || true
        fi
    fi
    if [ -n "${SUDO_USER_HOME:-}" ]; then
rm -rf "$SUDO_USER_HOME/.local/share/dnf-notify" >> "${LOG_FILE}" 2>&1 || true
rm -rf "$SUDO_USER_HOME/.cache/dnf-notify" >> "${LOG_FILE}" 2>&1 || true
    fi

    # 6. Reload systemd daemons
    log_debug "Reloading systemd daemons after uninstall..."
    systemctl daemon-reload >> "${LOG_FILE}" 2>&1 || true
    if [ -n "${SUDO_USER:-}" ]; then
        sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u "$SUDO_USER")/bus" \
            systemctl --user daemon-reload >> "${LOG_FILE}" 2>&1 || true
    fi

    # 7. Clear any failed state in systemd for the removed units so
    #    `systemctl --user status` looks clean after uninstall.
    log_debug "Resetting failed state for removed systemd units (if any)..."
    systemctl reset-failed dnf-autodownload.service dnf-cache-cleanup.service dnf-auto-verify.service >> "${LOG_FILE}" 2>&1 || true
    if [ -n "${SUDO_USER:-}" ]; then
        sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u "$SUDO_USER")/bus" \
            systemctl --user reset-failed dnf-notify-user.service >> "${LOG_FILE}" 2>&1 || true
    fi

log_success "Core dnf-auto-helper components uninstalled (installer script left in place)."
update_status "SUCCESS: dnf-auto-helper core components uninstalled"

    echo "" | tee -a "${LOG_FILE}"
    echo "Uninstall summary:" | tee -a "${LOG_FILE}"
    echo "  - System services and timers removed: dnf-autodownload, dnf-cache-cleanup, dnf-auto-verify" | tee -a "${LOG_FILE}"
    echo "  - User notifier units and helper scripts removed for user $SUDO_USER" | tee -a "${LOG_FILE}"
    echo "  - No changes made to snapd, Flatpak, Soar, Homebrew or /etc/dnf/dnf.conf" | tee -a "${LOG_FILE}"
    if [ "${UNINSTALL_KEEP_LOGS:-0}" -eq 1 ]; then
        echo "  - Logs under $LOG_DIR left in place (--keep-logs)" | tee -a "${LOG_FILE}"
    else
        echo "  - Logs and caches cleaned up (current uninstall log preserved)" | tee -a "${LOG_FILE}"
    fi
    echo "" | tee -a "${LOG_FILE}"
    echo "You can reinstall the helper at any time with:" | tee -a "${LOG_FILE}"
    echo "  sudo sh DNF-auto.sh install" | tee -a "${LOG_FILE}"
}

# --- Helper: Homebrew-only installation mode (CLI) ---
run_brew_install_only() {
    log_info ">>> Homebrew (brew) installation helper mode..."
    update_status "Running Homebrew installation helper..."

    # Detect an existing brew installation for the target user and, if found,
    # prefer to run a self-update (brew update && brew upgrade) instead of
    # re-running the installer.
    BREW_PATH=""

    # 1) In the user's PATH
    if sudo -u "$SUDO_USER" command -v brew >/dev/null 2>&1; then
        BREW_PATH="brew"
    # 2) In a per-user ~/.linuxbrew or ~/.homebrew prefix
    elif [ -x "$SUDO_USER_HOME/.linuxbrew/bin/brew" ]; then
        BREW_PATH="$SUDO_USER_HOME/.linuxbrew/bin/brew"
    elif [ -x "$SUDO_USER_HOME/.homebrew/bin/brew" ]; then
        BREW_PATH="$SUDO_USER_HOME/.homebrew/bin/brew"
    # 3) In the default Linuxbrew prefix /home/linuxbrew/.linuxbrew
    elif [ -x "/home/linuxbrew/.linuxbrew/bin/brew" ]; then
        BREW_PATH="/home/linuxbrew/.linuxbrew/bin/brew"
    fi

    if [ -n "$BREW_PATH" ]; then
        log_success "Homebrew already appears to be installed for user $SUDO_USER"
        echo "brew appears to be installed for user $SUDO_USER." | tee -a "${LOG_FILE}"

        # Build the brew command to run as the target user
        if [ "$BREW_PATH" = "brew" ]; then
            BREW_CMD=(sudo -u "$SUDO_USER" brew)
        else
            BREW_CMD=(sudo -u "$SUDO_USER" "$BREW_PATH")
        fi

        echo "Checking for Homebrew updates from GitHub (brew update) for user $SUDO_USER" | tee -a "${LOG_FILE}"
        if ! "${BREW_CMD[@]}" update >> "${LOG_FILE}" 2>&1; then
            local rc=$?
            log_error "Homebrew 'brew update' failed for user $SUDO_USER (exit code $rc)"
            return $rc
        fi

        # After syncing with GitHub, see if anything needs upgrading
        OUTDATED=$("${BREW_CMD[@]}" outdated --quiet 2>/dev/null || true)
        OUTDATED_COUNT=$(printf '%s\n' "$OUTDATED" | sed '/^$/d' | wc -l | tr -d ' ')

        if [ "${OUTDATED_COUNT:-0}" -eq 0 ]; then
            echo "Homebrew is already up to date for user $SUDO_USER (no formulae to upgrade)." | tee -a "${LOG_FILE}"
            return 0
        fi

        echo "Homebrew has ${OUTDATED_COUNT} outdated formulae for user $SUDO_USER; running 'brew upgrade'..." | tee -a "${LOG_FILE}"
        if "${BREW_CMD[@]}" upgrade >> "${LOG_FILE}" 2>&1; then
            log_success "Homebrew upgrade completed for user $SUDO_USER (upgraded ${OUTDATED_COUNT} formulae)"
            return 0
        else
            local rc=$?
            log_error "Homebrew 'brew upgrade' failed for user $SUDO_USER (exit code $rc)"
            return $rc
        fi
    fi

    # Ensure basic prerequisites for the installer (inline to avoid ordering issues)
    if ! command -v curl >/dev/null 2>&1; then
        log_info "curl is required for the Homebrew installer. Installing via dnf..."
        if ! dnf -y install curl >> "${LOG_FILE}" 2>&1; then
            log_error "Failed to install curl. Please install it manually and re-run with --brew."
            return 1
        fi
    fi

    if ! command -v git >/dev/null 2>&1; then
        log_info "git is required for Homebrew operations. Installing via dnf..."
        if ! dnf -y install git >> "${LOG_FILE}" 2>&1; then
            log_error "Failed to install git. Please install it manually and re-run with --brew."
            return 1
        fi
    fi

    BREW_INSTALL_CMD='/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"'

    echo "" | tee -a "${LOG_FILE}"
    echo "This will run the official Homebrew installer as user $SUDO_USER:" | tee -a "${LOG_FILE}"
    echo "  $BREW_INSTALL_CMD" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"

    if sudo -u "$SUDO_USER" bash -lc "$BREW_INSTALL_CMD"; then
        log_success "Homebrew installation finished for user $SUDO_USER"
        echo "" | tee -a "${LOG_FILE}"

        # Best-effort: automatically add Homebrew to the user's shell PATH if
        # they are using common shells and the recommended snippet is not
        # already present. This avoids the common "brew not in PATH" warning.
        BREW_SHELLENV_LINE='eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"'

        # fish
        FISH_CONFIG_DIR="$SUDO_USER_HOME/.config/fish"
        FISH_CONFIG_FILE="$FISH_CONFIG_DIR/config.fish"
        if [ -d "$FISH_CONFIG_DIR" ]; then
            if ! sudo -u "$SUDO_USER" grep -F "$BREW_SHELLENV_LINE" "$FISH_CONFIG_FILE" >/dev/null 2>&1; then
                mkdir -p "$FISH_CONFIG_DIR"
                sudo -u "$SUDO_USER" bash -lc "echo >> '$FISH_CONFIG_FILE'"
                sudo -u "$SUDO_USER" bash -lc "echo '$BREW_SHELLENV_LINE' >> '$FISH_CONFIG_FILE'"
                echo "Added Homebrew PATH setup to $FISH_CONFIG_FILE" | tee -a "${LOG_FILE}"
            fi
        fi

        # bash
        BASH_RC="$SUDO_USER_HOME/.bashrc"
        if [ -f "$BASH_RC" ]; then
            if ! sudo -u "$SUDO_USER" grep -F "$BREW_SHELLENV_LINE" "$BASH_RC" >/dev/null 2>&1; then
                sudo -u "$SUDO_USER" bash -lc "echo >> '$BASH_RC'"
                sudo -u "$SUDO_USER" bash -lc "echo '$BREW_SHELLENV_LINE' >> '$BASH_RC'"
                echo "Added Homebrew PATH setup to $BASH_RC" | tee -a "${LOG_FILE}"
            fi
        fi

        # zsh
        ZSH_RC="$SUDO_USER_HOME/.zshrc"
        if [ -f "$ZSH_RC" ]; then
            if ! sudo -u "$SUDO_USER" grep -F "$BREW_SHELLENV_LINE" "$ZSH_RC" >/dev/null 2>&1; then
                sudo -u "$SUDO_USER" bash -lc "echo >> '$ZSH_RC'"
                sudo -u "$SUDO_USER" bash -lc "echo '$BREW_SHELLENV_LINE' >> '$ZSH_RC'"
                echo "Added Homebrew PATH setup to $ZSH_RC" | tee -a "${LOG_FILE}"
            fi
        fi

        echo "You may need to add brew to your PATH. For example:" | tee -a "${LOG_FILE}"
        echo '  eval "$(/home/linuxbrew/.linuxbrew/bin/brew shellenv)"' | tee -a "${LOG_FILE}"
        echo 'or see:  https://docs.brew.sh/Homebrew-on-Linux' | tee -a "${LOG_FILE}"
        return 0
    else
        local rc=$?
        log_error "Homebrew installer exited with code $rc"
        return $rc
    fi
}

# --- Helper: pipx / Python CLI tools helper mode (CLI) ---
run_pipx_helper_only() {
    log_info ">>> pipx (Python CLI tools) helper mode..."
    update_status "Running pipx helper..."

    echo "" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "  Python command-line tools via pipx" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "Path A: You want to install a command-line tool (yt-dlp, black, ansible, httpie, etc.)." | tee -a "${LOG_FILE}"
    echo "Use pipx so each tool lives in its own isolated environment and won't break your system Python." | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"

    # Check if pipx is already available for the target user
    if sudo -u "$SUDO_USER" command -v pipx >/dev/null 2>&1; then
        log_success "pipx already appears to be installed for user $SUDO_USER"
        echo "pipx is already installed for user $SUDO_USER." | tee -a "${LOG_FILE}"
    else
        echo "pipx is not installed yet for user $SUDO_USER." | tee -a "${LOG_FILE}"
        echo "On Fedora the recommended way is:" | tee -a "${LOG_FILE}"
        echo "  sudo dnf install pipx" | tee -a "${LOG_FILE}"
        echo "" | tee -a "${LOG_FILE}"

        read -p "May I install pipx for you now via dnf? [y/N]: " -r REPLY
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Installing pipx via dnf..."
            update_status "Installing dependency: pipx"
            if ! dnf -y install pipx >> "${LOG_FILE}" 2>&1; then
                log_error "Failed to install pipx. Please install it manually and re-run with --pip-package."
                update_status "FAILED: Could not install pipx"
                return 1
            fi
            log_success "Successfully installed pipx"

            # Best-effort: ensure pipx adds its binaries to the user's PATH
            if sudo -u "$SUDO_USER" command -v pipx >/dev/null 2>&1; then
                sudo -u "$SUDO_USER" pipx ensurepath >> "${LOG_FILE}" 2>&1 || true
            fi
        else
            log_info "User declined automatic pipx installation"
        fi
    fi

    echo "" | tee -a "${LOG_FILE}"
    echo "How to use pipx for Python CLI tools:" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"
    echo "  1) Install a tool into its own isolated environment:" | tee -a "${LOG_FILE}"
    echo "       pipx install <package_name>" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"
    echo "  2) Upgrade all your pipx-installed tools at once (recommended instead of 'pip install --upgrade'):" | tee -a "${LOG_FILE}"
    echo "       pipx upgrade-all" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"

    # Offer to run a safe upgrade-all for the user
    if sudo -u "$SUDO_USER" command -v pipx >/dev/null 2>&1; then
        read -p "Do you want me to run 'pipx upgrade-all' for user $SUDO_USER now? [y/N]: " -r UPGRADE
        echo
        if [[ $UPGRADE =~ ^[Yy]$ ]]; then
            log_info "Running 'pipx upgrade-all' for user $SUDO_USER..."
            update_status "Running pipx upgrade-all for $SUDO_USER"
            if sudo -u "$SUDO_USER" pipx upgrade-all >> "${LOG_FILE}" 2>&1; then
                log_success "pipx upgrade-all completed for user $SUDO_USER"
            else
                local rc=$?
                log_error "pipx upgrade-all failed for user $SUDO_USER (exit code $rc)"
                return $rc
            fi
        else
            log_info "User chose not to run pipx upgrade-all automatically"
        fi
    fi

    echo "" | tee -a "${LOG_FILE}"
    echo "Summary:" | tee -a "${LOG_FILE}"
    echo "  - pipx is now the recommended/default way to install and upgrade standalone Python CLI tools." | tee -a "${LOG_FILE}"
    echo "  - Use 'pipx install <package>' to add a new tool." | tee -a "${LOG_FILE}"
    echo "  - Use 'pipx upgrade-all' instead of 'pip install --upgrade' for those tools." | tee -a "${LOG_FILE}"

    update_status "SUCCESS: pipx helper completed"
    return 0
}

# Show help if requested, or when invoked as the installed CLI with no arguments
if [[ "${1:-}" == "--help" || "${1:-}" == "-h" || "${1:-}" == "help" \
   || ( $# -eq 0 && "$(basename "$0")" == "dnf-auto-helper" ) ]]; then
    echo "DNF Auto-Helper - Installation and Maintenance Tool"
    echo ""
    echo "Usage: dnf-auto-helper [COMMAND]"
    echo "   or: sudo $0 [COMMAND]  # when running the script directly without the shell alias"
    echo ""
    echo "Commands:"
    echo "  install           Install or update the DNF auto-updater system (default)"
    echo "  --verify          Run verification and auto-repair checks"
    echo "  --repair          Same as --verify (alias)"
    echo "  --diagnose        Same as --verify (alias)"
    echo "  --check           Run syntax checks only"
    echo "  --self-check      Same as --check (alias)"
    echo "  --soar            Install/upgrade optional Soar CLI helper for the user"
    echo "  --brew            Install/upgrade Homebrew (brew) for the user"
    echo "  --pip-package     Install/upgrade pipx and show how to manage Python CLI tools with pipx"
     echo "  --reset-config    Reset /etc/dnf-auto.conf to documented defaults (with backup)"
     echo "  --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  dnf-auto-helper install         # Full installation (via shell alias, runs with sudo)"
    echo "  dnf-auto-helper --verify        # Check system health and auto-fix issues"
    echo "  dnf-auto-helper --check         # Verify script syntax"
    echo "  dnf-auto-helper --soar          # Install or upgrade Soar CLI helper"
    echo ""
    echo "Verification checks (--verify):"
    echo "  - System/user services active and enabled"
    echo "  - Python scripts executable and valid syntax"
    echo "  - Shell wrappers installed correctly"
    echo "  - No stale processes or bytecode cache"
    echo "  - Auto-repairs most common issues"
    echo ""
    echo "Note: After installation, you can use 'dnf-auto-helper' from anywhere."
    echo ""
    exit 0
fi

# Optional mode: only run self-check and exit
if [[ "${1:-}" == "--self-check" || "${1:-}" == "--check" ]]; then
    log_info "Self-check mode requested"
    run_self_check
    log_success "Self-check mode completed"
    exit 0
fi

# Optional modes: Soar, Homebrew, pipx, and uninstall helper-only
if [[ "${1:-}" == "--soar" ]]; then
    log_info "Soar helper-only mode requested"
    run_soar_install_only
    exit $?
elif [[ "${1:-}" == "--brew" ]]; then
    log_info "Homebrew helper-only mode requested"
    run_brew_install_only
    exit $?
elif [[ "${1:-}" == "--pip-package" || "${1:-}" == "--pipx" ]]; then
    log_info "pipx helper-only mode requested"
    run_pipx_helper_only
    exit $?
elif [[ "${1:-}" == "--reset-config" ]]; then
    log_info "Config reset mode requested"
    run_reset_config_only
    exit $?
fi

# Optional mode: run verification and auto-repair
if [[ "${1:-}" == "--verify" || "${1:-}" == "--repair" || "${1:-}" == "--diagnose" ]]; then
    log_info "Verification and auto-repair mode requested"
    echo "" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "  DNF Auto-Helper - Verification Mode" | tee -a "${LOG_FILE}"
    echo "==============================================" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"
    
    # Set a flag to skip to verification section
    VERIFICATION_ONLY_MODE=1
    # We'll jump to the verification section after defining all variables
fi

# --- Helper function to check and install ---
check_and_install() {
    local cmd=$1
    local package=$2
    local purpose=$3

    log_debug "Checking for command: $cmd (package: $package)"
    
    if ! command -v $cmd &> /dev/null; then
        log_info "---"
        log_info "⚠️  Dependency missing: '$cmd' ($purpose)."
        log_info "   This is provided by the package '$package'."
        read -p "   May I install it for you? (y/n) " -n 1 -r
        echo
        log_debug "User response: $REPLY"
        
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Installing $package..."
            update_status "Installing dependency: $package"
            
            if ! sudo dnf install -y "$package" >> "${LOG_FILE}" 2>&1; then
                log_error "Failed to install $package. Please install it manually and re-run this script."
                update_status "FAILED: Could not install $package"
                exit 1
            fi
            log_success "Successfully installed $package"
        else
            log_error "Dependency '$package' is required. Please install it manually and re-run this script."
            update_status "FAILED: Required dependency $package not installed"
            exit 1
        fi
    else
        log_success "Command '$cmd' found"
    fi
}

# Skip installation if we're only verifying
if [ "${VERIFICATION_ONLY_MODE:-0}" -eq 1 ]; then
    log_info "Skipping installation steps - verification mode"
    # Need to set DOWNLOADER_SCRIPT path for verification
    DOWNLOADER_SCRIPT="/usr/local/bin/dnf-download-with-progress"
    DNF_WRAPPER_PATH="$USER_BIN_DIR/dnf-with-ps"
    USER_LOG_DIR="$SUDO_USER_HOME/.local/share/dnf-notify"
    USER_BUS_PATH="unix:path=/run/user/$(id -u "$SUDO_USER")/bus"

    # In verification-only mode we *expect* a non-zero exit code when
    # problems are found, so disable the installer-wide ERR trap and
    # temporarily turn off 'set -e' so that run_verification_only can
    # complete and return its status cleanly instead of being treated as
    # a fatal installer error.
    trap - ERR
    set +e
    run_verification_only
    rc=$?
    set -e
    exit $rc
fi

# --- 2b. Dependency Checks ---
update_status "Checking dependencies..."
log_info ">>> Checking dependencies..."
check_and_install "nmcli" "NetworkManager" "checking metered connection"
check_and_install "upower" "upower" "checking AC power"
check_and_install "inxi" "inxi" "hardware and network detection"
check_and_install "python3" "python3" "running the notifier script"
check_and_install "pkexec" "polkit" "graphical authentication"
# On newer Fedora with dnf5, many plugins are built-in and
# 'needs-restarting' may not come from dnf-plugins-core anymore.
# Only require it when the legacy dnf4 stack is in use; otherwise
# treat it as optional and skip auto-install.
if command -v dnf5 >/dev/null 2>&1; then
    log_info "Skipping hard dependency on 'needs-restarting' under dnf5 (optional feature)."
else
    check_and_install "needs-restarting" "dnf-plugins-core" "detecting services that need restarting"
fi
check_and_install "semanage" "policycoreutils-python-utils" "managing SELinux file contexts (semanage)"

# Check Python version (must be 3.7+)
log_debug "Checking Python version..."
PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
log_debug "Python version: $PY_VERSION"

if [ "$(echo -e "$PY_VERSION\n3.7" | sort -V | head -n1)" != "3.7" ]; then
    log_error "Python 3.7 or newer is required. Found $PY_VERSION."
    update_status "FAILED: Python version too old ($PY_VERSION)"
    exit 1
fi
log_success "Python version check passed: $PY_VERSION"

# Check for PyGobject (the notification library)
log_debug "Checking for PyGObject..."
if ! python3 -c "import gi" &> /dev/null; then
    log_info "---"
    log_info "⚠️  Dependency missing: 'python3-gobject' (for notifications)."
    read -p "   May I install it for you? (y/n) " -n 1 -r
    echo
    log_debug "User response: $REPLY"
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Installing python3-gobject via dnf..."
        update_status "Installing python3-gobject..."
        
        if ! sudo dnf install -y "python3-gobject" >> "${LOG_FILE}" 2>&1; then
            log_error "Failed to install python3-gobject. Please install it manually and re-run this script."
            update_status "FAILED: Could not install python3-gobject"
            exit 1
        fi
        log_success "Successfully installed python3-gobject"
    else
        log_error "Dependency 'python3-gobject' is required. Please install it manually and re-run this script."
        update_status "FAILED: python3-gobject not installed"
        exit 1
    fi
else
    log_success "PyGObject found"
fi
log_success "All dependencies passed"
update_status "All dependencies verified"

# --- 3. Clean Up Old Logs First ---
log_info ">>> Cleaning up old log files..."
update_status "Cleaning up old installation logs..."
cleanup_old_logs

# --- 3b. Disable conflicting background updaters (PackageKit) ---
# To avoid constant DNF lock contention, proactively disable common
# PackageKit-based background services. This leaves interactive GUI
# tools installable, but stops them from automatically grabbing the
# system management lock behind the scenes.
log_info ">>> Disabling PackageKit background services to avoid DNF lock conflicts..."
update_status "Disabling PackageKit background services..."
systemctl disable --now packagekit.service packagekit-offline-update.service packagekit-background.service \
    >> "${LOG_FILE}" 2>&1 || true
log_success "PackageKit background services disabled (or not present)"

# --- 5. Create/Update DOWNLOADER (Root Service) ---
log_info ">>> Creating (root) downloader service: ${DL_SERVICE_FILE}"
update_status "Creating system downloader service..."
log_debug "Writing service file: ${DL_SERVICE_FILE}"

# Derive systemd OnCalendar/OnBootSec values from the configured
# DL_TIMER_INTERVAL_MINUTES. We keep this constrained to a small
# set of safe values (1,5,10,15,30,60) via load_config.
DL_ONBOOTSEC="${DL_TIMER_INTERVAL_MINUTES}min"
DL_ONCALENDAR="minutely"
if [ "$DL_TIMER_INTERVAL_MINUTES" -eq 60 ]; then
    DL_ONCALENDAR="hourly"
elif [ "$DL_TIMER_INTERVAL_MINUTES" -ne 1 ]; then
    DL_ONCALENDAR="*:0/${DL_TIMER_INTERVAL_MINUTES}"
fi

# Create service log directory
mkdir -p "${LOG_DIR}/service-logs"
chmod 755 "${LOG_DIR}/service-logs"

# First, create the downloader script with progress tracking
DOWNLOADER_SCRIPT="/usr/local/bin/dnf-download-with-progress"
log_debug "Creating downloader script with progress tracking: $DOWNLOADER_SCRIPT"
cat << 'DLSCRIPT' > "$DOWNLOADER_SCRIPT"
#!/bin/bash
# DNF downloader with real-time progress tracking
set -euo pipefail

LOG_DIR="__LOG_DIR_PLACEHOLDER__"
STATUS_FILE="$LOG_DIR/download-status.txt"
START_TIME_FILE="$LOG_DIR/download-start-time.txt"
CACHE_DIR="/var/cache/dnf"

# Optional: read extra dup flags from /etc/dnf-auto.conf so users can
# tweak solver behaviour (e.g. --allow-vendor-change) without editing
# this script directly.
CONFIG_FILE="__CONFIG_FILE_PLACEHOLDER__"
if [ -f "$CONFIG_FILE" ]; then
    # shellcheck source=/etc/dnf-auto.conf
    . "$CONFIG_FILE"
fi
DUP_EXTRA_FLAGS="${DUP_EXTRA_FLAGS:-}"
CACHE_EXPIRY_MINUTES="${CACHE_EXPIRY_MINUTES:-10}"
DOWNLOADER_DOWNLOAD_MODE="${DOWNLOADER_DOWNLOAD_MODE:-full}"

# Smart minimum interval between refresh/dry-run runs. This reuses the
# same CACHE_EXPIRY_MINUTES knob as the notifier so we don't hammer
# mirrors with constant metadata/solver checks when the timer is very
# frequent (e.g. every minute).
LAST_CHECK_FILE="$LOG_DIR/download-last-check.txt"
NOW=$(date +%s)
if [ -f "$LAST_CHECK_FILE" ]; then
    LAST=$(cat "$LAST_CHECK_FILE" 2>/dev/null || echo 0)
    if [ "$LAST" -gt 0 ] 2>/dev/null; then
        MIN_INTERVAL=$((CACHE_EXPIRY_MINUTES * 60))
        if [ "$MIN_INTERVAL" -gt 0 ] && [ $((NOW - LAST)) -lt "$MIN_INTERVAL" ]; then
            # Too soon since last full check; skip this run quietly and
            # let the existing status/notifications stand.
            exit 0
        fi
    fi
fi
echo "$NOW" > "$LAST_CHECK_FILE"

# Helper: trigger the user notifier immediately after downloads complete
trigger_notifier() {
    # Best-effort detection of the primary non-root user with a systemd user session.
    local user uid
    user=$(loginctl list-users --no-legend 2>/dev/null | awk '$1 != 0 {print $2; exit}') || user=""
    if [ -z "$user" ]; then
        return 0
    fi
    uid=$(id -u "$user" 2>/dev/null || echo "")
    if [ -z "$uid" ]; then
        return 0
    fi
    sudo -u "$user" \
        DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${uid}/bus" \
        systemctl --user start dnf-notify-user.service \
        >/dev/null 2>&1 || true
}

# Handle package-manager locks gracefully so we do not spam the logs or
# mark the service failed when another updater (dnf/PackageKit) is running.
handle_lock_or_fail() {
    local err_file="$1"

    # Common dnf/PackageKit lock messages (Fedora variants)
    if grep -qiE 'System management is locked|System management is currently locked by another update tool|Another app is currently holding the dnf lock|dnf is locked by another process|Existing lock' "$err_file" 2>/dev/null; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Package manager is locked by another process; skipping this downloader run (will retry on next timer)" >&2

        # Log detailed lock-owner information for easier diagnostics.
        local lock_pid_file lock_pid lock_comm lock_cmd rpm_lock_info
        if [ -f "/run/dnf.pid" ] || [ -f "/var/run/dnf.pid" ]; then
            lock_pid_file="/run/dnf.pid"
            [ -f "/var/run/dnf.pid" ] && lock_pid_file="/var/run/dnf.pid"
            lock_pid=$(cat "$lock_pid_file" 2>/dev/null || echo "")
            if [ -n "$lock_pid" ] && kill -0 "$lock_pid" 2>/dev/null; then
                lock_comm=$(ps -p "$lock_pid" -o comm= 2>/dev/null || echo "")
                lock_cmd=$(ps -p "$lock_pid" -o args= 2>/dev/null || echo "")
                echo "[LOCK] dnf.pid owner: PID=$lock_pid, COMM=$lock_comm" >&2
                echo "[LOCK] Command line: $lock_cmd" >&2
            else
                echo "[LOCK] dnf.pid exists at $lock_pid_file with stale or unknown PID '$lock_pid'" >&2
            fi
        else
            echo "[LOCK] No dnf.pid file present" >&2
        fi

        if [ -f "/var/lib/rpm/.rpm.lock" ] && command -v fuser >/dev/null 2>&1; then
            rpm_lock_info=$(fuser "/var/lib/rpm/.rpm.lock" 2>&1 || echo "")
            if [ -n "$rpm_lock_info" ]; then
                echo "[LOCK] RPM DB lock owners (fuser /var/lib/rpm/.rpm.lock): $rpm_lock_info" >&2
            else
                echo "[LOCK] RPM DB lock present but no active owner reported by fuser" >&2
            fi
        fi

        echo "idle" > "$STATUS_FILE"
        rm -f "$err_file"
        exit 0
    fi
}

# Write status: refreshing
echo "refreshing" > "$STATUS_FILE"
date +%s > "$START_TIME_FILE"

# Refresh package metadata (dnf makecache)
REFRESH_ERR=$(mktemp)
if ! /usr/bin/nice -n -20 /usr/bin/ionice -c1 -n0 /usr/bin/dnf -q makecache >/dev/null 2>"$REFRESH_ERR"; then
    # If another package manager instance holds the lock, handle_lock_or_fail will
    # mark the status as idle and exit 0 so we do not treat it as an
    # error here.
    handle_lock_or_fail "$REFRESH_ERR"

    # At this point we know the error was not a simple lock. Before we
    # surface an error to the user, try a lightweight auto-repair by
    # cleaning stale repository metadata once and retrying the refresh.
    if grep -qiE 'Failed to retrieve new repository metadata|repomd\\.xml' "$REFRESH_ERR"; then
        # Best-effort metadata cleanup; ignore failures here because the
        # second makecache run below will still surface any remaining
        # error in a controlled way.
        dnf clean metadata >/dev/null 2>&1 || true

        # Retry makecache once after cleaning metadata.
        REFRESH_ERR_RETRY=$(mktemp)
        if /usr/bin/nice -n -20 /usr/bin/ionice -c1 -n0 /usr/bin/dnf -q makecache >/dev/null 2>"$REFRESH_ERR_RETRY"; then
            # Auto-repair succeeded; clear error state and continue with
            # the normal workflow so the notifier sees a healthy status.
            rm -f "$REFRESH_ERR" "$REFRESH_ERR_RETRY"
            goto_after_refresh_success=1
        else
            # Merge retry diagnostics into the main error log for easier
            # debugging, then fall through to normal classification.
            cat "$REFRESH_ERR_RETRY" >> "$REFRESH_ERR" 2>/dev/null || true
            rm -f "$REFRESH_ERR_RETRY"
        fi
    fi

    # If the retry path marked a successful refresh, skip error
    # classification entirely.
    if [ "${goto_after_refresh_success:-0}" -eq 1 ]; then
        : # no-op; jump to the common success path below
    else
        # Classify as a network/repository problem so the notifier can
        # surface a clear error message instead of silently doing nothing.
        if grep -qi "could not resolve host" "$REFRESH_ERR" || \
           grep -qi "Failed to retrieve new repository metadata" "$REFRESH_ERR"; then
            echo "error:network" > "$STATUS_FILE"
        else
            echo "error:repo" > "$STATUS_FILE"
        fi

        cat "$REFRESH_ERR" >&2 || true
        rm -f "$REFRESH_ERR"
        # Exit 0 so systemd does not mark the service failed; the notifier
        # will pick up the error:* status on the next run.
        exit 0
    fi
fi
rm -f "$REFRESH_ERR"

# Get update info using a non-interactive dnf transaction preview
DRY_OUTPUT=$(mktemp)
DRY_ERR=$(mktemp)
if ! /usr/bin/nice -n -20 /usr/bin/ionice -c1 -n0 /usr/bin/dnf -q upgrade --assumeno $DUP_EXTRA_FLAGS > "$DRY_OUTPUT" 2>"$DRY_ERR"; then
    # Handle lock first; if it is just a lock, this will mark status idle
    # and exit 0 so we do not need to set an additional error state.
    handle_lock_or_fail "$DRY_ERR"

    # At this point we know the error was not a simple lock. Before we
    # surface an error to the user, try the same lightweight auto-repair
    # used for metadata refresh: clean stale repo metadata once and retry
    # the preview.
    if grep -qiE 'Failed to synchronize cache|Failed to download metadata|repomd\\.xml' "$DRY_ERR"; then
        dnf clean metadata >/dev/null 2>&1 || true

        DRY_ERR_RETRY=$(mktemp)
        if /usr/bin/nice -n -20 /usr/bin/ionice -c1 -n0 /usr/bin/dnf -q upgrade --assumeno $DUP_EXTRA_FLAGS > "$DRY_OUTPUT" 2>"$DRY_ERR_RETRY"; then
            # Auto-repair on preview succeeded; clear error state and
            # continue as if the original preview had worked.
            rm -f "$DRY_ERR" "$DRY_ERR_RETRY"
        else
            cat "$DRY_ERR_RETRY" >> "$DRY_ERR" 2>/dev/null || true
            rm -f "$DRY_ERR_RETRY"
        fi
    fi

    # Re-check whether the preview still failed after optional repair.
    if [ -s "$DRY_ERR" ]; then
        # Final fallback: run a more tolerant preview that allows erasing
        # and skips broken/unavailable packages so we can still pre-download
        # everything that is safe, without the user having to configure
        # anything.
        DRY_ERR_FALLBACK=$(mktemp)
        if /usr/bin/nice -n -20 /usr/bin/ionice -c1 -n0 \
            /usr/bin/dnf -q upgrade --assumeno --skip-broken --allowerasing $DUP_EXTRA_FLAGS \
            > "$DRY_OUTPUT" 2>"$DRY_ERR_FALLBACK"; then
            # Tolerant preview succeeded; discard previous errors and
            # continue as if the original preview had worked.
            rm -f "$DRY_ERR" "$DRY_ERR_FALLBACK"
        else
            # Merge fallback diagnostics into main error log and classify.
            cat "$DRY_ERR_FALLBACK" >> "$DRY_ERR" 2>/dev/null || true
            rm -f "$DRY_ERR_FALLBACK"

            # Non-lock failure at the preview stage – classify it so the
            # notifier can display a meaningful error notification.
            if grep -qi "could not resolve host" "$DRY_ERR" || \
               grep -qi "Failed to synchronize cache" "$DRY_ERR"; then
                echo "error:network" > "$STATUS_FILE"
            else
                echo "error:repo" > "$STATUS_FILE"
            fi

            cat "$DRY_ERR" >&2 || true
            rm -f "$DRY_ERR" "$DRY_OUTPUT"
            exit 0
        fi
    fi
fi
rm -f "$DRY_ERR"

# Extract package count from the dnf transaction summary, e.g.:
#   Upgrade  10 Packages
PKG_COUNT=$(grep -iE 'Upgrade[[:space:]]+[0-9]+[[:space:]]+Package' "$DRY_OUTPUT" \
    | head -1 \
    | awk '{for (i=1;i<=NF;i++) if ($i ~ /^[0-9]+$/) {print $i; break}}')

# If no upgrades are listed, nothing to do
if [ -z "$PKG_COUNT" ] || [ "$PKG_COUNT" -eq 0 ] 2>/dev/null; then
    echo "idle" > "$STATUS_FILE"
    rm -f "$DRY_OUTPUT"
    exit 0
fi

# Extract total download size, e.g. "120 M" or "1.2 G"
DOWNLOAD_SIZE=$(grep -i "Total download size:" "$DRY_OUTPUT" | head -1 | sed -E 's/.*Total download size:[[:space:]]*//')
[ -z "$DOWNLOAD_SIZE" ] && DOWNLOAD_SIZE="unknown"

rm -f "$DRY_OUTPUT"

# Count packages before download (approximate progress tracking)
BEFORE_COUNT=$(find "$CACHE_DIR" -name "*.rpm" 2>/dev/null | wc -l)

# Write initial downloading status so the tracker loop sees it immediately
echo "downloading:$PKG_COUNT:$DOWNLOAD_SIZE:0:0" > "$STATUS_FILE"
# Start background progress tracker
(
    while [ -f "$STATUS_FILE" ] && grep -q "^downloading:" "$STATUS_FILE" 2>/dev/null; do
        sleep 2  # Update every 2 seconds
        CURRENT_COUNT=$(find "$CACHE_DIR" -name "*.rpm" 2>/dev/null | wc -l)
        DOWNLOADED=$((CURRENT_COUNT - BEFORE_COUNT))
        if [ $DOWNLOADED -lt 0 ]; then DOWNLOADED=0; fi
        if [ $DOWNLOADED -gt $PKG_COUNT ]; then DOWNLOADED=$PKG_COUNT; fi
        
        # Calculate percentage
        if [ $PKG_COUNT -gt 0 ]; then
            PERCENT=$((DOWNLOADED * 100 / PKG_COUNT))
        else
            PERCENT=0
        fi
        
        echo "downloading:$PKG_COUNT:$DOWNLOAD_SIZE:$DOWNLOADED:$PERCENT" > "$STATUS_FILE"
    done
) &
TRACKER_PID=$!

# If the downloader is running in detect-only mode, skip the heavy
# "dup --download-only" pass and just trigger the notifier so it can
# inform the user that updates are available. This avoids extra
# bandwidth and disk usage when the user only cares about detection.
if [ "$DOWNLOADER_DOWNLOAD_MODE" = "detect-only" ]; then
    # Mark as a completed detection-only cycle; no new packages were
    # downloaded by this helper, but the notifier will see that updates
    # exist from its own dry-run.
    echo "complete:0:0" > "$STATUS_FILE"
    trigger_notifier
    exit 0
fi

# Do the actual download. We intentionally ignore most non-zero exit codes so
# that partial downloads remain in the cache even if dnf encounters solver
# problems that require manual intervention later. We still special-case the
# lock error to avoid noisy logs when another package manager instance is running.
set +e
DL_ERR=$(mktemp)
/usr/bin/nice -n -20 /usr/bin/ionice -c1 -n0 /usr/bin/dnf -q upgrade --downloadonly -y $DUP_EXTRA_FLAGS >/dev/null 2>"$DL_ERR"
DNF_RET=$?
if [ $DNF_RET -ne 0 ]; then
    handle_lock_or_fail "$DL_ERR"

    # Final fallback for downloads as well: if the normal download-only
    # pass fails for non-lock reasons, try a more tolerant run that allows
    # erasing and skips broken/unavailable packages so we can still
    # prefetch as much as possible.
    DL_ERR_FALLBACK=$(mktemp)
    /usr/bin/nice -n -20 /usr/bin/ionice -c1 -n0 \
        /usr/bin/dnf -q upgrade --downloadonly -y --skip-broken --allowerasing $DUP_EXTRA_FLAGS \
        >/dev/null 2>"$DL_ERR_FALLBACK"
    DNF_RET=$?
    if [ $DNF_RET -eq 0 ]; then
        rm -f "$DL_ERR" "$DL_ERR_FALLBACK"
    else
        cat "$DL_ERR_FALLBACK" >> "$DL_ERR" 2>/dev/null || true
        rm -f "$DL_ERR_FALLBACK"
    fi
fi
rm -f "$DL_ERR"
set -e

# Kill the progress tracker
kill $TRACKER_PID 2>/dev/null || true
wait $TRACKER_PID 2>/dev/null || true

# Count packages after download
AFTER_COUNT=$(find "$CACHE_DIR" -name "*.rpm" 2>/dev/null | wc -l)
ACTUAL_DOWNLOADED=$((AFTER_COUNT - BEFORE_COUNT))

# Calculate duration
START_TIME=$(cat "$START_TIME_FILE" 2>/dev/null || date +%s)
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# Decide final status:
#  - If we actually downloaded new packages, mark as complete
#  - If nothing was downloaded but dnf returned an error, mark an error
#    so the notifier can tell the user that manual intervention is required
#  - Otherwise, leave the previous status (e.g. idle or complete:0:0)
if [ $ACTUAL_DOWNLOADED -gt 0 ]; then
    echo "complete:$DURATION:$ACTUAL_DOWNLOADED" > "$STATUS_FILE"
    trigger_notifier
elif [ $DNF_RET -ne 0 ]; then
    echo "error:solver:$DNF_RET" > "$STATUS_FILE"
fi

DLSCRIPT
chmod +x "$DOWNLOADER_SCRIPT"

# Inject configured paths into downloader script
sed -i "s|__LOG_DIR_PLACEHOLDER__|${LOG_DIR}|g" "$DOWNLOADER_SCRIPT"
sed -i "s|__CONFIG_FILE_PLACEHOLDER__|${CONFIG_FILE}|g" "$DOWNLOADER_SCRIPT"

log_success "Downloader script created with progress tracking"

# Now create the service file
cat << EOF > ${DL_SERVICE_FILE}
[Unit]
Description=Download DNF system updates in background
ConditionACPower=true
ConditionNotOnMeteredConnection=true
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
Type=oneshot
IOSchedulingClass=realtime
IOSchedulingPriority=0
Nice=-20
StandardOutput=append:${LOG_DIR}/service-logs/downloader.log
StandardError=append:${LOG_DIR}/service-logs/downloader-error.log
ExecStart=${DOWNLOADER_SCRIPT}

# Systemd hardening (optional but safe for this service)
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=yes
ReadWritePaths=/var/cache/dnf /var/log/dnf-auto
EOF
log_success "Downloader service file created"

# --- 6. Create/Update DOWNLOADER (Root Timer) ---
log_info ">>> Creating (root) downloader timer: ${DL_TIMER_FILE}"
log_debug "Writing timer file: ${DL_TIMER_FILE}"
cat << EOF > ${DL_TIMER_FILE}
[Unit]
Description=Run ${DL_SERVICE_NAME} periodically to download updates

[Timer]
OnBootSec=${DL_ONBOOTSEC}
OnCalendar=${DL_ONCALENDAR}
Persistent=true

[Install]
WantedBy=timers.target
EOF
log_success "Downloader timer file created"

log_info ">>> Enabling (root) downloader timer: ${DL_SERVICE_NAME}.timer"
update_status "Enabling system downloader timer..."
log_debug "Reloading systemd daemon..."
systemctl daemon-reload >> "${LOG_FILE}" 2>&1

log_debug "Enabling and starting timer..."
if systemctl enable --now "${DL_SERVICE_NAME}.timer" >> "${LOG_FILE}" 2>&1; then
    log_success "Downloader timer enabled and started"
else
    log_error "Failed to enable downloader timer"
    update_status "FAILED: Could not enable downloader timer"
    exit 1
fi

# --- 6b. Create Cache Cleanup Service ---
log_info ">>> Creating (root) cache cleanup service: ${CLEANUP_SERVICE_FILE}"
update_status "Creating cache cleanup service..."
log_debug "Writing service file: ${CLEANUP_SERVICE_FILE}"
cat << EOF > ${CLEANUP_SERVICE_FILE}
[Unit]
Description=Clean up old DNF cache packages

[Service]
Type=oneshot
ExecStart=/usr/bin/find /var/cache/dnf -type f -name '*.rpm' -mtime +30 -delete
ExecStart=/usr/bin/find /var/cache/dnf -type d -empty -delete
StandardOutput=append:${LOG_DIR}/service-logs/cleanup.log
StandardError=append:${LOG_DIR}/service-logs/cleanup-error.log
EOF
log_success "Cache cleanup service file created"

log_info ">>> Creating (root) cache cleanup timer: ${CLEANUP_TIMER_FILE}"
log_debug "Writing timer file: ${CLEANUP_TIMER_FILE}"
cat << EOF > ${CLEANUP_TIMER_FILE}
[Unit]
Description=Run cache cleanup weekly

[Timer]
OnCalendar=weekly
Persistent=true

[Install]
WantedBy=timers.target
EOF
log_success "Cache cleanup timer file created"

log_info ">>> Enabling (root) cache cleanup timer: ${CLEANUP_SERVICE_NAME}.timer"
update_status "Enabling cache cleanup timer..."
systemctl daemon-reload >> "${LOG_FILE}" 2>&1
if systemctl enable --now "${CLEANUP_SERVICE_NAME}.timer" >> "${LOG_FILE}" 2>&1; then
log_success "Cache cleanup timer enabled and started"
else
    log_error "Failed to enable cache cleanup timer (non-fatal)"
fi

# --- 6c. Create verification/auto-repair service and timer ---
log_info ">>> Creating (root) verification/auto-repair service: ${VERIFY_SERVICE_FILE}"
update_status "Creating verification service..."
log_debug "Writing service file: ${VERIFY_SERVICE_FILE}"

# Derive systemd schedule for the verification timer from
# VERIFY_TIMER_INTERVAL_MINUTES. We mirror the downloader's
# behaviour: minutely/hourly for 1/60, or "*:0/N" for other values.
VERIFY_ONBOOTSEC="${VERIFY_TIMER_INTERVAL_MINUTES}min"
VERIFY_ONCALENDAR="minutely"
if [ "${VERIFY_TIMER_INTERVAL_MINUTES}" -eq 60 ]; then
    VERIFY_ONCALENDAR="hourly"
elif [ "${VERIFY_TIMER_INTERVAL_MINUTES}" -ne 1 ]; then
    VERIFY_ONCALENDAR="*:0/${VERIFY_TIMER_INTERVAL_MINUTES}"
fi

cat << EOF > ${VERIFY_SERVICE_FILE}
[Unit]
Description=Verify and auto-repair dnf-auto-helper installation
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/dnf-auto-helper --verify
StandardOutput=append:${LOG_DIR}/service-logs/verify.log
StandardError=append:${LOG_DIR}/service-logs/verify-error.log
Restart=on-failure
RestartSec=1h

# Hardening
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=yes
ReadWritePaths=${LOG_DIR} /run /var/run /var/cache/dnf
EOF
log_success "Verification service file created"

log_info ">>> Creating (root) verification timer: ${VERIFY_TIMER_FILE}"
log_debug "Writing timer file: ${VERIFY_TIMER_FILE}"
cat << EOF > ${VERIFY_TIMER_FILE}
[Unit]
Description=Run ${VERIFY_SERVICE_NAME} periodically to verify and auto-repair helper

[Timer]
OnBootSec=${VERIFY_ONBOOTSEC}
OnCalendar=${VERIFY_ONCALENDAR}
Persistent=true

[Install]
WantedBy=timers.target
EOF
log_success "Verification timer file created"

log_info ">>> Enabling (root) verification timer: ${VERIFY_SERVICE_NAME}.timer"
update_status "Enabling verification timer..."
systemctl daemon-reload >> "${LOG_FILE}" 2>&1
if systemctl enable --now "${VERIFY_SERVICE_NAME}.timer" >> "${LOG_FILE}" 2>&1; then
    log_success "Verification timer enabled and started"
else
    log_error "Failed to enable verification timer (non-fatal)"
fi

# --- 7. Create User Directories ---
log_info ">>> Creating user directories (if needed)..."
update_status "Creating user directories..."
log_debug "Creating $USER_CONFIG_DIR"
mkdir -p "$USER_CONFIG_DIR"
chown -R "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.config"

log_debug "Creating $USER_BIN_DIR"
mkdir -p "$USER_BIN_DIR"
chown -R "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.local"
log_success "User directories created"

# Create user log directory
USER_LOG_DIR="$SUDO_USER_HOME/.local/share/dnf-notify"
log_debug "Creating user log directory: $USER_LOG_DIR"
mkdir -p "$USER_LOG_DIR"
chown -R "$SUDO_USER:$SUDO_USER" "$USER_LOG_DIR"

# --- 7b. Create DNF Wrapper for Manual Updates ---
log_info ">>> Creating dnf wrapper script for manual updates..."
update_status "Creating dnf wrapper..."
DNF_WRAPPER_PATH="$USER_BIN_DIR/dnf-with-ps"
log_debug "Writing dnf wrapper to: $DNF_WRAPPER_PATH"
cat << 'EOF' > "$DNF_WRAPPER_PATH"
#!/usr/bin/env bash
# Wrapper that runs DNF for system updates and shows which services need restarting

# Load feature toggles from the same config used by the installer.
CONFIG_FILE="/etc/dnf-auto.conf"

# Default feature toggles (can be overridden by CONFIG_FILE)
ENABLE_FLATPAK_UPDATES="true"
ENABLE_SNAP_UPDATES="true"
ENABLE_SOAR_UPDATES="true"
ENABLE_BREW_UPDATES="true"
ENABLE_PIPX_UPDATES="true"

if [ -r "$CONFIG_FILE" ]; then
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
fi

# Helper to detect whether system management is currently locked by
# another package manager (dnf, PackageKit, etc.).
DNF_LOCK_FILE="/var/run/dnf.pid"

has_pkg_lock() {
    # Prefer the dnf.pid lock file when present.
    if [ -f "$DNF_LOCK_FILE" ]; then
        local pid
        pid=$(cat "$DNF_LOCK_FILE" 2>/dev/null || echo "")
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            local comm cmd
            comm=$(ps -p "$pid" -o comm= 2>/dev/null || echo "")
            cmd=$(ps -p "$pid" -o args= 2>/dev/null || echo "")
            if printf '%s\n%s\n' "$comm" "$cmd" | grep -qiE 'dnf|dnf-automatic|packagekitd'; then
                return 0
            fi
        fi
    fi

    # Also treat an actively held RPM database lock as a package-manager lock.
    if [ -f "/var/lib/rpm/.rpm.lock" ] && command -v fuser >/dev/null 2>&1; then
        if fuser "/var/lib/rpm/.rpm.lock" >/dev/null 2>&1; then
            return 0
        fi
    fi

    # Fallback: any obviously dnf/PackageKit related process.
    if pgrep -x dnf >/dev/null 2>&1; then
        return 0
    fi
    if pgrep -f -i 'packagekitd' >/dev/null 2>&1; then
        return 0
    fi

    return 1
}

# Check if we're running an update-style command
STATUS_DIR="/var/log/dnf-auto"
STATUS_FILE="$STATUS_DIR/download-status.txt"

if [[ "$*" == *"dup"* ]] || [[ "$*" == *"dist-upgrade"* ]] || [[ "$*" == *"update"* ]] || [[ "$*" == *"upgrade"* ]]; then
    # For interactive runs, publish a best-effort "downloading" status so the
    # desktop notifier can show a progress bar while the user is running
    # interactive dnf upgrades. We don't know the package count in advance
    # here, so we mark the total as 0 and treat that as "unknown" on the
    # notifier side.
    sudo mkdir -p "$STATUS_DIR" >/dev/null 2>&1 || true
    sudo bash -c "echo 'downloading:0:manual:0:0' > '$STATUS_FILE'" >/dev/null 2>&1 || true

    # Optionally warn if another package tool currently holds the lock, but
    # always let dnf handle locking itself so behaviour matches a direct
    # 'sudo dnf' call. This avoids the wrapper "locking out" user-initiated
    # updates when a short-lived background task briefly holds the lock.
    if has_pkg_lock; then
        echo ""
        echo "Warning: system management appears to be locked by another update tool (dnf/PackageKit)."
        echo "Lock diagnostics:"

        # Show dnf.pid owner if present
        if [ -f "/run/dnf.pid" ] || [ -f "/var/run/dnf.pid" ]; then
            lock_pid_file="/run/dnf.pid"
            [ -f "/var/run/dnf.pid" ] && lock_pid_file="/var/run/dnf.pid"
            lock_pid=$(cat "$lock_pid_file" 2>/dev/null || echo "")
            if [ -n "$lock_pid" ] && kill -0 "$lock_pid" 2>/dev/null; then
                lock_comm=$(ps -p "$lock_pid" -o comm= 2>/dev/null || echo "")
                lock_cmd=$(ps -p "$lock_pid" -o args= 2>/dev/null || echo "")
                echo "  dnf.pid owner: PID=$lock_pid, COMMAND=$lock_comm"
                echo "  Full command: $lock_cmd"
            else
                echo "  dnf.pid exists at $lock_pid_file, but PID '$lock_pid' is not running (stale lock?)"
            fi
        else
            echo "  No dnf.pid lock file present."
        fi

        # Show RPM DB lock owners if available
        if [ -f "/var/lib/rpm/.rpm.lock" ] && command -v fuser >/dev/null 2>&1; then
            rpm_lock_info=$(fuser "/var/lib/rpm/.rpm.lock" 2>&1 || echo "")
            if [ -n "$rpm_lock_info" ]; then
                echo "  RPM DB lock owners (fuser /var/lib/rpm/.rpm.lock): $rpm_lock_info"
            else
                echo "  RPM DB lock present but fuser reports no active owner."
            fi
        fi

        echo "Running dnf anyway; if the lock is still active, dnf will print its own error."
        echo ""
    fi

    # Run the actual dnf command (also handle dup/dist-upgrade as upgrade)
    if [[ "$*" == *"dup"* ]] || [[ "$*" == *"dist-upgrade"* ]]; then
        sudo /usr/bin/dnf upgrade -y
    else
        sudo /usr/bin/dnf "$@"
    fi
    EXIT_CODE=$?

    # Clear the manual downloading state so the notifier stops showing
    # a progress bar once the interactive session has finished.
    sudo bash -c "echo 'idle' > '$STATUS_FILE'" >/dev/null 2>&1 || true

    # Always run Flatpak and Snap updates after an upgrade, even if the upgrade had no updates or failed
    echo ""
    echo "=========================================="
    echo "  Flatpak Updates"
    echo "=========================================="
    echo ""
    
    if [[ "${ENABLE_FLATPAK_UPDATES,,}" == "true" ]]; then
        if command -v flatpak >/dev/null 2>&1; then
            if sudo flatpak update -y; then
                echo "✅ Flatpak updates completed."
            else
                echo "⚠️  Flatpak update failed (continuing)."
            fi
        else
            echo "⚠️  Flatpak is not installed - skipping Flatpak updates."
            echo "   To install: sudo dnf install flatpak"
        fi
    else
        echo "ℹ️  Flatpak updates are disabled in /etc/dnf-auto.conf (ENABLE_FLATPAK_UPDATES=false)."
    fi

    echo ""
    echo "=========================================="
    echo "  Snap Updates"
    echo "=========================================="
    echo ""
    
    if [[ "${ENABLE_SNAP_UPDATES,,}" == "true" ]]; then
        if command -v snap >/dev/null 2>&1; then
            if pkexec snap refresh; then
                echo "✅ Snap updates completed."
            else
                echo "⚠️  Snap refresh failed (continuing)."
            fi
        else
            echo "⚠️  Snapd is not installed - skipping Snap updates."
            echo "   To install: sudo dnf install snapd"
            echo "   Then enable: sudo systemctl enable --now snapd"
        fi
    else
        echo "ℹ️  Snap updates are disabled in /etc/dnf-auto.conf (ENABLE_SNAP_UPDATES=false)."
    fi

    echo ""
    echo "==========================================" 
    echo "  Soar (stable) Update & Sync (optional)"
    echo "=========================================="
    echo ""

        if command -v soar >/dev/null 2>&1; then
        # Run the Soar installer/updater in a subshell with set +e to ensure
        # that any errors cannot kill the interactive dnf session.
        (
            set +e

            # First, check if a newer *stable* Soar release exists on GitHub.
            # We compare the local "soar --version" against
            # https://api.github.com/repos/pkgforge/soar/releases/latest (stable only).
            if command -v curl >/dev/null 2>&1; then
                echo "Checking for newer stable Soar release from GitHub..."

                LOCAL_VER_RAW=$(soar --version 2>/dev/null | head -n1)
                LOCAL_VER=$(echo "$LOCAL_VER_RAW" | grep -oE 'v?[0-9]+(\\.[0-9]+)*' | head -n1 || true)
                LOCAL_BASE=${LOCAL_VER#v}

                REMOTE_JSON=$(curl -fsSL "https://api.github.com/repos/pkgforge/soar/releases/latest" 2>/dev/null || true)
                # Extract the tag_name value in a simple, portable way to avoid sed backref issues
                REMOTE_VER=$(printf '%s\\n' "$REMOTE_JSON" | grep -m1 '"tag_name"' | cut -d '"' -f4 || true)
                REMOTE_BASE=${REMOTE_VER#v}

                if [ -n "$LOCAL_BASE" ] && [ -n "$REMOTE_BASE" ]; then
                    LATEST=$(printf '%s\\n%s\\n' "$LOCAL_BASE" "$REMOTE_BASE" | sort -V | tail -n1)
                    if [ "$LATEST" = "$REMOTE_BASE" ] && [ "$LOCAL_BASE" != "$REMOTE_BASE" ]; then
                        echo "New stable Soar available ($LOCAL_VER -> $REMOTE_VER), updating..."
                        if ! curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh; then
                            echo "⚠️  Soar update from GitHub failed (continuing)."
                        fi
                    else
                        echo "Soar is already up to date (local: ${LOCAL_VER:-unknown}, latest stable: ${REMOTE_VER:-unknown})."
                    fi
                else
                    echo "Could not determine Soar versions; running installer to ensure latest stable."
                    if ! curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh; then
                        echo "⚠️  Soar installer from GitHub failed (continuing)."
                    fi
                fi
            else
                echo "⚠️  curl is not installed; skipping automatic Soar update from GitHub."
                echo "    You can update Soar manually from: https://github.com/pkgforge/soar/releases"
            fi

            # Then run the usual metadata sync.
            if soar sync; then
                echo "✅ Soar sync completed."
                # Optionally refresh Soar-managed apps that support "soar update".
                if soar update; then
                    echo "✅ Soar update completed."
                else
                    echo "⚠️  Soar update failed (continuing)."
                fi
            else
                echo "⚠️  Soar sync failed (continuing)."
            fi
        )
    else
        echo "ℹ️  Soar is not installed - skipping Soar update/sync."
        echo "    Install from: https://github.com/pkgforge/soar/releases"
        if [ -x /usr/local/bin/dnf-auto-helper ]; then
            echo "    Or via helper: dnf-auto-helper --soar"
        fi
    fi

    echo ""
    echo "=========================================="
    echo "  Homebrew (brew) Updates (optional)"
    echo "=========================================="
    echo ""

    if [[ "${ENABLE_BREW_UPDATES,,}" != "true" ]]; then
        echo "ℹ️  Homebrew updates are disabled in /etc/dnf-auto.conf (ENABLE_BREW_UPDATES=false)."
        echo "    You can still run 'brew update' / 'brew upgrade' manually."
        echo ""
    else
        # Try to detect Homebrew in PATH or the default Linuxbrew prefix
        if command -v brew >/dev/null 2>&1 || [ -x "/home/linuxbrew/.linuxbrew/bin/brew" ]; then
            # Normalise brew command path
            if command -v brew >/dev/null 2>&1; then
                BREW_BIN="brew"
            else
                BREW_BIN="/home/linuxbrew/.linuxbrew/bin/brew"
            fi

            echo "Checking for Homebrew updates from GitHub (brew update)..."
            if ! $BREW_BIN update; then
                echo "⚠️  Homebrew 'brew update' failed (continuing without brew upgrade)."
            else
                # After syncing with GitHub, see if anything needs upgrading
                OUTDATED=$($BREW_BIN outdated --quiet 2>/dev/null || true)
                OUTDATED_COUNT=$(printf '%s\n' "$OUTDATED" | sed '/^$/d' | wc -l | tr -d ' ')

                if [ "${OUTDATED_COUNT:-0}" -eq 0 ]; then
                    echo "Homebrew is already up to date (no formulae to upgrade)."
                else
                    echo "Homebrew has ${OUTDATED_COUNT} outdated formulae; running 'brew upgrade'..."
                    if $BREW_BIN upgrade; then
                        echo "✅ Homebrew upgrade completed (upgraded ${OUTDATED_COUNT} formulae)."
                    else
                        echo "⚠️  Homebrew 'brew upgrade' failed (continuing)."
                    fi
                fi
            fi
        else
            echo "ℹ️  Homebrew (brew) is not installed - skipping brew update/upgrade."
            if [ -x /usr/local/bin/dnf-auto-helper ]; then
                echo "    To install via helper: sudo dnf-auto-helper --brew"
            fi
        fi
    fi

    echo ""
    echo "=========================================="
    echo "  Python (pipx) Updates (optional)"
    echo "=========================================="
    echo ""

    if [[ "${ENABLE_PIPX_UPDATES,,}" != "true" ]]; then
        echo "ℹ️  pipx updates are disabled in /etc/dnf-auto.conf (ENABLE_PIPX_UPDATES=false)."
        echo "    You can still manage Python CLI tools manually with pipx."
        echo ""
    else
        if command -v pipx >/dev/null 2>&1; then
            echo "Upgrading all pipx-managed Python command-line tools (pipx upgrade-all)..."
            if pipx upgrade-all; then
                echo "✅ pipx upgrade-all completed."
            else
                echo "⚠️  pipx upgrade-all failed (continuing)."
            fi
        else
            echo "ℹ️  pipx is not installed - skipping Python CLI (pipx) updates."
            if [ -x /usr/local/bin/dnf-auto-helper ]; then
                echo "    Recommended: dnf-auto-helper --pip-package (run without sudo)"
            fi
        fi
    fi

    echo ""

    # Always show service restart info, even if dnf reported errors
    echo "=========================================="
    echo "  Post-Update Service Check"
    echo "=========================================="
    echo ""
    echo "Checking which services need to be restarted..."
    echo ""
    
    # On Fedora, use 'needs-restarting' (from dnf-plugins-core) to show
    # services and processes using old libraries, if available.
    if command -v needs-restarting >/dev/null 2>&1; then
        NEEDS_OUTPUT=$(sudo needs-restarting 2>/dev/null || true)
        echo "$NEEDS_OUTPUT"
    else
        NEEDS_OUTPUT=""
        echo "'needs-restarting' not found. Install 'dnf-plugins-core' for detailed restart information."
    fi
    
    # Check if there are any running processes that require restart
    if [ -n "$NEEDS_OUTPUT" ]; then
        echo ""
        echo "ℹ️  Services listed above are using old library versions."
        echo ""
        echo "What this means:"
        echo "  • These services/processes are still running old code in memory"
        echo "  • They should be restarted to use the updated libraries"
        echo ""
        echo "Options:"
        echo "  1. Restart individual services: systemctl restart <service>"
        echo "  2. Reboot your system (recommended for kernel/system updates)"
        echo ""
    else
        echo "✅ No services require restart. You're all set!"
        echo ""
    fi
    
    exit $EXIT_CODE
else
    # Not an update-style command, just pass through to dnf
    sudo /usr/bin/dnf "$@"
fi
EOF
chown "$SUDO_USER:$SUDO_USER" "$DNF_WRAPPER_PATH"
chmod +x "$DNF_WRAPPER_PATH"
log_success "DNF wrapper script created and made executable"

# Add shell alias/function to user's shell config
log_info ">>> Adding dnf alias to shell configurations..."
update_status "Configuring shell aliases..."

# Bash configuration
if [ -f "$SUDO_USER_HOME/.bashrc" ]; then
    log_debug "Adding dnf alias to .bashrc"
    # Remove old aliases if they exist
    sed -i '/# DNF wrapper for auto service check/d' "$SUDO_USER_HOME/.bashrc" || true
    sed -i "/alias dnf='$DNF_WRAPPER_PATH'/d" "$SUDO_USER_HOME/.bashrc" || true
    # Add new alias
    echo "" >> "$SUDO_USER_HOME/.bashrc"
    echo "# DNF wrapper for auto service check (added by dnf-auto-helper)" >> "$SUDO_USER_HOME/.bashrc"
    echo "alias dnf='$DNF_WRAPPER_PATH'" >> "$SUDO_USER_HOME/.bashrc"
    chown "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.bashrc"
    log_success "Added dnf alias to .bashrc"
fi

# Fish configuration
if [ -d "$SUDO_USER_HOME/.config/fish" ]; then
    log_debug "Adding dnf wrapper to fish config"
    FISH_CONFIG_DIR="$SUDO_USER_HOME/.config/fish/conf.d"
    mkdir -p "$FISH_CONFIG_DIR"
    FISH_ALIAS_FILE="$FISH_CONFIG_DIR/dnf-wrapper.fish"
    cat > "$FISH_ALIAS_FILE" << 'FISHEOF'
# DNF wrapper for auto service check (added by dnf-auto-helper)

# Wrap dnf command
function dnf --wraps dnf --description "Wrapper for dnf with post-update checks"
    # Call the wrapper script (which handles sudo internally)
    ~/.local/bin/dnf-with-ps $argv
end

# Wrap sudo command when used with dnf
function sudo --wraps sudo --description "Wrapper for sudo to intercept dnf commands"
    # Check if first argument is dnf
    if test (count $argv) -gt 0; and test "$argv[1]" = "dnf"
        # Remove 'dnf' from argv and call our dnf wrapper
        set -l dnf_args $argv[2..-1]
        ~/.local/bin/dnf-with-ps $dnf_args
    else
        # Not a dnf command, use real sudo
        command sudo $argv
    end
end
FISHEOF
    chown -R "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.config/fish"
    log_success "Added dnf wrapper functions to fish config"
fi

# Zsh configuration
if [ -f "$SUDO_USER_HOME/.zshrc" ]; then
    log_debug "Adding dnf alias to .zshrc"
    # Remove old alias if it exists
    sed -i '/# DNF wrapper for auto service check/d' "$SUDO_USER_HOME/.zshrc" || true
    sed -i "/alias dnf='$DNF_WRAPPER_PATH'/d" "$SUDO_USER_HOME/.zshrc" || true
    # Add new alias
    echo "" >> "$SUDO_USER_HOME/.zshrc"
    echo "# DNF wrapper for auto service check (added by dnf-auto-helper)" >> "$SUDO_USER_HOME/.zshrc"
    echo "alias dnf='$DNF_WRAPPER_PATH'" >> "$SUDO_USER_HOME/.zshrc"
    chown "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.zshrc"
    log_success "Added dnf alias to .zshrc"
fi

log_success "Shell aliases configured. Restart your shell or run 'source ~/.bashrc' (or equivalent) to activate."

# --- 7c. Add dnf-auto-helper command alias to shells ---
log_info ">>> Adding dnf-auto-helper command alias to shell configurations..."
update_status "Configuring dnf-auto-helper aliases..."

# Bash configuration for dnf-auto-helper
if [ -f "$SUDO_USER_HOME/.bashrc" ]; then
    log_debug "Adding dnf-auto-helper alias to .bashrc"
    # Remove old alias if it exists
    sed -i '/# dnf-auto-helper command alias/d' "$SUDO_USER_HOME/.bashrc" || true
    sed -i '/alias dnf-auto-helper=/d' "$SUDO_USER_HOME/.bashrc" || true
    # Add new alias
    echo "" >> "$SUDO_USER_HOME/.bashrc"
    echo "# dnf-auto-helper command alias (added by dnf-auto-helper)" >> "$SUDO_USER_HOME/.bashrc"
    echo "alias dnf-auto-helper='sudo /usr/local/bin/dnf-auto-helper'" >> "$SUDO_USER_HOME/.bashrc"
    chown "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.bashrc"
    log_success "Added dnf-auto-helper alias to .bashrc"
fi

# Fish configuration for dnf-auto-helper
if [ -d "$SUDO_USER_HOME/.config/fish" ]; then
    log_debug "Adding dnf-auto-helper alias to fish config"
    FISH_HELPER_FILE="$SUDO_USER_HOME/.config/fish/conf.d/dnf-auto-helper-alias.fish"
    cat > "$FISH_HELPER_FILE" << 'FISHHELPER'
# dnf-auto-helper command alias (added by dnf-auto-helper)
alias dnf-auto-helper='sudo /usr/local/bin/dnf-auto-helper'
FISHHELPER
    chown "$SUDO_USER:$SUDO_USER" "$FISH_HELPER_FILE"
    log_success "Added dnf-auto-helper alias to fish config"
fi

# Zsh configuration for dnf-auto-helper
if [ -f "$SUDO_USER_HOME/.zshrc" ]; then
    log_debug "Adding dnf-auto-helper alias to .zshrc"
    # Remove old alias if it exists
    sed -i '/# dnf-auto-helper command alias/d' "$SUDO_USER_HOME/.zshrc" || true
    sed -i '/alias dnf-auto-helper=/d' "$SUDO_USER_HOME/.zshrc" || true
    # Add new alias
    echo "" >> "$SUDO_USER_HOME/.zshrc"
    echo "# dnf-auto-helper command alias (added by dnf-auto-helper)" >> "$SUDO_USER_HOME/.zshrc"
    echo "alias dnf-auto-helper='sudo /usr/local/bin/dnf-auto-helper'" >> "$SUDO_USER_HOME/.zshrc"
    chown "$SUDO_USER:$SUDO_USER" "$SUDO_USER_HOME/.zshrc"
    log_success "Added dnf-auto-helper alias to .zshrc"
fi

log_success "dnf-auto-helper command aliases configured for all shells."

# --- 8. Create/Update NOTIFIER (User Service) ---
log_info ">>> Creating (user) notifier service: ${NT_SERVICE_FILE}"
update_status "Creating user notifier service..."
log_debug "Writing user service file: ${NT_SERVICE_FILE}"
cat << EOF > ${NT_SERVICE_FILE}
[Unit]
Description=Notify user of pending system updates
Wants=network-online.target
After=network-online.target nss-lookup.target

[Service]
Type=oneshot
StandardOutput=append:${USER_LOG_DIR}/notifier.log
StandardError=append:${USER_LOG_DIR}/notifier-error.log
Environment=ZNH_CACHE_EXPIRY_MINUTES=${CACHE_EXPIRY_MINUTES}
Environment=ZNH_SNOOZE_SHORT_HOURS=${SNOOZE_SHORT_HOURS}
Environment=ZNH_SNOOZE_MEDIUM_HOURS=${SNOOZE_MEDIUM_HOURS}
Environment=ZNH_SNOOZE_LONG_HOURS=${SNOOZE_LONG_HOURS}
ExecStart=/usr/bin/python3 ${NOTIFY_SCRIPT_PATH}
EOF
chown "$SUDO_USER:$SUDO_USER" "${NT_SERVICE_FILE}"
log_success "User notifier service file created"

# --- 9. Create/Update NOTIFIER (User Timer) ---
log_info ">>> Creating (user) notifier timer: ${NT_TIMER_FILE}"
log_debug "Writing user timer file: ${NT_TIMER_FILE}"
cat << EOF > ${NT_TIMER_FILE}
[Unit]
Description=Run ${NT_SERVICE_NAME} every minute to check for updates

[Timer]
# First run a few seconds after the user manager starts,
# then re-run every minute.
OnBootSec=5sec
OnCalendar=minutely
Persistent=true

[Install]
WantedBy=timers.target
EOF
chown "$SUDO_USER:$SUDO_USER" "${NT_TIMER_FILE}"
log_success "User notifier timer file created"

# --- 10. Create/Update Notification Script (v47 Python with logging) ---
log_info ">>> Creating (user) Python notification script: ${NOTIFY_SCRIPT_PATH}"
update_status "Creating Python notifier script..."
log_debug "Writing Python script to: ${NOTIFY_SCRIPT_PATH}"
cat << 'EOF' > ${NOTIFY_SCRIPT_PATH}
#!/usr/bin/env python3
#
# dnf-notify-updater.py (v53 with snooze controls and safety preflight)
#
# This script is run as the USER. It uses PyGObject (gi)
# to create a robust, clickable notification.

import sys
import subprocess
import os
import re
import time
import shlex
from datetime import datetime, timedelta
from pathlib import Path

DEBUG = os.getenv("ZNH_DEBUG", "").lower() in ("1", "true", "yes", "debug")

# Logging setup
LOG_DIR = Path.home() / ".local" / "share" / "dnf-notify"
LOG_FILE = LOG_DIR / "notifier-detailed.log"
STATUS_FILE = LOG_DIR / "last-run-status.txt"
HISTORY_FILE = LOG_DIR / "update-history.log"
MAX_LOG_SIZE = 5 * 1024 * 1024  # 5MB
MAX_HISTORY_SIZE = 1 * 1024 * 1024  # 1MB

# Cache directory
CACHE_DIR = Path.home() / ".cache" / "dnf-notify"
CACHE_FILE = CACHE_DIR / "last_check.txt"
SNOOZE_FILE = CACHE_DIR / "snooze_until.txt"
CACHE_EXPIRY_MINUTES = 10

# Global config path for dnf-auto-helper
CONFIG_FILE = "/etc/dnf-auto.conf"
# Cache and snooze configuration (overridable via environment, see systemd unit)
def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    if not raw:
        return default
    try:
        value = int(raw)
        if value <= 0:
            return default
        return value
    except ValueError:
        return default

CACHE_EXPIRY_MINUTES = _int_env("ZNH_CACHE_EXPIRY_MINUTES", 10)
SNOOZE_SHORT_HOURS = _int_env("ZNH_SNOOZE_SHORT_HOURS", 1)
SNOOZE_MEDIUM_HOURS = _int_env("ZNH_SNOOZE_MEDIUM_HOURS", 4)
SNOOZE_LONG_HOURS = _int_env("ZNH_SNOOZE_LONG_HOURS", 24)

# Ensure directories exist
LOG_DIR.mkdir(parents=True, exist_ok=True)
CACHE_DIR.mkdir(parents=True, exist_ok=True)

def rotate_log_if_needed():
    """Rotate log file if it exceeds MAX_LOG_SIZE."""
    try:
        if LOG_FILE.exists() and LOG_FILE.stat().st_size > MAX_LOG_SIZE:
            backup = LOG_FILE.with_suffix(".log.old")
            if backup.exists():
                backup.unlink()
            LOG_FILE.rename(backup)
    except Exception as e:
        print(f"Failed to rotate log: {e}", file=sys.stderr)

def log_to_file(level: str, msg: str) -> None:
    """Write log message to file with timestamp."""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] [{level}] {msg}\n")
    except Exception as e:
        print(f"Failed to write log: {e}", file=sys.stderr)

def log_info(msg: str) -> None:
    """Log info message."""
    log_to_file("INFO", msg)
    print(f"[INFO] {msg}")

def log_error(msg: str) -> None:
    """Log error message."""
    log_to_file("ERROR", msg)
    print(f"[ERROR] {msg}", file=sys.stderr)

def log_debug(msg: str) -> None:
    """Log debug message."""
    if DEBUG:
        log_to_file("DEBUG", msg)
        print(f"[DEBUG] {msg}", file=sys.stderr)

def update_status(status: str) -> None:
    """Update the status file with current state."""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(STATUS_FILE, "w", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {status}\n")
    except Exception as e:
        log_error(f"Failed to update status file: {e}")

# --- Helper: read extra dup flags from CONFIG_FILE (/etc/dnf-auto.conf by default) ---

def _read_dup_extra_flags() -> list[str]:
    """Read DUP_EXTRA_FLAGS from CONFIG_FILE (usually /etc/dnf-auto.conf), if set.

    The value is split using shell-like rules so users can write e.g.:
        DUP_EXTRA_FLAGS="--allow-vendor-change --from my-repo"
    """
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if not stripped.startswith("DUP_EXTRA_FLAGS"):
                    continue
                # Expect shell-style "NAME=VALUE"
                parts = stripped.split("=", 1)
                if len(parts) != 2:
                    continue
                raw = parts[1].strip()
                # Remove optional surrounding quotes
                if (raw.startswith("\"") and raw.endswith("\"")) or (
                    raw.startswith("'") and raw.endswith("'")
                ):
                    raw = raw[1:-1]
                try:
                    return shlex.split(raw)
                except Exception as e:
                    log_debug(f"Failed to parse DUP_EXTRA_FLAGS='{raw}': {e}")
                    return []
    except FileNotFoundError:
        return []
    except Exception as e:
        log_debug(f"Failed to read {CONFIG_FILE} for DUP_EXTRA_FLAGS: {e}")
        return []


def _read_bool_from_config(name: str, default: bool) -> bool:
    """Best-effort boolean reader for CONFIG_FILE (usually /etc/dnf-auto.conf).

    Accepts typical shell-style booleans such as true/false, yes/no,
    on/off, 1/0 (case-insensitive after stripping quotes and spaces).
    """
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if not stripped.startswith(name + "="):
                    continue
                parts = stripped.split("=", 1)
                if len(parts) != 2:
                    continue
                raw = parts[1].strip().strip("'\"").strip()
                value = raw.lower()
                if value in ("1", "true", "yes", "on", "enabled"):
                    return True
                if value in ("0", "false", "no", "off", "disabled"):
                    return False
        return default
    except FileNotFoundError:
        return default
    except Exception as e:
        log_debug(f"Failed to read {CONFIG_FILE} for {name}: {e}")
        return default


DUP_EXTRA_FLAGS = _read_dup_extra_flags()
LOCK_REMINDER_ENABLED = _read_bool_from_config("LOCK_REMINDER_ENABLED", True)
NO_UPDATES_REMINDER_REPEAT_ENABLED = _read_bool_from_config("NO_UPDATES_REMINDER_REPEAT_ENABLED", True)
UPDATES_READY_REMINDER_REPEAT_ENABLED = _read_bool_from_config("UPDATES_READY_REMINDER_REPEAT_ENABLED", True)

# --- Caching Functions ---
def read_cache():
    """Read cached update check results.
    Returns: (timestamp, package_count, snapshot) or None if cache invalid/missing.
    """
    try:
        if not CACHE_FILE.exists():
            return None
        
        with open(CACHE_FILE, 'r') as f:
            line = f.read().strip()
            parts = line.split('|')
            if len(parts) != 3:
                return None
            
            timestamp_str, pkg_count, snapshot = parts
            cache_time = datetime.fromisoformat(timestamp_str)
            
            # Check if cache is still valid
            age_minutes = (datetime.now() - cache_time).total_seconds() / 60
            if age_minutes > CACHE_EXPIRY_MINUTES:
                log_debug(f"Cache expired (age: {age_minutes:.1f} minutes)")
                return None
            
            log_debug(f"Cache hit (age: {age_minutes:.1f} minutes)")
            return cache_time, int(pkg_count), snapshot
    except Exception as e:
        log_debug(f"Failed to read cache: {e}")
        return None

def write_cache(package_count: int, snapshot: str) -> None:
    """Write update check results to cache."""
    try:
        timestamp = datetime.now().isoformat()
        with open(CACHE_FILE, 'w') as f:
            f.write(f"{timestamp}|{package_count}|{snapshot}")
        log_debug(f"Cache written: {package_count} packages, snapshot {snapshot}")
    except Exception as e:
        log_debug(f"Failed to write cache: {e}")

# --- Snooze Functions ---
def check_snoozed() -> bool:
    """Check if updates are currently snoozed.
    Returns True if snoozed, False otherwise.
    """
    try:
        if not SNOOZE_FILE.exists():
            return False
        
        with open(SNOOZE_FILE, 'r') as f:
            snooze_until_str = f.read().strip()
            snooze_until = datetime.fromisoformat(snooze_until_str)
            
            if datetime.now() < snooze_until:
                remaining = snooze_until - datetime.now()
                hours = remaining.total_seconds() / 3600
                log_info(f"Updates snoozed for {hours:.1f} more hours")
                return True
            else:
                # Snooze expired, remove file
                SNOOZE_FILE.unlink()
                log_info("Snooze expired, removing snooze file")
                return False
    except Exception as e:
        log_debug(f"Failed to check snooze: {e}")
        return False

def set_snooze(hours: int) -> None:
    """Set snooze for specified number of hours."""
    try:
        snooze_until = datetime.now() + timedelta(hours=hours)
        with open(SNOOZE_FILE, 'w') as f:
            f.write(snooze_until.isoformat())
        log_info(f"Updates snoozed for {hours} hours until {snooze_until.strftime('%Y-%m-%d %H:%M')}")
    except Exception as e:
        log_error(f"Failed to set snooze: {e}")

# --- History Logging ---
def log_update_history(snapshot: str, package_count: int) -> None:
    """Log update installation to history file."""
    try:
        # Rotate history if needed
        if HISTORY_FILE.exists() and HISTORY_FILE.stat().st_size > MAX_HISTORY_SIZE:
            backup = HISTORY_FILE.with_suffix(".log.old")
            if backup.exists():
                backup.unlink()
            HISTORY_FILE.rename(backup)
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(HISTORY_FILE, 'a') as f:
            f.write(f"[{timestamp}] Installed snapshot {snapshot} with {package_count} packages\n")
        log_info(f"Update history logged: {snapshot}")
    except Exception as e:
        log_error(f"Failed to log update history: {e}")

# --- Safety Checks ---
def check_disk_space() -> tuple[bool, str]:
    """Check if there's enough disk space for updates.
    Returns: (has_space, message)
    """
    try:
        result = subprocess.run(
            ['df', '-BG', '/'],
            capture_output=True,
            text=True,
            check=True
        )
        lines = result.stdout.strip().split('\n')
        if len(lines) < 2:
            return True, "Could not determine disk space"
        
        # Parse df output: Filesystem 1G-blocks Used Available Use% Mounted
        fields = lines[1].split()
        if len(fields) < 4:
            return True, "Could not parse disk space"
        
        available_str = fields[3].rstrip('G')
        available_gb = int(available_str)
        
        if available_gb < 5:
            msg = f"Only {available_gb}GB free. 5GB required for updates."
            log_info(msg)
            return False, msg
        
        log_debug(f"Disk space check passed: {available_gb}GB available")
        return True, f"{available_gb}GB available"
    except Exception as e:
        log_debug(f"Disk space check failed: {e}")
        return True, "Could not check disk space"

def check_snapshots() -> tuple[bool, str]:
    """Check for filesystem snapshots using snapper, if available.

    This is intentionally distro-agnostic: on any system where the
    `snapper` tool is installed and configured, we report whether
    snapshots exist and return a short human-readable message.

    Returns: (has_snapshots, message)
    - has_snapshots=True  => at least one snapshot exists
    - has_snapshots=False => snapper not installed, not configured, or zero snapshots
    """
    # First, see if snapper is installed and if there is a root config
    try:
        cfg_result = subprocess.run(
            ['snapper', 'list-configs'],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except FileNotFoundError:
        msg = "Snapper not installed"
        log_info(msg)
        return False, msg
    except Exception as e:
        log_debug(f"Snapshot config check failed: {e}")
        return False, "Could not check snapshots"

    has_config = False
    root_config = False
    if cfg_result.returncode == 0 and cfg_result.stdout.strip():
        for line in cfg_result.stdout.strip().split('\n'):
            line = line.strip()
            if not line or line.startswith('Config'):
                continue
            parts = [p.strip() for p in line.split('|')]
            if len(parts) < 2:
                continue
            name = parts[1]
            if not name:
                continue
            has_config = True
            if name == 'root':
                root_config = True

    # Now check the actual snapshots
    try:
        result = subprocess.run(
            ['snapper', 'list'],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception as e:
        log_debug(f"Snapshot list check failed: {e}")
        if root_config or has_config:
            msg = "Snapper configured (root) but snapshot list not available"
            log_info(msg)
            return False, msg
        return False, "Could not check snapshots"

    # Combine stdout/stderr for permission checks
    out_all = (result.stdout or "") + "\n" + (result.stderr or "")
    if "No permissions" in out_all:
        # On openSUSE Tumbleweed with Btrfs, this usually means snapshots
        # exist but are only visible to root. Treat this as "snapshots
        # present" but explain the limitation.
        if root_config or has_config:
            msg = "Snapper snapshots exist (root-only; run as root to view)"
        else:
            msg = "Snapper present but requires root to view snapshots"
        log_info(msg)
        return True, msg

    if result.returncode == 0:
        lines = [ln for ln in result.stdout.split('\n') if ln.strip()]

        # snapper list normally has 2 header lines; anything beyond that is a snapshot
        if len(lines) > 2:
            snapshot_count = len(lines) - 2
            log_debug(f"Snapper is working, {snapshot_count} snapshots available")
            return True, f"{snapshot_count} snapshots available"
        if root_config or has_config:
            msg = "Snapper configured (root) but no snapshots yet"
            log_info(msg)
            return False, msg
        msg = "Snapper not configured or no snapshots"
        log_info(msg)
        return False, msg

    # Non-zero return code from snapper list (and no explicit "No permissions")
    if root_config or has_config:
        msg = "Snapper configured (root) but snapshot list failed"
        log_info(msg)
        return False, msg

    msg = "Snapper not configured or no snapshots"
    log_info(msg)
    return False, msg
def check_network_quality() -> tuple[bool, str]:
    """Check connectivity using NetworkManager (firewall friendly).

    Returns: (is_good, message)
    """
    try:
        # nmcli general reports overall connectivity state for the host.
        # We treat "full" and "limited" as usable so that captive portals or
        # partial connectivity still allow the updater to run, but anything
        # else ("none", "portal", "unknown") is treated as a failure.
        result = subprocess.run(
            ['nmcli', '-t', '-f', 'CONNECTIVITY', 'general'],
            capture_output=True,
            text=True,
            timeout=5,
        )
        status = (result.stdout or '').strip().lower()
        log_debug(f"nmcli connectivity status: {status or 'empty'}")

        if status == "full":
            return True, "Network connection is full"
        if status == "limited":
            # Limited connectivity is often a captive portal; allow but log.
            log_info("Network connectivity is limited (possibly captive portal)")
            return True, "Network is limited (captive portal?)"

        if not status:
            msg = "Network connectivity status unknown"
        else:
            msg = f"Network status: {status}"
        log_info(msg)
        return False, msg
    except Exception as e:
        # If NetworkManager/nmcli is unavailable or misconfigured, don't
        # block updates entirely – just log and fall back to "unknown".
        log_debug(f"NMCLI connectivity check failed: {e}")
        return True, "Network check skipped"


def is_package_manager_locked(stderr_text: str | None = None) -> bool:
    """Best-effort detection of a dnf/PackageKit lock.

    Checks stderr text for common lock messages and the dnf lock file
    (/var/run/dnf.pid) plus a few common lock-owner processes
    (dnf, dnf-automatic, packagekitd).
    """
    KNOWN_LOCK_OWNERS = ("dnf", "dnf-automatic", "packagekitd")
    try:
        # If the tool already told us "System management is locked", trust that.
        lower_err = (stderr_text or "").lower()
        if any(tok in lower_err for tok in (
            "system management is locked",
            "another app is currently holding the dnf lock",
            "dnf is locked by another process",
            "existing lock",
        )):
            return True

        # Look at the canonical dnf lock file first; verify that the PID
        # really belongs to a known dnf/PackageKit-style process.
        for pid_file in ("/var/run/dnf.pid", "/run/dnf.pid"):
            try:
                with open(pid_file, "r", encoding="utf-8") as f:
                    pid_str = f.read().strip()
                if not pid_str:
                    continue
                pid = int(pid_str)
            except (OSError, ValueError):
                continue

            try:
                comm = subprocess.check_output(
                    ["ps", "-p", str(pid), "-o", "comm="],
                    text=True,
                    stderr=subprocess.DEVNULL,
                ).strip().lower()
            except subprocess.CalledProcessError:
                comm = ""

            try:
                cmd = subprocess.check_output(
                    ["ps", "-p", str(pid), "-o", "args="],
                    text=True,
                    stderr=subprocess.DEVNULL,
                ).strip().lower()
            except subprocess.CalledProcessError:
                cmd = ""

            candidate = comm + " " + cmd
            if candidate and any(tok in candidate for tok in KNOWN_LOCK_OWNERS):
                return True

        # Fallback: scan the process list for any obviously dnf/PackageKit
        # style processes even if the lock file is missing or stale.
        try:
            ps_out = subprocess.check_output(
                ["ps", "-eo", "comm="], text=True, stderr=subprocess.DEVNULL
            ).lower()
            if any(owner in ps_out for owner in KNOWN_LOCK_OWNERS):
                return True
        except Exception:
            pass

    except Exception as e:
        log_debug(f"Lock detection failed: {e}")

    return False


# Rotate log at startup if needed
rotate_log_if_needed()
log_info("=" * 60)
log_info("DNF Notify Updater started")
update_status("Starting update check...")

try:
    import gi
    gi.require_version("Notify", "0.7")
    from gi.repository import Notify, GLib
    log_debug("PyGObject imported successfully")
except ImportError as e:
    log_error(f"PyGObject (gi) not found: {e}")
    update_status("FAILED: PyGObject not available")
    sys.exit(1)

def has_battery_via_inxi() -> bool:
    """Use inxi to detect if the system reports a real battery.

    We look for a Battery section in `inxi -Bazy` output.
    """
    try:
        out = subprocess.check_output(
            ["inxi", "-Bazy"], text=True, stderr=subprocess.DEVNULL
        )
        log_debug("inxi battery check executed")
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        log_debug(f"inxi battery check failed: {e}")
        return False

    # Check if output contains both Battery: and ID- (can be on different lines)
    if "Battery:" in out and "ID-" in out:
        log_debug("Battery detected via inxi")
        return True
    log_debug("No battery detected via inxi")
    return False


def detect_form_factor():
    """Detect whether this machine is a laptop or a desktop.

    Prefer inxi's Machine Type if available; fall back to upower/battery heuristics.
    Returns "laptop", "desktop", or "unknown".
    """
    log_debug("Detecting form factor...")
    # 0. If inxi reports a real battery, treat as laptop immediately.
    try:
        if has_battery_via_inxi():
            log_info("Form factor detected: laptop (via inxi battery)")
            return "laptop"
    except Exception as e:
        log_debug(f"has_battery_via_inxi failed in detect_form_factor: {e}")

    # 1. Prefer inxi's Machine Type (very reliable on most systems)
    try:
        out = subprocess.check_output(
            ["inxi", "-Mazy"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
        for line in out.splitlines():
            if "Type:" in line:
                # Example: "  Type: Laptop System: HP ..."
                val = line.split("Type:", 1)[1].strip().lower()
                if val.startswith("laptop") or "notebook" in val:
                    log_info(f"Form factor detected: laptop (via inxi Type: {val})")
                    return "laptop"
                if val.startswith("desktop") or "tower" in val or "server" in val:
                    log_info(f"Form factor detected: desktop (via inxi Type: {val})")
                    return "desktop"
    except Exception as e:
        log_debug(f"inxi -Mazy failed in detect_form_factor: {e}")

    # 2. Fall back to the previous upower + battery-based heuristic
    try:
        devices = subprocess.check_output(["upower", "-e"], text=True).strip().splitlines()
    except Exception as e:
        log_debug(f"upower -e failed in detect_form_factor: {e}")
        devices = []

    has_battery = False
    has_line_power = False

    if devices:
        try:
            for dev in devices:
                if not dev:
                    continue
                info = subprocess.check_output(["upower", "-i", dev], text=True, errors="ignore").lower()

                if "line_power" in dev:
                    has_line_power = True

                if "battery" in info:
                    # Heuristic: real laptop batteries usually have power supply yes
                    if "power supply: yes" in info or "power-supply: yes" in info:
                        has_battery = True
        except Exception as e:
            log_debug(f"upower inspection failed in detect_form_factor: {e}")

    # If upower clearly indicates laptop
    if has_battery and has_line_power:
        log_info("Form factor detected: laptop (via upower battery+line_power)")
        return "laptop"

    # If upower sees a battery but no line_power, treat as laptop as well.
    # Some laptops expose only a battery device without a separate line_power
    # entry; in that case, we must *not* classify as desktop or we will
    # incorrectly assume always-on AC power.
    if has_battery and not has_line_power:
        log_info("Form factor detected: laptop (via upower battery only)")
        return "laptop"

    # No battery seen by upower; fall back to inxi battery information
    if not has_battery:
        if has_battery_via_inxi():
            log_info("Form factor detected: laptop (fallback inxi check)")
            return "laptop"
        log_info("Form factor detected: desktop (no battery found)")
        return "desktop"

    # Last resort
    log_info("Form factor detected: unknown")
    return "unknown"


def on_ac_power(form_factor: str) -> bool:
    """Check if the system is on AC power.

    On desktops (no battery), we assume AC is effectively always on.
    """
    log_debug(f"Checking AC power status (form_factor: {form_factor})")
    if form_factor == "desktop":
        log_debug("Desktop detected, assuming AC power always available")
        return True

    try:
        devices = subprocess.check_output(["upower", "-e"], text=True).strip().splitlines()
        line_power_devices = [d for d in devices if "line_power" in d]

        if not line_power_devices:
            # Laptop but no explicit line_power device; be conservative
            log_error("No line_power device found; treating as battery (unsafe)")
            return False

        for dev in line_power_devices:
            info = subprocess.check_output(["upower", "-i", dev], text=True, errors="ignore")
            for line in info.splitlines():
                line = line.strip().lower()
                if line.startswith("online:"):
                    value = line.split(":", 1)[1].strip()
                    if value in ("yes", "true"):
                        log_info("AC power detected: plugged in")
                        return True
                    elif value in ("no", "false"):
                        log_info("AC power detected: on battery")
                        return False

        # Could not parse any 'online' line; be conservative for laptops
        log_error("Could not parse AC status; treating as battery (unsafe)")
        return False

    except Exception as e:
        # On a laptop and we truly cannot determine AC: be safe and treat as battery
        log_error(f"AC power check failed: {e}")
        return False


def is_metered() -> bool:
    """Check if any active connection is metered using nmcli.

    Uses GENERAL.METERED per active connection.
    Treats values like 'yes', 'guess-yes', 'payg' as metered.
    """
    log_debug("Checking if connection is metered...")
    try:
        # List all connections with ACTIVE flag
        output = subprocess.check_output(
            ["nmcli", "-t", "-f", "NAME,UUID,DEVICE,ACTIVE", "connection", "show"],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        log_debug(f"nmcli connection list failed for metered check: {e}")
        return False

    active_ids = []
    for line in output.strip().splitlines():
        if not line:
            continue
        parts = line.split(":")
        if len(parts) < 4:
            continue
        name, uuid, device, active = parts[:4]
        if active.strip().lower() == "yes":
            # Prefer UUID (stable), but fall back to name if missing
            ident = uuid.strip() or name.strip()
            if ident:
                active_ids.append(ident)

    if not active_ids:
        return False

    for ident in active_ids:
        m = ""
        try:
            m = subprocess.check_output(
                ["nmcli", "-g", "GENERAL.METERED", "connection", "show", ident],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip().lower()
        except subprocess.CalledProcessError as e:
            # Some nmcli versions don't support -g GENERAL.METERED; fall back
            # to parsing the full "connection show" output.
            log_debug(f"nmcli GENERAL.METERED failed for {ident}: {e}; trying full show")
            try:
                full = subprocess.check_output(
                    ["nmcli", "connection", "show", ident],
                    text=True,
                    stderr=subprocess.DEVNULL,
                )
            except subprocess.CalledProcessError as e2:
                log_debug(f"nmcli full show failed for {ident}: {e2}")
                continue

            for line in full.splitlines():
                line = line.strip()
                if line.lower().startswith("general.metered:"):
                    m = line.split(":", 1)[1].strip().lower()
                    break

        if m in ("yes", "guess-yes", "payg", "guess-payg"):
            log_info(f"Metered connection detected: {ident} is {m}")
            return True

    # All active connections are explicitly unmetered/unknown
    log_debug("No metered connections detected")
    return False


# --- Environment change tracking ---
ENV_STATE_DIR = os.path.expanduser("~/.cache/dnf-notify")
ENV_STATE_FILE = os.path.join(ENV_STATE_DIR, "env_state.txt")
LAST_NOTIFICATION_FILE = os.path.join(ENV_STATE_DIR, "last_notification.txt")


def _read_last_env_state() -> str:
    try:
        with open(ENV_STATE_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def _write_env_state(state: str) -> None:
    try:
        os.makedirs(ENV_STATE_DIR, exist_ok=True)
        with open(ENV_STATE_FILE, "w", encoding="utf-8") as f:
            f.write(state)
    except OSError as e:
        log_debug(f"Failed to write env state: {e}")


def _read_last_notification() -> str:
    """Read the last notification state (title+message)."""
    try:
        with open(LAST_NOTIFICATION_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def _write_last_notification(title: str, message: str) -> None:
    """Write the last notification state."""
    try:
        os.makedirs(ENV_STATE_DIR, exist_ok=True)
        notification_key = f"{title}|{message}"
        with open(LAST_NOTIFICATION_FILE, "w", encoding="utf-8") as f:
            f.write(notification_key)
    except OSError as e:
        log_debug(f"Failed to write last notification: {e}")


def _notify_env_change(prev_state: str, form_factor: str, on_ac: bool, metered: bool, safe: bool) -> None:
    """Track environment changes and notify once per change.

    - When conditions become *unsafe* (battery or metered), show a
      "paused" notification explaining why.
    - When they become *safe* again (AC + unmetered), show a
      "now safe" notification.
    """
    current_state = f"form_factor={form_factor}, on_ac={on_ac}, metered={metered}, safe={safe}"

    if prev_state == current_state:
        log_debug("Environment state unchanged, no notification needed")
        return  # no change

    log_info(f"Environment state changed from [{prev_state}] to [{current_state}]")
    # Always record the new state
    _write_env_state(current_state)

    # Decide a short human‑readable message
    if safe:
        title = "Update conditions now safe"
        if metered:
            # logically shouldn't happen (safe implies not metered), but guard anyway
            body = "Updates may proceed, but connection is marked metered."
        elif form_factor == "laptop" and on_ac:
            body = "Laptop is on AC power and network is unmetered. Updates can be downloaded."
        else:
            body = "Conditions are okay to download updates."
    else:
        title = "Updates paused due to conditions"
        if metered:
            body = "Active connection is metered. Background update downloads are skipped."
        elif form_factor == "laptop" and not on_ac:
            body = "Laptop is running on battery. Background update downloads are skipped."
        else:
            body = "Current conditions are not safe for background update downloads."

    log_info(f"Showing environment change notification: {title}")
    try:
        n = Notify.Notification.new(title, body, "dialog-information")
        n.set_timeout(8000)
        n.show()
    except Exception as e:
        log_error(f"Failed to show environment change notification: {e}")


def is_safe() -> bool:
    """Combined safety check.

    - desktops: don't block on AC; only check metered.
    - laptops: require AC and not metered.

    Returns True if it's safe to run a full refresh, False otherwise.
    """
    log_info("Performing safety check...")
    update_status("Checking environment conditions...")
    
    form_factor = detect_form_factor()

    # Pre-compute AC and metered status for clearer logging
    metered = is_metered()
    if form_factor == "laptop":
        on_ac = on_ac_power(form_factor)
    else:
        on_ac = True  # desktops/unknown are treated as effectively always on AC

    # Decide safety based on current conditions
    safe = (not metered) and (form_factor != "laptop" or on_ac)

    # Log environment and safety
    log_info(f"Environment: form_factor={form_factor}, on_ac={on_ac}, metered={metered}, safe={safe}")

    # Notify user if conditions changed since last run
    prev_state = _read_last_env_state()
    _notify_env_change(prev_state, form_factor, on_ac, metered, safe)

    # Apply safety policy
    if metered:
        log_info("Metered connection detected. Skipping refresh.")
        update_status("SKIPPED: Metered connection detected")
        return False

    if form_factor == "laptop":
        if not on_ac:
            log_info("Running on battery (or AC unknown). Skipping refresh.")
            update_status("SKIPPED: Running on battery")
            return False
        else:
            log_info("Laptop on AC power.")

    # Desktop or unknown: no AC restriction (already checked metered above)
    log_info("Environment is safe for updates")
    return True


def get_updates():
    """Run dnf and return the output.

    Returns:
        - stdout string from a non-interactive "dnf upgrade --assumeno" when environment is safe
        - "" (empty string) if environment is not safe and we skip dnf
        - None if dnf/PolicyKit fails
    """
    log_info("Starting update check...")

    # Run dnf in a stable C locale so that output is always English, which our
    # regex/parser expects. This avoids issues on systems where DNF is
    # localised (Spanish, German, etc.).
    base_env = os.environ.copy()
    base_env["LC_ALL"] = "C"

    try:
        safe = is_safe()

        if not safe:
            # Environment not safe (battery or metered). We already showed
            # an environment change notification, so just skip dnf.
            log_info("Environment not safe for background updates; skipping dnf.")
            return ""

        log_info("Safe to refresh. Running full check...")
        update_status("Running dnf makecache (refreshing metadata)...")
        log_debug("Executing: pkexec /usr/bin/sh -c 'LC_ALL=C /usr/bin/dnf -q makecache'")

        env = base_env.copy()
        subprocess.run(
            ["pkexec", "/usr/bin/sh", "-c", "LC_ALL=C /usr/bin/dnf -q makecache"],
            check=True,
            capture_output=True,
            env=env,
        )
        log_info("dnf makecache completed successfully")

        update_status("Running dnf upgrade --assumeno (preview)...")
        log_debug("Executing: pkexec /usr/bin/sh -c 'LC_ALL=C /usr/bin/dnf -q upgrade --assumeno'")

        # Build a shell-safe representation of extra flags so they are
        # honoured even when running under sh -c.
        shell_flags = ""  # type: str
        try:
            import shlex as _shlex_for_flags
            if DUP_EXTRA_FLAGS:
                shell_flags = " " + " ".join(_shlex_for_flags.quote(str(f)) for f in DUP_EXTRA_FLAGS)
        except Exception:
            # Fall back to a simple join if shlex is not available for some reason.
            if DUP_EXTRA_FLAGS:
                shell_flags = " " + " ".join(str(f) for f in DUP_EXTRA_FLAGS)

        cmd_str = "LC_ALL=C /usr/bin/dnf -q upgrade --assumeno" + shell_flags
        dup_cmd = ["pkexec", "/usr/bin/sh", "-c", cmd_str]
        env = base_env.copy()
        result = subprocess.run(
            dup_cmd,
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )
        log_info("dnf upgrade --assumeno completed successfully")
        return result.stdout

    except subprocess.CalledProcessError as e:
        """Handle dnf failures more intelligently.

        - Distinguish between a normal package-manager lock, PolicyKit errors,
          and solver/interaction errors.
        """
        # Normalise stderr/stdout to strings
        stderr_text = ""
        stdout_text = ""
        if e.stderr:
            stderr_text = e.stderr.decode() if isinstance(e.stderr, bytes) else str(e.stderr)
        if e.stdout:
            stdout_text = e.stdout.decode() if isinstance(e.stdout, bytes) else str(e.stdout)

        # 1) Package manager is locked by another process – this is expected sometimes.
        if is_package_manager_locked(stderr_text):
            # The helper function name is historic; it also detects generic
            # package-manager locks via lock files and process names.
            log_info("Package manager is currently locked by another process. Skipping this check.")
            update_status("SKIPPED: Package manager locked by another process")

            # Show a gentle desktop notification so the user knows why
            # the background check was skipped. This reminder runs on
            # every notifier cycle while the lock is present, unless
            # LOCK_REMINDER_ENABLED=false in /etc/dnf-auto.conf.
            if LOCK_REMINDER_ENABLED:
                try:
                    lock_note = Notify.Notification.new(
                        "Updates paused while the package manager is running",
                        "Background checks will retry automatically in about a minute.",
                        "system-software-update",
                    )
                    lock_note.set_timeout(5000)
                    lock_note.set_hint(
                        "x-canonical-private-synchronous",
                        GLib.Variant("s", "dnf-locked"),
                    )
                    lock_note.show()
                except Exception as ne:
                    log_debug(f"Could not show lock notification: {ne}")
            else:
                log_info("Lock reminder notifications are disabled via LOCK_REMINDER_ENABLED=false; skipping desktop popup.")

            return ""  # Return empty string to skip further processing in this cycle

        # 2) Check for PolicyKit / authentication style errors.
        lower_stderr = stderr_text.lower()
        polkit_markers = (
            "polkit",
            "authentication is required",
            "authentication failed",
            "not authorized",
            "not authorised",
        )
        if any(marker in lower_stderr for marker in polkit_markers):
            log_error("Policy Block Failure: PolicyKit/PAM refused command")
            update_status("FAILED: PolicyKit/PAM authentication error")
            if stderr_text:
                log_error(f"Policy Error: {stderr_text.strip()}")
            if stdout_text:
                log_debug(f"Command stdout: {stdout_text}")
            return None

        # 3) Otherwise, treat as a normal dnf/solver error that needs manual action.
        log_error("dnf preview failed: manual intervention required")
        if stderr_text:
            log_debug(f"dnf stderr: {stderr_text.strip()}")

        # Try to extract a useful hint line from stdout.
        problem_line = ""
        for line in stdout_text.splitlines():
            if line.strip().startswith("Problem:"):
                problem_line = line.strip()
                break

        if problem_line:
            summary = problem_line
        else:
            summary = "dnf upgrade --assumeno failed. See logs for detailed information."

        update_status("FAILED: dnf preview requires manual decision")
        err_title = "Updates require manual decision"
        err_message = (
            summary
            + "\n\n"
            + "Open a terminal and run:\n"
            + "  sudo dnf upgrade\n"
            + "to resolve this interactively. After that, the notifier will resume normally."
        )

        n = Notify.Notification.new(err_title, err_message, "dialog-warning")
        n.set_timeout(30000)  # 30 seconds
        n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "dnf-error"))

        # Add an action button to launch the interactive helper in a terminal
        action_script = os.path.expanduser("~/.local/bin/dnf-run-install")
        n.add_action("install", "Open Helper", on_action, action_script)

        log_info("Manual-intervention notification displayed (with Open Helper action)")

        # Run a short GLib main loop so the user can click the action
        loop = GLib.MainLoop()
        n.connect("closed", lambda *args: loop.quit())
        n.show()
        try:
            loop.run()
        except KeyboardInterrupt:
            log_info("Manual-intervention main loop interrupted")

        return None

def extract_package_preview(output: str, max_packages: int = 5) -> list:
    """Extract a preview of packages being updated.
    Returns list of package names.
    """
    packages = []
    try:
        # Look for lines that show package upgrades
        # Format: package-name | version | arch | repository
        in_upgrade_section = False
        for line in output.splitlines():
            line = line.strip()
            
            if "packages to upgrade" in line.lower():
                in_upgrade_section = True
                continue
            
            # Skip non-package summary lines that can appear in the table,
            # such as the "Package download size" section or "0 B | ... already in cache".
            lower = line.lower()
            if any(tok in lower for tok in ["package download size", "overall package size", "already in cache"]):
                continue
            
            if in_upgrade_section and "|" in line:
                # Parse package line
                parts = [p.strip() for p in line.split("|")]
                if len(parts) >= 1 and parts[0] and not parts[0].startswith("-"):
                    pkg_name = parts[0]
                    # Skip header lines and size-like pseudo "names" such as "0 B" or "12.3 MiB"
                    if pkg_name not in ["Name", "Status", "#"] and not re.match(r"^[0-9].*", pkg_name):
                        packages.append(pkg_name)
                        if len(packages) >= max_packages:
                            break
            
            # Stop if we hit another section
            if in_upgrade_section and line and not line.startswith("|") and "|" not in line:
                if packages:  # Only break if we found some packages
                    break
    except Exception as e:
        log_debug(f"Failed to extract package preview: {e}")
    
    return packages


def parse_output(output: str, include_preview: bool = True):
    """Parse DNF's transaction preview output for info.

    NOTE (DNF4 vs DNF5): This parser currently expects DNF4-style summary
    lines like "<N> packages to upgrade". If future dnf5 versions change
    this wording, the package_count may fall back to 0 even when updates
    exist; notifications will still work, but counts/previews might need
    a small regex adjustment.

    Returns: (title, message, snapshot, package_count)
             or (None, None, None, 0).
    """
    log_debug("Parsing dnf output...")
    
    if "Nothing to do." in output:
        log_info("No updates found in dnf output")
        return None, None, None, 0

    # Count Packages from DNF summary line, e.g. "Upgrade  5 Packages"
    count_match = re.search(r"Upgrade\s+(\d+)\s+Packages?", output, re.IGNORECASE)
    package_count = int(count_match.group(1)) if count_match else 0
    
    # If no packages found or count is 0, return None
    if package_count == 0:
        log_info("No packages to upgrade (count is 0)")
        return None, None, None, 0

    # Fedora/DNF: we don't try to parse an OS snapshot/version from the
    # preview output; leave snapshot empty and use a generic title.
    snapshot = ""

    log_info(f"Found {package_count} packages to upgrade")

    # Build strings
    title = "Updates Ready to Install"

    if package_count == 1:
        message = "1 update is pending."
    else:
        message = f"{package_count} updates are pending."
    
    # Add package preview if requested
    if include_preview and package_count > 0:
        preview_packages = extract_package_preview(output, max_packages=3)
        if preview_packages:
            preview_str = ", ".join(preview_packages)
            if len(preview_packages) < package_count:
                preview_str += f", and {package_count - len(preview_packages)} more"
            message += f"\n\nIncluding: {preview_str}"

    return title, message, snapshot, package_count

def on_action(notification, action_id, user_data):
    """Callback to run when an action button is clicked."""
    log_info(f"User clicked action: {action_id}")
    
    if action_id == "install":
        update_status("User initiated update installation")
        action_script = user_data
        try:
            # Prefer to launch via systemd-run so the process is clearly
            # associated with the user session and not tied to this script.
            try:
                log_debug(f"Launching install script via systemd-run: {action_script}")
                subprocess.Popen([
                    "systemd-run",
                    "--user",
                    "--scope",
                    action_script,
                ])
            except FileNotFoundError:
                # Fallback: run the script directly if systemd-run is not available.
                log_debug(f"Launching install script directly: {action_script}")
                subprocess.Popen([action_script])
            log_info("Install script launched successfully")
        except Exception as e:
            log_error(f"Failed to launch action script: {e}")
    
    elif action_id == "snooze-1h":
        set_snooze(SNOOZE_SHORT_HOURS)
        update_status(f"Updates snoozed for {SNOOZE_SHORT_HOURS} hour(s)")
    
    elif action_id == "snooze-4h":
        set_snooze(SNOOZE_MEDIUM_HOURS)
        update_status(f"Updates snoozed for {SNOOZE_MEDIUM_HOURS} hour(s)")
    
    elif action_id == "snooze-1d":
        set_snooze(SNOOZE_LONG_HOURS)
        update_status(f"Updates snoozed for {SNOOZE_LONG_HOURS} hour(s)")
    
    elif action_id == "view-changes":
        log_info("User clicked View Changes button")
        update_status("User viewing update details")
        view_script = os.path.expanduser("~/.local/bin/dnf-view-changes")
        try:
            # Make sure the script is executable
            import stat
            if os.path.exists(view_script):
                os.chmod(view_script, os.stat(view_script).st_mode | stat.S_IEXEC)
                log_debug(f"Launching view changes script via systemd-run: {view_script}")
                try:
                    subprocess.Popen([
                        "systemd-run",
                        "--user",
                        "--scope",
                        view_script,
                    ])
                except FileNotFoundError:
                    log_debug("systemd-run not found, launching directly")
                    subprocess.Popen([view_script], start_new_session=True)
                log_info("View changes script launched successfully")
            else:
                log_error(f"View changes script not found: {view_script}")
        except Exception as e:
            log_error(f"Failed to launch view changes script: {e}")
            import traceback
            log_debug(f"Traceback: {traceback.format_exc()}")
        # Don't close notification or quit loop for view changes
        return
    
    notification.close()
    GLib.MainLoop().quit()

def main():
    try:
        log_debug("Initializing notification system...")
        Notify.init("dnf-updater")
        
        # Check if updates are snoozed FIRST - skip all notifications if snoozed
        if check_snoozed():
            log_info("Updates are currently snoozed, skipping all notifications")
            return
        
        # Check if downloader is actively downloading updates
        download_status_file = "/var/log/dnf-auto/download-status.txt"
        if os.path.exists(download_status_file):
            try:
                # Treat very old statuses as stale so we don't get stuck forever
                try:
                    mtime = os.path.getmtime(download_status_file)
                    age_seconds = time.time() - mtime
                except Exception as e:
                    log_debug(f"Could not stat download status file: {e}")
                    age_seconds = 0

                with open(download_status_file, 'r') as f:
                    status = f.read().strip()

                # If status looks like an in‑progress state but is stale, ignore it
                if status in ("refreshing",) or status.startswith("downloading:"):
                    if age_seconds > 300:  # older than 5 minutes
                        log_info(f"Stale download status '{status}' (age {age_seconds:.0f}s) - ignoring and continuing to full check")
                    else:
                        # Handle stage-based status for fresh operations
                        if status == "refreshing":
                            log_info("Stage: Refreshing repositories")
                            n = Notify.Notification.new(
                                "Checking for updates...",
                                "Refreshing repositories...",
                                "emblem-synchronizing"
                            )
                            n.set_timeout(5000)  # 5 seconds
                            # Set hint to replace previous download status notifications
                            n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "dnf-download-status"))
                            n.show()
                            time.sleep(0.1)
                            return  # Exit, will check again in 5 seconds

                        elif status.startswith("downloading:"):
                            # Extract from "downloading:TOTAL:SIZE:DOWNLOADED:PERCENT" format
                            try:
                                parts = status.split(":")
                                pkg_total = parts[1] if len(parts) > 1 else "0"
                                download_size = parts[2] if len(parts) > 2 else "unknown size"
                                pkg_downloaded = parts[3] if len(parts) > 3 else "0"
                                percent = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0

                                log_info(
                                    f"Stage: Downloading {pkg_downloaded} of {pkg_total} packages ({download_size})"
                                )

                                # Build progress bar visual
                                if 0 <= percent <= 100:
                                    bar_length = 20
                                    filled = int(bar_length * percent / 100)
                                    bar = "█" * filled + "░" * (bar_length - filled)
                                    progress_text = f"[{bar}] {percent}%"
                                else:
                                    progress_text = "Processing..."

                                # Build message with progress
                                total_int = int(pkg_total) if pkg_total.isdigit() else 0
                                if total_int > 0:
                                    if download_size and download_size not in ("unknown", "manual"):
                                        msg = (
                                            f"Downloading {pkg_downloaded} of {pkg_total} packages\n"
                                            f"{progress_text}\n"
                                            f"{download_size} total • HIGH priority"
                                        )
                                    else:
                                        msg = (
                                            f"Downloading {pkg_downloaded} of {pkg_total} packages\n"
                                            f"{progress_text}\n"
                                            "HIGH priority"
                                        )
                                else:
                                    # Manual or unknown total: avoid misleading "0 of 0" text
                                    if download_size and download_size not in ("unknown", "manual"):
                                        msg = (
                                            "Downloading updates\n"
                                            f"{progress_text}\n"
                                            f"{download_size} total • HIGH priority"
                                        )
                                    else:
                                        msg = (
                                            "Downloading updates\n"
                                            f"{progress_text}\n"
                                            "HIGH priority"
                                        )

                                n = Notify.Notification.new(
                                    "Downloading updates...",
                                    msg,
                                    "emblem-downloads"
                                )

                                # Add progress bar hint (0-100) for notification daemons that support it
                                if 0 <= percent <= 100:
                                    n.set_hint("value", GLib.Variant("i", percent))
                                    n.set_category("transfer.progress")  # Category hint for progress notifications
                                else:
                                    # Indeterminate progress (pulsing animation)
                                    n.set_hint("value", GLib.Variant("i", 0))
                                    n.set_category("transfer")
                            except Exception as e:
                                log_debug(f"Error parsing download status: {e}")
                                log_info("Stage: Downloading packages")
                                n = Notify.Notification.new(
                                    "Downloading updates...",
                                    "Background download is in progress at HIGH priority.",
                                    "emblem-downloads"
                                )
                                n.set_hint("value", GLib.Variant("i", 50))

                            # Common settings for the progress notification
                            n.set_timeout(5000)  # 5 seconds
                            # Set hint to replace previous download status notifications
                            n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "dnf-download-status"))
                            n.show()

                            # Keep updating the same notification until the downloader
                            # finishes (status changes away from "downloading:").
                            while True:
                                time.sleep(2)
                                try:
                                    with open(download_status_file, 'r') as f2:
                                        new_status = f2.read().strip()
                                except Exception as e:
                                    log_debug(f"Error reading download status during progress loop: {e}")
                                    break

                                if not new_status.startswith("downloading:"):
                                    # Status changed (likely to complete: or idle) –
                                    # update our local variable so the logic below
                                    # can handle completion.
                                    status = new_status
                                    log_debug(f"Download status changed to '{status}', leaving progress loop")
                                    break

                                try:
                                    parts = new_status.split(":")
                                    pkg_total = parts[1] if len(parts) > 1 else "?"
                                    download_size = parts[2] if len(parts) > 2 else "unknown size"
                                    pkg_downloaded = parts[3] if len(parts) > 3 else "0"
                                    percent = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0

                                    log_info(f"Stage: Downloading {pkg_downloaded} of {pkg_total} packages ({download_size})")

                                    # Rebuild progress bar
                                    if 0 <= percent <= 100:
                                        bar_length = 20
                                        filled = int(bar_length * percent / 100)
                                        bar = "█" * filled + "░" * (bar_length - filled)
                                        progress_text = f"[{bar}] {percent}%"
                                    else:
                                        progress_text = "Processing..."

                                    total_int = int(pkg_total) if pkg_total.isdigit() else 0

                                    if total_int > 0:
                                        if download_size and download_size not in ("unknown", "manual"):
                                            msg = (
                                                f"Downloading {pkg_downloaded} of {pkg_total} packages\n"
                                                f"{progress_text}\n"
                                                f"{download_size} total • HIGH priority"
                                            )
                                        else:
                                            msg = (
                                                f"Downloading {pkg_downloaded} of {pkg_total} packages\n"
                                                f"{progress_text}\n"
                                                "HIGH priority"
                                            )
                                    else:
                                        if download_size and download_size not in ("unknown", "manual"):
                                            msg = (
                                                "Downloading updates\n"
                                                f"{progress_text}\n"
                                                f"{download_size} total • HIGH priority"
                                            )
                                        else:
                                            msg = (
                                                "Downloading updates\n"
                                                f"{progress_text}\n"
                                                "HIGH priority"
                                            )

                                    # Update the existing notification in place
                                    n.update("Downloading updates...", msg, "emblem-downloads")

                                    if 0 <= percent <= 100:
                                        n.set_hint("value", GLib.Variant("i", percent))
                                        n.set_category("transfer.progress")
                                    else:
                                        n.set_hint("value", GLib.Variant("i", 0))
                                        n.set_category("transfer")

                                    n.show()
                                except Exception as e:
                                    log_debug(f"Error updating download progress notification: {e}")
                                    # If something goes wrong, just break out and
                                    # let the rest of main() continue.
                                    break

                            # Do not return here – fall through so that a
                            # subsequent 'complete:' status is handled by the
                            # code below.

                # Fresh 'complete:' or 'idle' status fall through to the normal logic below
                if status.startswith("complete:"):
                    # Extract from "complete:DURATION:ACTUAL_DOWNLOADED" format (seconds)
                    try:
                        parts = status.split(":")
                        duration = int(parts[1]) if len(parts) > 1 else 0
                        actual_downloaded = int(parts[2]) if len(parts) > 2 else 0
                        
                        minutes = duration // 60
                        seconds = duration % 60
                        
                        if minutes > 0:
                            time_str = f"{minutes}m {seconds}s"
                        else:
                            time_str = f"{seconds}s"
                        
                        # Before we show any "Downloads Complete" message, double‑check that
                        # there are still updates pending. If a non-interactive dnf preview
                        # reports nothing to do, this completion status is stale (the user
                        # probably installed updates manually) and we should skip the
                        # download notification entirely so it doesn't appear after everything
                        # is already installed.
                        dry_output = ""
                        pending_count = None
                        try:
                            log_debug("Verifying pending updates for downloads-complete status...")
                            # Reuse the same LC_ALL=C shell wrapping as in get_updates()
                            shell_flags = ""
                            try:
                                import shlex as _shlex_for_flags2
                                if DUP_EXTRA_FLAGS:
                                    shell_flags = " " + " ".join(_shlex_for_flags2.quote(str(f)) for f in DUP_EXTRA_FLAGS)
                            except Exception:
                                if DUP_EXTRA_FLAGS:
                                    shell_flags = " " + " ".join(str(f) for f in DUP_EXTRA_FLAGS)

                            cmd_str = "LC_ALL=C /usr/bin/dnf -q upgrade --assumeno" + shell_flags
                            preview_cmd = [
                                "pkexec",
                                "/usr/bin/sh",
                                "-c",
                                cmd_str,
                            ]
                            env = base_env.copy()
                            result = subprocess.run(
                                preview_cmd,
                                capture_output=True,
                                text=True,
                                timeout=30,
                                env=env,
                            )
                            if result.returncode == 0:
                                dry_output = result.stdout or ""
                                _, _, _, pending_count = parse_output(dry_output, include_preview=False)
                                pending_count = pending_count or 0
                        except Exception as e:
                            log_debug(f"Verification dry-run for downloads-complete status failed: {e}")
                            dry_output = ""
                            pending_count = None
                        
                        if pending_count == 0:
                            log_info("Download status was 'complete' but dnf reports no pending updates; treating completion as stale and skipping 'Downloads Complete' notification.")
                            try:
                                with open(download_status_file, "w") as f:
                                    f.write("idle")
                            except Exception as e2:
                                log_debug(f"Failed to reset download status after stale completion: {e2}")
                            # Skip the downloads-complete popup; normal update check below
                            # will show the usual 'system up to date' message instead.
                        else:
                            # Build a completion message for both cases:
                            #  - actual_downloaded == 0  => everything was already in cache
                            #  - actual_downloaded > 0   => we just downloaded new packages
                            if actual_downloaded == 0:
                                log_info("All packages were already cached; treating as completed download")
                                changelog_msg = (
                                    "All update packages are already present in the local cache.\n\n"
                                    "Packages are ready to install."
                                )
                            else:
                                # Packages were actually downloaded, show notification
                                log_info(f"Downloaded {actual_downloaded} packages in {time_str}")
                                
                                # Base message
                                changelog_msg = f"Downloaded {actual_downloaded} packages in {time_str}.\n\nPackages are ready to install."
                                # If we have fresh dry-run output, attach a short preview
                                if dry_output:
                                    try:
                                        preview_packages = extract_package_preview(dry_output, max_packages=5)
                                        if preview_packages:
                                            preview_str = ", ".join(preview_packages)
                                            changelog_msg = (
                                                f"Downloaded {actual_downloaded} packages in {time_str}.\n\n"
                                                f"Including: {preview_str}\n\nReady to install."
                                            )
                                            log_info(f"Added changelog preview: {preview_str}")
                                    except Exception as e:
                                        log_debug(f"Could not build changelog preview: {e}")
                            
                            if pending_count is None or pending_count > 0:
                                n = Notify.Notification.new(
                                    "✅ Downloads Complete!",
                                    changelog_msg,
                                    "emblem-default"
                                )
                                n.set_timeout(0)  # 0 = persist until user interaction
                                n.set_urgency(Notify.Urgency.NORMAL)  # Normal urgency
                                n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "dnf-download-complete"))
                                n.show()
                                time.sleep(0.1)  # Wait a bit before continuing
                                # Clear the complete status so it doesn't show again
                                try:
                                    with open("/var/log/dnf-auto/download-status.txt", "w") as f:
                                        f.write("idle")
                                except Exception:
                                    pass
                        # Continue to show install notification below
                    except Exception:
                        log_debug("Could not process completion status")
                        # Continue to show install notification below
                
                elif status == "idle":
                    log_debug("Status is idle (no updates to download)")
                    # Continue to normal check below

                elif status.startswith("error:network"):
                    # Downloader could not talk to the repositories (DNS or
                    # similar network problem). Surface a clear error to the
                    # user instead of silently failing.
                    log_error("Background downloader reported a network error while checking for updates")
                    msg = (
                        "The background updater could not reach the configured repositories.\n\n"\
                        "This is usually a temporary network or DNS problem.\n\n"\
                        "Check your connection and DNS settings, then try again."
                    )
                    n = Notify.Notification.new(
                        "Update check failed (network)",
                        msg,
                        "network-error",
                    )
                    n.set_timeout(30000)
                    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "dnf-network-error"))
                    n.set_urgency(Notify.Urgency.NORMAL)
                    n.show()

                    # Reset status to idle so we do not spam the same
                    # notification on every timer tick.
                    try:
                        with open(download_status_file, "w") as f:
                            f.write("idle")
                    except Exception as e2:
                        log_debug(f"Failed to reset download status after network error: {e2}")

                    return

                elif status.startswith("error:repo"):
                    # Repositories themselves reported an error (e.g. invalid
                    # metadata). Treat similarly to network errors but use a
                    # slightly different message.
                    log_error("Background downloader reported a repository error while checking for updates")
                    msg = (
                        "The background updater hit an error while talking to configured repositories.\\n\\n"\
                        "DNF reported repository failures or invalid metadata.\\n\\n"\
                        "Run 'sudo dnf upgrade --refresh' in a terminal for full details and to resolve the issue."\
                    )
                    n = Notify.Notification.new(
                        "Update check failed (repositories)",
                        msg,
                        "dialog-warning",
                    )
                    n.set_timeout(30000)
                    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "dnf-repo-error"))
                    n.set_urgency(Notify.Urgency.NORMAL)
                    n.show()

                    try:
                        with open(download_status_file, "w") as f:
                            f.write("idle")
                    except Exception as e2:
                        log_debug(f"Failed to reset download status after repo error: {e2}")

                    return

                elif status.startswith("error:solver:"):
                    # Background downloader hit a solver/non-interactive error.
                    # Show a persistent notification that both:
                    #   - explains the conflict, and
                    #   - summarises how many updates are available (if possible),
                    # with an "Install Now" action that runs the helper.
                    try:
                        parts = status.split(":")
                        exit_code = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None
                    except Exception:
                        exit_code = None

                    if exit_code is not None:
                        log_info(f"Background downloader encountered a dnf solver/error exit code {exit_code}")
                    else:
                        log_info("Background downloader reported a solver error (unknown exit code)")

                    # Try to run a dry-run to get a summary of pending updates, even if
                    # dnf still exits non-zero due to conflicts.
                    dry_output = ""
                    try:
                        log_debug("Running dnf upgrade --assumeno to summarise solver-conflict state...")
                        shell_flags = ""
                        try:
                            import shlex as _shlex_for_flags3
                            if DUP_EXTRA_FLAGS:
                                shell_flags = " " + " ".join(_shlex_for_flags3.quote(str(f)) for f in DUP_EXTRA_FLAGS)
                        except Exception:
                            if DUP_EXTRA_FLAGS:
                                shell_flags = " " + " ".join(str(f) for f in DUP_EXTRA_FLAGS)

                        cmd_str = "LC_ALL=C /usr/bin/dnf -q upgrade --assumeno" + shell_flags
                        conflict_cmd = [
                            "pkexec",
                            "/usr/bin/sh",
                            "-c",
                            cmd_str,
                        ]
                        env = base_env.copy()
                        result = subprocess.run(
                            conflict_cmd,
                            capture_output=True,
                            text=True,
                            timeout=60,
                            env=env,
                        )
                        dry_output = result.stdout or ""
                    except Exception as e2:
                        log_debug(f"Failed to run dnf preview for solver summary: {e2}")
                        dry_output = ""

                    title = "Updates require your decision"
                    message = ""

                    # If we got useful output, reuse the normal parser to describe
                    # how many updates are pending and a short preview.
                    parsed_title = None
                    parsed_message = None
                    pkg_count = 0
                    if dry_output:
                        try:
                            parsed_title, parsed_message, snapshot, pkg_count = parse_output(dry_output, include_preview=True)
                        except Exception as e3:
                            log_debug(f"parse_output failed for solver summary: {e3}")
                            parsed_title, parsed_message, pkg_count = None, None, 0

                    if parsed_title:
                        title = f"{parsed_title} (manual decision needed)"
                        message = parsed_message + "\n\nDNF needs your decision to resolve conflicts before these updates can be installed."
                    else:
                        # Fallback generic explanation
                        if exit_code is not None:
                            message = (
                                f"Background download of updates hit a dnf solver error (exit code {exit_code}).\\n\\n"\
                                "Some packages may already be cached, but dnf needs your decision to continue."
                            )
                        else:
                            message = (
                                "Background download of updates hit a dnf solver error.\\n\\n"\
                                "Some packages may already be cached, but dnf needs your decision to continue."
                            )

                    # Always give clear instructions on what to do next.
                    message += (
                        "\\n\\nOpen a terminal and run:\n"\
                        "  sudo dnf upgrade\\n"\
                        "or click 'Install Now' to open the helper, then follow dnf's prompts to resolve the conflicts."
                    )

                    action_script = os.path.expanduser("~/.local/bin/dnf-run-install")

                    n = Notify.Notification.new(
                        title,
                        message,
                        "system-software-update",
                    )
                    # Persistent notification, high urgency.
                    n.set_timeout(0)
                    n.set_urgency(Notify.Urgency.CRITICAL)
                    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "dnf-updates-conflict"))

                    # Add the same actions as the normal "updates ready" notification.
                    n.add_action("install", "Install Now", on_action, action_script)
                    n.add_action("view-changes", "View Changes", on_action, None)
                    n.add_action("snooze-1h", "1h", on_action, None)
                    n.add_action("snooze-4h", "4h", on_action, None)
                    n.add_action("snooze-1d", "1d", on_action, None)

                    # Reset the status to idle so we don't spam the same notification forever.
                    try:
                        with open(download_status_file, "w") as f:
                            f.write("idle")
                    except Exception as e2:
                        log_debug(f"Failed to reset download status after solver error: {e2}")

                    # Run a short main loop so actions work, then exit this cycle.
                    loop = GLib.MainLoop()
                    n.connect("closed", lambda *args: loop.quit())
                    n.show()
                    try:
                        loop.run()
                    except KeyboardInterrupt:
                        log_info("Solver-conflict notification main loop interrupted")

                    # Do not run another dnf preview in this cycle; wait for user action.
                    return
                    
            except Exception as e:
                log_debug(f"Could not read download status: {e}")

        # Run safety checks before proceeding
        has_space, space_msg = check_disk_space()
        has_snapshots, snapshot_msg = check_snapshots()
        net_ok, net_msg = check_network_quality()
        
        # Log safety check results
        log_info(f"Safety checks: disk={space_msg}, snapshots={snapshot_msg}, network={net_msg}")
        
        output = get_updates()

        # If get_updates() failed with a real error (not just a DNF lock), show error notification
        if output is None:
            log_error("Update check failed due to PolicyKit/authentication error")
            update_status("FAILED: Update check failed")
            err_title = "Update check failed"
            err_message = (
                "The updater could not authenticate with PolicyKit.\\n"\
                "This may be a configuration issue.\\n\\n"\
                "Try running 'pkexec /usr/bin/dnf -q upgrade --assumeno' manually to test."
            )
            n = Notify.Notification.new(err_title, err_message, "dialog-error")
            n.set_timeout(30000)  # 30 seconds
            n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "dnf-error"))
            n.show()
            log_info("Error notification displayed")
            return

        # Empty string means environment was unsafe and dnf was skipped.
        if not output or not output.strip():
            log_info("No dnf run performed (environment not safe). Exiting.")
            return

        title, message, snapshot, package_count = parse_output(output)
        if not title:
            # No updates available: check if we already showed this
            log_info("System is up-to-date.")
            update_status("SUCCESS: System up-to-date")
            
            # Check if we already showed "no updates" notification
            last_notification = _read_last_notification()
            no_updates_key = "No updates found|Your system is already up to date. (dnf)"
            
            if (not NO_UPDATES_REMINDER_REPEAT_ENABLED) and last_notification == no_updates_key:
                log_info("'No updates' notification already shown, skipping duplicate (NO_UPDATES_REMINDER_REPEAT_ENABLED=false)")
                return
            
            # First time or repeat - show notification and remember it
            log_info("Showing 'no updates found' notification")
            _write_last_notification("No updates found", "Your system is already up to date.")
            
            n = Notify.Notification.new(
                "No updates found",
                "Your system is already up to date.",
                "dialog-information",
            )
            n.set_timeout(10000)  # 10 seconds
            n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "dnf-no-updates"))
            n.show()
            return
        
        # Write cache for future checks
        write_cache(package_count, snapshot)

        log_info("Updates are pending. Sending 'updates ready' reminder.")
        update_status(f"Updates available: {title}")
        
        # Add safety warnings / info lines to message
        warnings = []
        if not has_space:
            warnings.append(f"⚠️ {space_msg}")
        # Always show snapshot state when available; use ℹ️ when snapshots exist,
        # ⚠️ when they don't. On non-openSUSE systems check_snapshots() returns
        # an empty message so nothing is shown here.
        if snapshot_msg:
            icon = "ℹ️" if has_snapshots else "⚠️"
            warnings.append(f"{icon} {snapshot_msg}")
        if not net_ok:
            warnings.append(f"⚠️ {net_msg}")
        
        if warnings:
            message += "\n\n" + "\n".join(warnings)

        # Check if this notification is different from the last one
        last_notification = _read_last_notification()
        current_notification = f"{title}|{message}"
        
        if (not UPDATES_READY_REMINDER_REPEAT_ENABLED) and last_notification == current_notification:
            log_info("'Updates ready' notification already shown, skipping duplicate (UPDATES_READY_REMINDER_REPEAT_ENABLED=false)")
            return
        
        if last_notification == current_notification:
            log_debug("Notification unchanged, re-showing to keep it visible")
        else:
            log_info(f"Notification changed from [{last_notification}] to [{current_notification}]")
        
        _write_last_notification(title, message)

        # Get the path to the action script
        action_script = os.path.expanduser("~/.local/bin/dnf-run-install")

        # Create the notification with a stable ID so it replaces the previous one
        log_debug(f"Creating notification: {title}")
        n = Notify.Notification.new(title, message, "system-software-update")
        n.set_timeout(0) # 0 = persistent notification (no timeout)
        n.set_urgency(Notify.Urgency.CRITICAL) # Make it more noticeable
        
        # Set a consistent ID so notifications replace each other
        n.set_hint("desktop-entry", GLib.Variant("s", "dnf-updater"))
        n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "dnf-updates"))

        # Add action buttons with shorter labels
        n.add_action("install", "Install Now", on_action, action_script)
        n.add_action("view-changes", "View Changes", on_action, None)
        n.add_action("snooze-1h", "1h", on_action, None)
        n.add_action("snooze-4h", "4h", on_action, None)
        n.add_action("snooze-1d", "1d", on_action, None)

        log_info("Displaying persistent update notification with Install and Snooze buttons")
        n.show()
        
        # Run main loop indefinitely - only exit when user interacts with notification
        # This keeps the notification visible until user takes action
        log_info("Running GLib main loop indefinitely - waiting for user action...")
        loop = GLib.MainLoop()
        n.connect("closed", lambda *args: loop.quit())
        
        try:
            loop.run()
        except KeyboardInterrupt:
            log_info("Main loop interrupted")
        
        log_info("Main loop finished - user interacted with notification or it was dismissed")

    except Exception as e:
        log_error(f"An error occurred in main: {e}")
        update_status(f"FAILED: {str(e)}")
        import traceback
        log_error(f"Traceback: {traceback.format_exc()}")
    finally:
        log_info("Shutting down notification system")
        Notify.uninit()
        log_info("DNF Notify Updater finished")
        log_info("=" * 60)

if __name__ == "__main__":
    main()
EOF

log_info "Configuring Python script paths..."
sed -i "s|/var/log/dnf-auto|${LOG_DIR}|g" "${NOTIFY_SCRIPT_PATH}"
sed -i "s|/etc/dnf-auto.conf|${CONFIG_FILE}|g" "${NOTIFY_SCRIPT_PATH}"

chown "$SUDO_USER:$SUDO_USER" "${NOTIFY_SCRIPT_PATH}"
chmod +x "${NOTIFY_SCRIPT_PATH}"
log_success "Python notifier script created and made executable"

# If there were any configuration warnings collected during load_config,
# surface them clearly in the status/log so the user can fix them.
if [ "${#CONFIG_WARNINGS[@]}" -gt 0 ]; then
    echo "" | tee -a "${LOG_FILE}"
    echo "Configuration warnings (from ${CONFIG_FILE}):" | tee -a "${LOG_FILE}"
    for w in "${CONFIG_WARNINGS[@]}"; do
        echo "  - $w" | tee -a "${LOG_FILE}"
    done
    echo "" | tee -a "${LOG_FILE}"
    update_status "WARNING: One or more settings in ${CONFIG_FILE} were invalid and reset to defaults"

    # Try to send a desktop notification to the target user so they
    # notice the config issue and can fix or reset it.
    if command -v sudo >/dev/null 2>&1; then
        sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$(id -u "$SUDO_USER")/bus" \
notify-send "DNF Auto-Helper config warnings" \
            "Some settings in ${CONFIG_FILE} were invalid and reset to safe defaults.\n\nCheck the install log or run: dnf-auto-helper --reset-config"
            >/dev/null 2>&1 || true
    fi
fi

# --- 11. Create/Update Install Script (user) ---
log_info ">>> Creating (user) install script: ${INSTALL_SCRIPT_PATH}"
update_status "Creating install helper script..."
log_debug "Writing install script to: ${INSTALL_SCRIPT_PATH}"
cat << 'EOF' > "${INSTALL_SCRIPT_PATH}"
#!/usr/bin/env bash
set -euo pipefail

# Simple logging helper so we can debug why the install window may be
# opening and closing immediately.
LOG_FILE="$HOME/.local/share/dnf-notify/run-install.log"
LOG_DIR="$(dirname "$LOG_FILE")"
mkdir -p "$LOG_DIR" 2>/dev/null || true
log() {
    # Best-effort logging; never fail the script because of logging issues.
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    {
        printf '[%s] %s\n' "$ts" "$*" >>"$LOG_FILE" 2>/dev/null || true
    } || true
}

log "===== dnf-run-install started (PID $$) ====="
log "ENV: TERM=${TERM:-} DISPLAY=${DISPLAY:-} WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-} XDG_SESSION_TYPE=${XDG_SESSION_TYPE:-}"
log "ENV: SHELL=${SHELL:-} USER=${USER:-} PWD=${PWD:-}"

# Load feature toggles from the same config used by the installer.
CONFIG_FILE="/etc/dnf-auto.conf"

# Default feature toggles (can be overridden by CONFIG_FILE)
ENABLE_FLATPAK_UPDATES="true"
ENABLE_SNAP_UPDATES="true"
ENABLE_SOAR_UPDATES="true"
ENABLE_BREW_UPDATES="true"
ENABLE_PIPX_UPDATES="true"

if [ -r "$CONFIG_FILE" ]; then
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
fi

# Enhanced install script with post-update service check
TERMINALS=("konsole" "gnome-terminal" "kitty" "alacritty" "xterm")

# Helper to detect whether system management is currently locked by
# another package manager (dnf, PackageKit, etc.).
DNF_LOCK_FILE="/var/run/dnf.pid"

has_pkg_lock() {
    # Prefer the dnf.pid lock file when present.
    if [ -f "$DNF_LOCK_FILE" ]; then
        local pid
        pid=$(cat "$DNF_LOCK_FILE" 2>/dev/null || echo "")
        if [ -n "$pid" ]; then
            if kill -0 "$pid" 2>/dev/null; then
                # Double-check that this PID really looks like a DNF/PackageKit
                # style process so we don't treat a reused PID as a live lock.
                local comm cmd
                comm=$(ps -p "$pid" -o comm= 2>/dev/null || echo "")
                cmd=$(ps -p "$pid" -o args= 2>/dev/null || echo "")
                if printf '%s\n%s\n' "$comm" "$cmd" | grep -qiE 'dnf|dnf-automatic|packagekitd'; then
                    log "has_pkg_lock: package manager lock file $DNF_LOCK_FILE exists with live pid $pid (comm='$comm')"
                    return 0
                fi
                log "has_pkg_lock: ignoring non-dnf-looking process for lock file $DNF_LOCK_FILE (pid $pid, comm='$comm')"
            else
                log "has_pkg_lock: ignoring stale package-manager lock file $DNF_LOCK_FILE with pid $pid"
            fi
        else
            log "has_pkg_lock: package-manager lock file $DNF_LOCK_FILE present but empty"
        fi
    fi

    # Also treat an actively held RPM database lock as a package-manager lock.
    if [ -f "/var/lib/rpm/.rpm.lock" ] && command -v fuser >/dev/null 2>&1; then
        if fuser "/var/lib/rpm/.rpm.lock" >/dev/null 2>&1; then
            log "has_pkg_lock: RPM database lock /var/lib/rpm/.rpm.lock is held by another process"
            return 0
        fi
    fi

    # Fallback: any obviously dnf/PackageKit related process.
    if pgrep -x dnf >/dev/null 2>&1; then
        local zpid
        zpid=$(pgrep -x dnf | head -n1 || true)
        log "has_pkg_lock: detected running dnf process pid ${zpid:-unknown}"
        return 0
    fi
    if pgrep -f -i 'packagekitd' >/dev/null 2>&1; then
        local ypid
        ypid=$(pgrep -f -i 'packagekitd' | head -n1 || true)
        log "has_pkg_lock: detected running PackageKit process pid ${ypid:-unknown}"
        return 0
    fi

    return 1
}

# Create a wrapper script that will run in the terminal
RUN_UPDATE() {
    echo ""
    echo "=========================================="
    echo "  Running System Update"
    echo "=========================================="
    echo ""
    
    # Track whether dnf failed specifically because of a lock so we can
    # show a clearer message later.
    LOCKED_DURING_UPDATE=0
    
    # Best-effort: stop the background downloader so it doesn't compete
    # for the dnf lock while we're doing an interactive update.
    log "RUN_UPDATE: stopping dnf-autodownload.service/timer to avoid lock conflicts"
    set +e
    pkexec systemctl stop dnf-autodownload.service dnf-autodownload.timer >/dev/null 2>&1
    set -e

    # If any other package manager process is still running at this point (for example
    # an open graphical updater or another terminal dnf), retry a few times with
    # increasing delays (1, 2, 3, ... seconds) before giving up and telling
    # the user what to do. The number of attempts and base delay are
    # controlled from /etc/dnf-auto.conf.
    max_attempts=${LOCK_RETRY_MAX_ATTEMPTS:-10}
    base_delay=${LOCK_RETRY_INITIAL_DELAY_SECONDS:-1}
    attempt=1
    while has_pkg_lock && [ "$attempt" -le "$max_attempts" ]; do
        delay=$((base_delay * attempt))
        echo ""
        echo "System management is currently locked by another update tool (dnf/PackageKit)."
        echo "Retry $attempt/$max_attempts: waiting $delay second(s) for the other updater to finish..."
        log "RUN_UPDATE: lock still active before attempt $attempt/$max_attempts; sleeping ${delay}s"
        sleep "$delay"
        attempt=$((attempt + 1))
    done

    # After retries, if a lock is still present, show a clear message and exit
    # cleanly instead of letting pkexec/dnf print the raw lock error.
    if has_pkg_lock; then
        echo ""
        echo "System management is still locked by another update tool."
        echo "Close that other update tool (or wait for it to finish), then run"
        echo "this 'Ready to Install' action again."
        echo ""
        log "RUN_UPDATE: aborting after $max_attempts lock retries because another updater is still holding the lock"
        echo "Press Enter to close this window..."
        set +e
        if ! read -r _ </dev/tty 2>/dev/null; then
            # If /dev/tty is not available (or read fails instantly), pause briefly
            # so the user still has a chance to see the message.
            sleep 5
        fi
        set -e
        return 0
    fi

    log "RUN_UPDATE: starting pkexec dnf upgrade..."
    # Run the update, capturing stderr so we can detect a lock even if it
    # appears after our pre-check.
    set +e
    DNF_ERR_FILE=$(mktemp)
    pkexec dnf upgrade -y 2> >(tee "$DNF_ERR_FILE" | sed -E '/System management is locked/d;/Close this application before trying again/d' >&2)
    rc=$?
    set -e

    if [ "$rc" -ne 0 ] && grep -q "System management is locked" "$DNF_ERR_FILE" 2>/dev/null; then
        LOCKED_DURING_UPDATE=1
    fi
    rm -f "$DNF_ERR_FILE"

    if [ "$rc" -eq 0 ]; then
        UPDATE_SUCCESS=true
        log "RUN_UPDATE: pkexec dnf upgrade completed successfully (rc=$rc)"
    else
        UPDATE_SUCCESS=false
        if [ "$LOCKED_DURING_UPDATE" -eq 1 ]; then
            log "RUN_UPDATE: pkexec dnf upgrade failed due to existing lock (rc=$rc)"
        else
            log "RUN_UPDATE: pkexec dnf upgrade FAILED (rc=$rc)"
        fi
    fi
    
    echo ""
    echo "=========================================="
    echo "  Update Complete - Post-Update Check"
    echo "=========================================="
    echo ""
    
    # Post-update integrations (Flatpak, Snap, Soar, Homebrew) are controlled
    # by flags in /etc/dnf-auto.conf.
    echo "=========================================="
    echo "  Flatpak Updates"
    echo "=========================================="
    echo ""
    
    if [[ "${ENABLE_FLATPAK_UPDATES,,}" == "true" ]]; then
        if command -v flatpak >/dev/null 2>&1; then
            if pkexec flatpak update -y; then
                echo "✅ Flatpak updates completed."
            else
                echo "⚠️  Flatpak update failed (continuing)."
            fi
        else
            echo "⚠️  Flatpak is not installed - skipping Flatpak updates."
            echo "   To install: sudo dnf install flatpak"
        fi
    else
        echo "ℹ️  Flatpak updates are disabled in /etc/dnf-auto.conf (ENABLE_FLATPAK_UPDATES=false)."
    fi

    echo ""
    echo "=========================================="
    echo "  Snap Updates"
    echo "=========================================="
    echo ""

    if [[ "${ENABLE_SNAP_UPDATES,,}" == "true" ]]; then
        if command -v snap >/dev/null 2>&1; then
            if pkexec snap refresh; then
                echo "✅ Snap updates completed."
            else
                echo "⚠️  Snap refresh failed (continuing)."
            fi
        else
            echo "⚠️  Snapd is not installed - skipping Snap updates."
            echo "   To install: sudo dnf install snapd"
            echo "   Then enable: sudo systemctl enable --now snapd"
        fi
    else
        echo "ℹ️  Snap updates are disabled in /etc/dnf-auto.conf (ENABLE_SNAP_UPDATES=false)."
    fi

    echo ""
    echo "=========================================="
    echo "  Soar (stable) Update & Sync"
    echo "=========================================="
    echo ""

    # Detect Soar in common per-user locations so we don't offer to install
    # it when it's already present but not yet on PATH for non-interactive
    # shells.
    SOAR_BIN=""
    if command -v soar >/dev/null 2>&1; then
        SOAR_BIN=$(command -v soar)
    elif [ -x "$HOME/.local/bin/soar" ]; then
        SOAR_BIN="$HOME/.local/bin/soar"
    elif [ -d "$HOME/pkgforge" ] && \
         find "$HOME/pkgforge" -maxdepth 1 -type f -name 'soar*' -perm -u+x 2>/dev/null | grep -q .; then
        SOAR_BIN=$(find "$HOME/pkgforge" -maxdepth 1 -type f -name 'soar*' -perm -u+x 2>/dev/null | head -n1)
    fi

    if [[ "${ENABLE_SOAR_UPDATES,,}" != "true" ]]; then
        echo "ℹ️  Soar updates are disabled in /etc/dnf-auto.conf (ENABLE_SOAR_UPDATES=false)."
    elif [ -n "$SOAR_BIN" ]; then
        # First, check if a newer *stable* Soar release exists on GitHub.
        # We compare the local "soar --version" against
        # https://api.github.com/repos/pkgforge/soar/releases/latest (stable only).
        if command -v curl >/dev/null 2>&1; then
            echo "Checking for newer stable Soar release from GitHub..."

            LOCAL_VER_RAW=$("$SOAR_BIN" --version 2>/dev/null | head -n1)
            LOCAL_VER=$(echo "$LOCAL_VER_RAW" | grep -oE 'v?[0-9]+(\.[0-9]+)*' | head -n1 || true)
            LOCAL_BASE=${LOCAL_VER#v}

            REMOTE_JSON=$(curl -fsSL "https://api.github.com/repos/pkgforge/soar/releases/latest" 2>/dev/null || true)
            REMOTE_VER=$(printf '%s\n' "$REMOTE_JSON" | grep -m1 '"tag_name"' | sed -E 's/.*"tag_name" *: *"([^"]+)".*/\1/' || true)
            REMOTE_BASE=${REMOTE_VER#v}

            if [ -n "$LOCAL_BASE" ] && [ -n "$REMOTE_BASE" ]; then
                LATEST=$(printf '%s\n%s\n' "$LOCAL_BASE" "$REMOTE_BASE" | sort -V | tail -n1)
                if [ "$LATEST" = "$REMOTE_BASE" ] && [ "$LOCAL_BASE" != "$REMOTE_BASE" ]; then
                    echo "New stable Soar available ($LOCAL_VER -> $REMOTE_VER), updating..."
                    if curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh; then
                        echo "✅ Soar updated to latest stable release."
                    else
                        echo "⚠️  Failed to update Soar from GitHub (continuing with existing version)."
                    fi
                else
                    echo "Soar is already up to date (local: ${LOCAL_VER:-unknown}, latest stable: ${REMOTE_VER:-unknown})."
                fi
            else
                echo "Could not determine Soar versions; running installer to ensure latest stable."
                if curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh; then
                    echo "✅ Soar updated to latest stable release."
                else
                    echo "⚠️  Failed to update Soar from GitHub (continuing with existing version)."
                fi
            fi
        else
            echo "⚠️  curl is not installed; skipping automatic Soar update from GitHub."
            echo "    You can update Soar manually from: https://github.com/pkgforge/soar/releases"
            if [ -x /usr/local/bin/dnf-auto-helper ]; then
                echo "    Or via helper: dnf-auto-helper --soar"
            fi
        fi

        # Then run the usual metadata sync.
        if "$SOAR_BIN" sync; then
            echo "✅ Soar sync completed."
            # Optionally refresh Soar-managed apps that support "soar update".
            if "$SOAR_BIN" update; then
                echo "✅ Soar update completed."
            else
                echo "⚠️  Soar update failed (continuing)."
            fi
        else
            echo "⚠️  Soar sync failed (continuing)."
        fi
    else
        echo "ℹ️  Soar is not installed."
        if command -v curl >/dev/null 2>&1; then
            echo "    Soar can be installed from the official GitHub installer."
            read -rp "    Do you want to install Soar (stable) from GitHub now? [y/N]: " SOAR_INSTALL_REPLY
            if [[ "$SOAR_INSTALL_REPLY" =~ ^[Yy]$ ]]; then
                echo "Installing Soar from GitHub..."
                if curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh; then
                    echo "✅ Soar installed successfully."
                    # Optionally run initial sync if the binary is now available
                    if command -v soar >/dev/null 2>&1; then
                        if soar sync; then
                            echo "✅ Soar sync completed."
                        else
                            echo "⚠️  Soar sync failed after install (continuing)."
                        fi
                    fi
                else
                    echo "⚠️  Failed to install Soar from GitHub. You can install it manually from:"
                    echo "    https://github.com/pkgforge/soar/releases"
                fi
            else
                echo "Skipping Soar installation. You can install it later from:"
                echo "    https://github.com/pkgforge/soar/releases"
            if [ -x /usr/local/bin/dnf-auto-helper ]; then
                    echo "    Or via helper: dnf-auto-helper --soar"
                fi
            fi
        else
            echo "⚠️  curl is not installed; cannot automatically install Soar."
            echo "    Please install curl or install Soar manually from: https://github.com/pkgforge/soar/releases"
            if [ -x /usr/local/bin/dnf-auto-helper ]; then
                echo "    Or via helper: dnf-auto-helper --soar"
            fi
        fi
    fi

    echo ""

    echo "=========================================="
    echo "  Homebrew (brew) Updates (optional)"
    echo "=========================================="
    echo ""

    if [[ "${ENABLE_BREW_UPDATES,,}" != "true" ]]; then
        echo "ℹ️  Homebrew updates are disabled in /etc/dnf-auto.conf (ENABLE_BREW_UPDATES=false)."
        echo "    You can still run 'brew update' / 'brew upgrade' manually."
        echo ""
        return
    fi

    # Try to detect Homebrew in PATH or the default Linuxbrew prefix
    if command -v brew >/dev/null 2>&1 || [ -x "/home/linuxbrew/.linuxbrew/bin/brew" ]; then
        # Normalise brew command path
        if command -v brew >/dev/null 2>&1; then
            BREW_BIN="brew"
        else
            BREW_BIN="/home/linuxbrew/.linuxbrew/bin/brew"
        fi

        echo "Checking for Homebrew updates from GitHub (brew update)..."
        if ! $BREW_BIN update; then
            echo "⚠️  Homebrew 'brew update' failed (continuing without brew upgrade)."
        else
            # After syncing with GitHub, see if anything needs upgrading
            OUTDATED=$($BREW_BIN outdated --quiet 2>/dev/null || true)
            OUTDATED_COUNT=$(printf '%s\n' "$OUTDATED" | sed '/^$/d' | wc -l | tr -d ' ')

            if [ "${OUTDATED_COUNT:-0}" -eq 0 ]; then
                echo "Homebrew is already up to date (no formulae to upgrade)."
            else
                echo "Homebrew has ${OUTDATED_COUNT} outdated formulae; running 'brew upgrade'..."
                if $BREW_BIN upgrade; then
                    echo "✅ Homebrew upgrade completed (upgraded ${OUTDATED_COUNT} formulae)."
                else
                    echo "⚠️  Homebrew 'brew upgrade' failed (continuing)."
                fi
            fi
        fi
    else
        echo "ℹ️  Homebrew (brew) is not installed - skipping brew update/upgrade."
        if [ -x /usr/local/bin/dnf-auto-helper ]; then
            echo "    To install via helper: dnf-auto-helper --brew"
        fi
    fi

    echo ""
    echo "=========================================="
    echo "  Python (pipx) Updates (optional)"
    echo "=========================================="
    echo ""

    if [[ "${ENABLE_PIPX_UPDATES,,}" != "true" ]]; then
        echo "ℹ️  pipx updates are disabled in /etc/dnf-auto.conf (ENABLE_PIPX_UPDATES=false)."
        echo "    You can still manage Python CLI tools manually with pipx."
        echo ""
    else
        if command -v pipx >/dev/null 2>&1; then
            echo "Upgrading all pipx-managed Python command-line tools (pipx upgrade-all)..."
            if pipx upgrade-all; then
                echo "✅ pipx upgrade-all completed."
            else
                echo "⚠️  pipx upgrade-all failed (continuing)."
            fi
        else
            echo "ℹ️  pipx is not installed - skipping Python CLI (pipx) updates."
            echo "    Recommended: dnf-auto-helper --pip-package (run without sudo)"
        fi
    fi

    echo ""
    echo "Checking which services need to be restarted..."
    echo ""
    
    # On Fedora, prefer 'needs-restarting' to show services/processes using old libraries.
    if command -v needs-restarting >/dev/null 2>&1; then
        NEEDS_OUTPUT=$(sudo needs-restarting 2>/dev/null || true)
        echo "$NEEDS_OUTPUT"
    else
        NEEDS_OUTPUT=""
        echo "'needs-restarting' not found. Install 'dnf-plugins-core' for detailed restart info."
    fi
    
    # Check if there are any running processes in the output
    if [ -n "$NEEDS_OUTPUT" ]; then
        echo ""
        echo "ℹ️  Services listed above are using old library versions."
        echo ""
        echo "What this means:"
        echo "  • These services/processes are still running old code in memory"
        echo "  • They should be restarted to use the updated libraries"
        echo ""
        echo "Options:"
        echo "  1. Restart individual services: systemctl restart <service>"
        echo "  2. Reboot your system (recommended for kernel/system updates)"
        echo ""
    else
        echo "✅ No services require restart. You're all set!"
        echo ""
    fi

    if [ "$UPDATE_SUCCESS" = false ]; then
        if [ "$LOCKED_DURING_UPDATE" -eq 1 ]; then
            echo "⚠  dnf could not run because system management is locked by another tool. No system packages were changed."
        else
            echo "⚠️  dnf upgrade reported errors (see above), but Flatpak/Snap updates were attempted."
        fi
        echo ""
    fi

    log "RUN_UPDATE: finished (UPDATE_SUCCESS=$UPDATE_SUCCESS)"

    # Keep the terminal open so the user can read the output, even if stdin
    # is not a normal TTY or "read" would normally fail under set -e.
    echo "Press Enter to close this window..."
    set +e
    if ! read -r _ </dev/tty 2>/dev/null; then
        # If /dev/tty is not available (or read fails instantly), pause briefly
        # so the user still has a chance to see the final output.
        sleep 5
    fi
    set -e
}

# If invoked with --inner, run the update directly in this process instead of
# spawning another terminal. This avoids relying on exported shell functions
# inside a separate konsole/gnome-terminal bash.
if [[ "${1:-}" == "--inner" ]]; then
    log "Inner mode (--inner) invoked; running RUN_UPDATE directly"
    shift || true
    RUN_UPDATE
    exit $?
fi

# Export the function (harmless, but not relied upon anymore)
export -f RUN_UPDATE || true

# Run the update in a terminal
log "Terminal selection: candidates: ${TERMINALS[*]}"
for term in "${TERMINALS[@]}"; do
    log "Checking terminal: $term"
    if command -v "$term" >/dev/null 2>&1; then
        log "Using terminal '$term' to run inner helper (--inner)"
        case "$term" in
            konsole)
                set +e
                konsole -e bash -lc '"$HOME"/.local/bin/dnf-run-install --inner'
                rc=$?
                set -e
                log "konsole finished with exit code $rc"
                exit 0
                ;;
            gnome-terminal)
                set +e
                gnome-terminal -- bash -lc '"$HOME"/.local/bin/dnf-run-install --inner'
                rc=$?
                set -e
                log "gnome-terminal finished with exit code $rc"
                exit 0
                ;;
            kitty|alacritty|xterm)
                set +e
                "$term" -e bash -lc '"$HOME"/.local/bin/dnf-run-install --inner'
                rc=$?
                set -e
                log "${term} finished with exit code $rc"
                exit 0
                ;;
        esac
    fi
done

log "No GUI terminal found; falling back to running RUN_UPDATE directly"
# Fallback: run directly if no terminal found
RUN_UPDATE
EOF

chown "$SUDO_USER:$SUDO_USER" "${INSTALL_SCRIPT_PATH}"
chmod +x "${INSTALL_SCRIPT_PATH}"
log_success "Install helper script created and made executable"

# --- 11b. Create View Changes Script ---
log_info ">>> Creating (user) view changes script: ${VIEW_CHANGES_SCRIPT_PATH}"
update_status "Creating view changes helper script..."
log_debug "Writing view changes script to: ${VIEW_CHANGES_SCRIPT_PATH}"
cat << 'EOF' > "${VIEW_CHANGES_SCRIPT_PATH}"
#!/usr/bin/env bash

# Script to view detailed package changes
# Logging for debugging
LOG_FILE="$HOME/.local/share/dnf-notify/view-changes.log"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] View changes script started" >> "$LOG_FILE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] DISPLAY=$DISPLAY" >> "$LOG_FILE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] USER=$USER" >> "$LOG_FILE"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] PWD=$PWD" >> "$LOG_FILE"

# Ensure a usable GUI environment when launched from systemd --user
# Prefer existing vars; only set safe defaults if missing
if [ -z "${XDG_RUNTIME_DIR:-}" ]; then
    export XDG_RUNTIME_DIR="/run/user/$(id -u)"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] XDG_RUNTIME_DIR was empty, set to $XDG_RUNTIME_DIR" >> "$LOG_FILE"
fi
if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
    export DBUS_SESSION_BUS_ADDRESS="unix:path=${XDG_RUNTIME_DIR}/bus"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] DBUS_SESSION_BUS_ADDRESS was empty, set to $DBUS_SESSION_BUS_ADDRESS" >> "$LOG_FILE"
fi
# On Wayland, WAYLAND_DISPLAY is usually set by the session. If both DISPLAY and WAYLAND_DISPLAY
# are empty, fall back to DISPLAY=:0 which works for X11
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    export DISPLAY=:0
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Neither DISPLAY nor WAYLAND_DISPLAY set; defaulted DISPLAY to :0" >> "$LOG_FILE"
fi

# Create a temporary script file for the terminal to execute
TMP_SCRIPT=$(mktemp /tmp/dnf-view-changes.XXXXXX.sh)
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Created temp script: $TMP_SCRIPT" >> "$LOG_FILE"

cat > "$TMP_SCRIPT" << 'INNEREOF'
#!/usr/bin/env bash
echo ""
echo "=========================================="
echo "  Package Update Details"
echo "=========================================="
echo ""
echo "Fetching update information..."
echo ""

# Run dnf with details (preview only)
if pkexec dnf upgrade --assumeno --refresh; then
    echo ""
    echo "=========================================="
    echo ""
    echo "This is a preview of what will be updated."
echo "Click 'Install Now' in the notification to proceed with dnf upgrade."
    echo ""
else
    echo "⚠️  Could not fetch update details."
    echo ""
fi

echo "Press Enter to close this window..."
read -r

# Clean up temporary script
rm -f "$0"
INNEREOF

chmod +x "$TMP_SCRIPT"

# Try terminals in order  
if command -v konsole >/dev/null 2>&1; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Launching konsole..." >> "$LOG_FILE"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Command: konsole --noclose -e bash $TMP_SCRIPT" >> "$LOG_FILE"
    nohup konsole --noclose -e bash "$TMP_SCRIPT" >> "$LOG_FILE" 2>&1 &
    KONSOLE_PID=$!
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Konsole PID: $KONSOLE_PID" >> "$LOG_FILE"
    sleep 0.5
    if ps -p $KONSOLE_PID > /dev/null 2>&1; then
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Konsole is running" >> "$LOG_FILE"
    else
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Konsole exited immediately!" >> "$LOG_FILE"
    fi
elif command -v gnome-terminal >/dev/null 2>&1; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Launching gnome-terminal..." >> "$LOG_FILE"
    gnome-terminal -- "$TMP_SCRIPT" >> "$LOG_FILE" 2>&1 &
    disown
elif command -v kitty >/dev/null 2>&1; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Launching kitty..." >> "$LOG_FILE"
    kitty -e "$TMP_SCRIPT" >> "$LOG_FILE" 2>&1 &
    disown
elif command -v alacritty >/dev/null 2>&1; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Launching alacritty..." >> "$LOG_FILE"
    alacritty -e "$TMP_SCRIPT" >> "$LOG_FILE" 2>&1 &
    disown
elif command -v xterm >/dev/null 2>&1; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Launching xterm..." >> "$LOG_FILE"
    xterm -e "$TMP_SCRIPT" >> "$LOG_FILE" 2>&1 &
    disown
else
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] No terminal found, running directly" >> "$LOG_FILE"
    "$TMP_SCRIPT" >> "$LOG_FILE" 2>&1
fi
EOF

chown "$SUDO_USER:$SUDO_USER" "${VIEW_CHANGES_SCRIPT_PATH}"
chmod +x "${VIEW_CHANGES_SCRIPT_PATH}"
log_success "View changes helper script created and made executable"

# --- 11c. Create Soar Install Helper (user) ---
SOAR_INSTALL_HELPER_PATH="$USER_BIN_DIR/dnf-soar-install-helper"
log_info ">>> Creating (user) Soar install helper: ${SOAR_INSTALL_HELPER_PATH}"
update_status "Creating Soar install helper script..."
log_debug "Writing Soar helper script to: ${SOAR_INSTALL_HELPER_PATH}"
cat << 'EOF' > "${SOAR_INSTALL_HELPER_PATH}"
#!/usr/bin/env python3
"""
Small helper that shows a notification with an "Install Soar" button.
When clicked, it opens a terminal and runs the official Soar install
command:

  curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh
"""

import os
import subprocess
import sys
import traceback
import shutil
import time

try:
    import gi
    gi.require_version("Notify", "0.7")
    from gi.repository import Notify, GLib
except Exception:
    # If PyGObject is not available for some reason, just exit quietly.
    sys.exit(0)


# Best-effort fixups for environment when launched from systemd --user or
# via sudo -u from the installer, so that terminals can attach to the
# correct user session.
if "XDG_RUNTIME_DIR" not in os.environ or not os.environ["XDG_RUNTIME_DIR"]:
    os.environ["XDG_RUNTIME_DIR"] = f"/run/user/{os.getuid()}"
if "DBUS_SESSION_BUS_ADDRESS" not in os.environ or not os.environ["DBUS_SESSION_BUS_ADDRESS"]:
    os.environ["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={os.environ['XDG_RUNTIME_DIR']}/bus"
if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
    # Fallback for X11-only sessions
    os.environ["DISPLAY"] = ":0"
if not os.environ.get("PATH"):
    # Minimal sane PATH so we can discover common terminals
    os.environ["PATH"] = "/usr/local/bin:/usr/bin:/bin"


LOG_PATH = os.path.expanduser("~/.local/share/dnf-notify/soar-install-helper.log")
loop = None  # type: ignore[assignment]


def _log(message: str) -> None:
    """Best-effort logging to a user log file for debugging."""
    try:
        log_dir = os.path.dirname(LOG_PATH)
        os.makedirs(log_dir, exist_ok=True)
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
    except Exception:
        # Never let logging failures break the helper
        pass


def _open_terminal_with_soar_install() -> None:
    # Use the main helper CLI so behavior is consistent with running
    #   sudo dnf-auto-helper --soar
    # from a regular terminal.
    cmd = (
        "sudo dnf-auto-helper --soar; "
        "echo; echo 'Press Enter to close this window...'; read -r"
    )
    terminals = ["konsole", "gnome-terminal", "kitty", "alacritty", "xterm"]

    _log("Install action triggered; attempting to open terminal for Soar install")
    _log(f"Environment DISPLAY={os.environ.get('DISPLAY')} WAYLAND_DISPLAY={os.environ.get('WAYLAND_DISPLAY')} DBUS_SESSION_BUS_ADDRESS={os.environ.get('DBUS_SESSION_BUS_ADDRESS')}")
    _log(f"PATH={os.environ.get('PATH')}")

    for term in terminals:
        term_path = shutil.which(term)
        _log(f"Checking terminal '{term}': path={term_path}")
        # Use shutil.which instead of external 'which' so we don't depend on
        # that binary existing in a restricted PATH.
        if term_path is not None:
            try:
                _log(f"Trying to launch terminal '{term}' with command: {cmd}")
                if term == "konsole":
                    subprocess.Popen([term, "-e", "bash", "-lc", cmd])
                elif term == "gnome-terminal":
                    subprocess.Popen([term, "--", "bash", "-lc", cmd])
                else:
                    subprocess.Popen([term, "-e", "bash", "-lc", cmd])
                _log(f"Successfully launched terminal '{term}'")
                return
            except Exception as e:
                _log(f"Failed to launch terminal '{term}': {e}")
                # If launching this terminal fails for any reason, try the next one.
                continue

    # Fallback: run in a plain shell if no terminal was detected or all
    # launches failed. This at least ensures the installer runs, even if it
    # isn't in a separate GUI terminal.
    _log("No GUI terminal found or all launches failed; falling back to 'bash -lc'")
    try:
        subprocess.Popen(["bash", "-lc", cmd])
        _log("Started fallback 'bash -lc' successfully")
    except Exception as e:
        _log(f"Failed to start fallback 'bash -lc': {e}")



def _on_action(notification, action_id, user_data):
    global loop
    _log(f"Notification action received: {action_id}")
    if action_id == "install":
        _open_terminal_with_soar_install()
    try:
        notification.close()
    except Exception as e:
        _log(f"Error while closing notification: {e}")
    if loop is not None:
        try:
            loop.quit()
        except Exception as e:
            _log(f"Error while quitting main loop: {e}")



def main() -> None:
    global loop
    try:
        _log("Soar install helper started")
        _log(f"Initial env DISPLAY={os.environ.get('DISPLAY')} WAYLAND_DISPLAY={os.environ.get('WAYLAND_DISPLAY')} DBUS_SESSION_BUS_ADDRESS={os.environ.get('DBUS_SESSION_BUS_ADDRESS')}")
        _log(f"Initial PATH={os.environ.get('PATH')}")

        Notify.init("dnf-auto-helper")
        body = (
            "Soar (optional CLI helper) is not installed.\n\n"
            "Click 'Install Soar' to open a terminal and run the official "
            "install script, or dismiss this notification to skip."
        )
        n = Notify.Notification.new(
            "DNF Auto-Helper: Install Soar",
            body,
            "dialog-information",
        )
        n.set_timeout(0)  # persistent until action or close
        n.add_action("install", "Install Soar", _on_action, None)

        loop = GLib.MainLoop()
        n.connect("closed", lambda *args: (_log("Notification closed"), loop.quit()))
        n.show()
        _log("Notification shown; entering GLib main loop")
        try:
            loop.run()
        finally:
            _log("Exiting GLib main loop; calling Notify.uninit()")
            Notify.uninit()
    except Exception:
        tb = traceback.format_exc()
        _log(f"Unhandled exception in helper: {tb}")
        try:
            Notify.uninit()
        except Exception as e:
            _log(f"Error during Notify.uninit after exception: {e}")
if __name__ == "__main__":
    main()
EOF

chown "$SUDO_USER:$SUDO_USER" "${SOAR_INSTALL_HELPER_PATH}"
chmod +x "${SOAR_INSTALL_HELPER_PATH}"
log_success "Soar install helper script created and made executable"

# --- 11d. Install script itself as a command ---
log_info ">>> Installing dnf-auto-helper command..."
update_status "Installing command-line interface..."

COMMAND_PATH="/usr/local/bin/dnf-auto-helper"
INSTALLER_SCRIPT_PATH="$0"

# Get the absolute path of the installer script
if [ ! -f "$INSTALLER_SCRIPT_PATH" ]; then
    INSTALLER_SCRIPT_PATH="$(realpath "$0")"
fi

log_debug "Installer script path: $INSTALLER_SCRIPT_PATH"
log_debug "Command installation path: $COMMAND_PATH"

# Copy the installer script to /usr/local/bin
if cp "$INSTALLER_SCRIPT_PATH" "$COMMAND_PATH" >> "${LOG_FILE}" 2>&1; then
    chmod +x "$COMMAND_PATH" >> "${LOG_FILE}" 2>&1
    log_success "Command installed: dnf-auto-helper"
    log_info "You can now run: dnf-auto-helper --help"
else
    log_error "Warning: Could not install command (non-fatal)"
fi

# --- 11e. Apply SELinux contexts (Fedora) ---
if command -v restorecon >/dev/null 2>&1; then
    log_info ">>> Applying SELinux contexts (restorecon)..."

    # First, if semanage is available, register our custom paths so SELinux
    # knows how to label them. This is idempotent and safe to run multiple times.
    if command -v semanage >/dev/null 2>&1; then
        log_info "Applying SELinux file contexts..."
        # Tell SELinux that ${LOG_DIR} is a log directory hierarchy
        semanage fcontext -a -t var_log_t "${LOG_DIR}(/.*)?" 2>/dev/null || true
        # Tell SELinux that the helper binary is an executable bin_t
        semanage fcontext -a -t bin_t "/usr/local/bin/dnf-auto-helper" 2>/dev/null || true
    fi

    # Log directory and its contents
    restorecon -Rv "${LOG_DIR}" >> "${LOG_FILE}" 2>&1 || true

    # Systemd unit files
    restorecon -v "${DL_SERVICE_FILE}" "${DL_TIMER_FILE}" \
        "${CLEANUP_SERVICE_FILE}" "${CLEANUP_TIMER_FILE}" \
        "${VERIFY_SERVICE_FILE}" "${VERIFY_TIMER_FILE}" \
        >> "${LOG_FILE}" 2>&1 || true

    # Helper binaries and scripts
    restorecon -v \
        "/usr/local/bin/dnf-auto-helper" \
        "${DOWNLOADER_SCRIPT}" \
        "${INSTALL_SCRIPT_PATH}" \
        "${VIEW_CHANGES_SCRIPT_PATH}" \
        "${SOAR_INSTALL_HELPER_PATH}" \
        >> "${LOG_FILE}" 2>&1 || true
fi

# --- 11f. Install Polkit rule for dnf-auto-helper (optional) ---
if [ -d /etc/polkit-1/rules.d ]; then
    POLKIT_RULES_FILE="/etc/polkit-1/rules.d/90-dnf-auto-helper.rules"
    log_info ">>> Installing Polkit rule for dnf-auto-helper preview commands..."
    update_status "Installing Polkit rule for dnf preview..."

    cat << 'EOF' > "$POLKIT_RULES_FILE"
// Allow members of the wheel group to run safe, non-interactive dnf
// preview commands used by dnf-auto-helper without an authentication
// prompt. This covers:
//   pkexec /usr/bin/sh -c 'LC_ALL=C /usr/bin/dnf -q makecache'
//   pkexec /usr/bin/sh -c 'LC_ALL=C /usr/bin/dnf -q upgrade --assumeno'
polkit.addRule(function(action, subject) {
    if (action.id == "org.freedesktop.policykit.exec" &&
        subject.isInGroup("wheel")) {
        var cmd = action.lookup("command");
        var argv = action.lookup("argv");
        if (!argv || !cmd) {
            return polkit.Result.NOT_HANDLED;
        }

        // Legacy direct dnf path: pkexec /usr/bin/dnf -q ...
        if (cmd == "/usr/bin/dnf") {
            // Expect argv like: ["/usr/bin/dnf", "-q", "makecache", ...]
            if (argv.length >= 3 && argv[1] == "-q") {
                if (argv[2] == "makecache") {
                    return polkit.Result.YES;
                }
                if (argv[2] == "upgrade" && argv.indexOf("--assumeno") >= 0) {
                    return polkit.Result.YES;
                }
            }
        }

        // New shell-wrapped form used by dnf-auto-helper:
        //   pkexec /usr/bin/sh -c "LC_ALL=C /usr/bin/dnf -q ..."
        if (cmd == "/usr/bin/sh" && argv.length >= 3 && argv[1] == "-c") {
            var script = argv[2];
            if (!script) {
                return polkit.Result.NOT_HANDLED;
            }

            // Normalise by trimming leading/trailing whitespace
            script = script.trim();

            if (script.indexOf("LC_ALL=C /usr/bin/dnf -q makecache") === 0) {
                return polkit.Result.YES;
            }
            if (script.indexOf("LC_ALL=C /usr/bin/dnf -q upgrade --assumeno") === 0) {
                return polkit.Result.YES;
            }
        }
    }
    return polkit.Result.NOT_HANDLED;
});
EOF

    chmod 644 "$POLKIT_RULES_FILE" 2>/dev/null || true
else
    log_info "Polkit rules directory /etc/polkit-1/rules.d not found; skipping Polkit rule installation"
fi

# --- 12. Final self-check ---
log_info ">>> Final syntax self-check..."
update_status "Running final syntax checks..."
run_self_check

# --- 13. Reload user systemd daemon and ensure notifier timer is active ---
USER_BUS_PATH="unix:path=/run/user/$(id -u "$SUDO_USER")/bus"

log_info ">>> Reloading user systemd daemon and (re)starting ${NT_SERVICE_NAME}.timer..."
update_status "Enabling user services..."
log_debug "User bus path: $USER_BUS_PATH"

if sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user daemon-reload >> "${LOG_FILE}" 2>&1; then
    log_success "User systemd daemon reloaded"
    
    log_debug "Enabling user timer: ${NT_SERVICE_NAME}.timer"
    if sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user enable --now "${NT_SERVICE_NAME}.timer" >> "${LOG_FILE}" 2>&1; then
        log_success "User notifier timer enabled and started"
        # Some systemd versions can leave the timer in an 'elapsed' state
        # with no NEXT trigger after unit changes. Force a restart so it
        # gets a fresh schedule and actually fires again for this user.
        log_debug "Restarting user timer to ensure it is scheduled"
        sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" systemctl --user restart "${NT_SERVICE_NAME}.timer" >> "${LOG_FILE}" 2>&1 || true
    else
        log_error "Failed to enable user timer (non-fatal)"
        log_info "You may need to run manually as the target user:"
        log_info "  systemctl --user enable --now ${NT_SERVICE_NAME}.timer"
    fi
else
    log_error "Warning: Could not talk to user systemd (no session bus?)"
    log_info "You may need to run manually as the target user:"
    log_info "  systemctl --user daemon-reload"
    log_info "  systemctl --user enable --now ${NT_SERVICE_NAME}.timer"
fi


# --- 14. Installation Verification (called during install) ---
if [ "${VERIFICATION_ONLY_MODE:-0}" -ne 1 ]; then
    # Only run verification during installation, not in verify-only mode
    # (verify-only mode calls the function directly and exits)
    run_verification_only
    VERIFICATION_EXIT_CODE=$?
else
    # Should never reach here - verify mode exits earlier
    VERIFICATION_EXIT_CODE=0
fi

# --- 14b. Check for Optional Packages ---
log_info ">>> Checking for optional package managers..."
MISSING_PACKAGES=()

if ! command -v flatpak >/dev/null 2>&1; then
    log_info "Flatpak is not installed (optional)"
    MISSING_PACKAGES+=("flatpak")
fi

if ! command -v snap >/dev/null 2>&1; then
    log_info "Snapd is not installed (optional)"
    MISSING_PACKAGES+=("snapd")
fi

# Optional: Soar CLI helper (used to sync metadata after updates)
# Soar is typically installed per-user (for example under ~/.local/bin or
# ~/pkgforge). Detect it using the user's PATH and common install dirs so
# we don't warn when it is already present.
SOAR_PRESENT=0

# Optional: pipx helper (for Python CLI tools). Only warn when
# ENABLE_PIPX_UPDATES=true and pipx is missing for the target user.
PIPX_MISSING_FOR_UPDATES=0
if [[ "${ENABLE_PIPX_UPDATES,,}" == "true" ]]; then
    if ! sudo -u "$SUDO_USER" command -v pipx >/dev/null 2>&1; then
        PIPX_MISSING_FOR_UPDATES=1
        log_info "pipx is not installed for user $SUDO_USER but ENABLE_PIPX_UPDATES=true (optional)"
    fi
fi

# 1) Check via the user's PATH
if sudo -u "$SUDO_USER" command -v soar >/dev/null 2>&1; then
    SOAR_PRESENT=1
# 2) Check common per-user install locations
elif [ -x "$SUDO_USER_HOME/.local/bin/soar" ]; then
    SOAR_PRESENT=1
elif [ -d "$SUDO_USER_HOME/pkgforge" ] && \
     find "$SUDO_USER_HOME/pkgforge" -maxdepth 1 -type f -name 'soar*' -perm -u+x 2>/dev/null | grep -q .; then
    SOAR_PRESENT=1
fi

if [ "$SOAR_PRESENT" -eq 0 ]; then
    log_info "Soar CLI is not installed for user $SUDO_USER (optional)"
    MISSING_PACKAGES+=("soar")
fi

if [ "$PIPX_MISSING_FOR_UPDATES" -eq 1 ]; then
    MISSING_PACKAGES+=("pipx")
fi

# Notify user about missing packages if any
if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
    log_info "Optional package managers missing: ${MISSING_PACKAGES[*]}"
    
    # Create notification for user
    MISSING_MSG="The following optional package managers are not installed:\n\n"
    for pkg in "${MISSING_PACKAGES[@]}"; do
        if [ "$pkg" = "flatpak" ]; then
            MISSING_MSG+="• Flatpak - for Flatpak app updates\n  Install: sudo dnf install flatpak\n\n"
        elif [ "$pkg" = "snapd" ]; then
            MISSING_MSG+="• Snapd - for Snap package updates\n  Install: sudo dnf install snapd\n  Enable: sudo systemctl enable --now snapd\n\n"
        fi
    done
    MISSING_MSG+="These are optional. System updates will work without them."
    
    # Send desktop notification to user
    if command -v notify-send >/dev/null 2>&1; then
        sudo -u "$SUDO_USER" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" notify-send \
            -u normal \
            -t 15000 \
            -i "dialog-information" \
            "DNF Auto-Helper: Optional Packages" \
            "${MISSING_MSG}" 2>/dev/null || true
    fi

    # If Soar is missing and the helper exists, also show a richer
    # notification with an "Install Soar" button that opens a terminal
    # running the official install script.
    if printf '%s
' "${MISSING_PACKAGES[@]}" | grep -qx 'soar'; then
        # Propagate DISPLAY from the current environment so the helper
        # can open a terminal on the correct graphical session. Without
        # this, the helper fell back to DISPLAY=:0 which may not match
        # the user's real display.
        if sudo -u "$SUDO_USER" DISPLAY="$DISPLAY" DBUS_SESSION_BUS_ADDRESS="$USER_BUS_PATH" \
            "$USER_BIN_DIR/dnf-soar-install-helper" >/dev/null 2>&1 & then
            log_debug "Launched Soar install helper notification for user $SUDO_USER"
        fi
    fi
    
    echo "" | tee -a "${LOG_FILE}"
    echo "============================" | tee -a "${LOG_FILE}"
    echo "⚠️  Optional Packages Missing" | tee -a "${LOG_FILE}"
    echo "============================" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"
    for pkg in "${MISSING_PACKAGES[@]}"; do
        if [ "$pkg" = "flatpak" ]; then
            echo "Flatpak:" | tee -a "${LOG_FILE}"
            echo "  Purpose: Update Flatpak applications" | tee -a "${LOG_FILE}"
            echo "  Install: sudo dnf install flatpak"
            echo "" | tee -a "${LOG_FILE}"
        elif [ "$pkg" = "snapd" ]; then
            echo "Snapd:" | tee -a "${LOG_FILE}"
            echo "  Purpose: Update Snap packages" | tee -a "${LOG_FILE}"
            echo "  Install: sudo dnf install snapd"
            echo "  Enable:  sudo systemctl enable --now snapd" | tee -a "${LOG_FILE}"
            echo "" | tee -a "${LOG_FILE}"
        elif [ "$pkg" = "soar" ]; then
            echo "Soar:" | tee -a "${LOG_FILE}"
            echo "  Purpose: Optional CLI helper for keeping metadata in sync after updates" | tee -a "${LOG_FILE}"
            echo "  Install: curl -fsSL \"https://raw.githubusercontent.com/pkgforge/soar/main/install.sh\" | sh" | tee -a "${LOG_FILE}"
            echo "  Usage after install: soar sync" | tee -a "${LOG_FILE}"
            echo "" | tee -a "${LOG_FILE}"
        elif [ "$pkg" = "pipx" ]; then
            echo "pipx:" | tee -a "${LOG_FILE}"
            echo "  Purpose: Manage standalone Python CLI tools (yt-dlp, black, ansible, httpie, etc.)" | tee -a "${LOG_FILE}"
            echo "  Install: sudo dnf install pipx"
            echo "  Helper:  dnf-auto-helper --pip-package  (run without sudo)"
            echo "" | tee -a "${LOG_FILE}"
        fi
    done
    echo "Note: These are optional. System updates will work without them." | tee -a "${LOG_FILE}"
    echo "============================" | tee -a "${LOG_FILE}"
    echo "" | tee -a "${LOG_FILE}"
fi

# --- 15. Final Summary ---
log_success ">>> Installation completed successfully!"
update_status "SUCCESS: Installation completed"

echo "" | tee -a "${LOG_FILE}"
echo "==============================================" | tee -a "${LOG_FILE}"
echo "Installation Summary:" | tee -a "${LOG_FILE}"
echo "  - Command: dnf-auto-helper (installed to /usr/local/bin)"
echo "  - System service: ${DL_SERVICE_NAME}.timer (enabled)" | tee -a "${LOG_FILE}"
echo "  - User service: ${NT_SERVICE_NAME}.timer (enabled)" | tee -a "${LOG_FILE}"
echo "  - Install logs: ${LOG_DIR}/install-*.log" | tee -a "${LOG_FILE}"
echo "  - Service logs: ${LOG_DIR}/service-logs/" | tee -a "${LOG_FILE}"
echo "  - User logs: ${USER_LOG_DIR}/" | tee -a "${LOG_FILE}"
echo "  - Status file: ${STATUS_FILE}" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"
echo "Quick Commands:" | tee -a "${LOG_FILE}"
echo "  sudo dnf-auto-helper --verify        # Check system health"
echo "  sudo dnf-auto-helper --help          # Show help"
echo "  cat ${STATUS_FILE}                      # View current status" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"
echo "Service Status:" | tee -a "${LOG_FILE}"
echo "  systemctl status ${DL_SERVICE_NAME}.timer" | tee -a "${LOG_FILE}"
echo "  systemctl --user status ${NT_SERVICE_NAME}.timer" | tee -a "${LOG_FILE}"
echo "" | tee -a "${LOG_FILE}"
echo "View Logs:" | tee -a "${LOG_FILE}"
echo "  journalctl -u ${DL_SERVICE_NAME}.service" | tee -a "${LOG_FILE}"
echo "  journalctl --user -u ${NT_SERVICE_NAME}.service" | tee -a "${LOG_FILE}"
echo "  cat ${LOG_FILE}" | tee -a "${LOG_FILE}"
echo "==============================================" | tee -a "${LOG_FILE}"
echo "Completed: $(date)" | tee -a "${LOG_FILE}"
