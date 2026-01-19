# DNF Auto-Downloader for Fedora

A robust `systemd` architecture that automates background **DNF upgrade downloads**, provides persistent, battery‑safe **user notifications**, and cleanly installs, verifies, and uninstalls itself.

It is built and tested for Fedora with `dnf`/`dnf5`.

## ⚡ Quick Start

```bash
chmod +x DNF-auto.sh
sudo ./DNF-auto.sh install    # installs helper, units, and default config

# Optional: run a health check after install
dnf-auto-helper --verify

# Later, just watch for "Updates ready" notifications and click Install
```

-----

## 🐞 Reporting Issues

**If you need help, please include the relevant logs.** See [Reporting Issues](#reporting-issues) for exact commands.

-----

## 🎯 Goal

On Fedora, updates can be frequent and large. The slow part is usually **downloading** packages, not running `dnf upgrade` itself.

This helper automates the slow part: it runs a background **DNF downloader** on a schedule so that, when you choose to upgrade, most or all packages are already in the cache. A "10‑minute" update becomes roughly "1 minute of authenticated install".

By default it runs a full `dnf upgrade --downloadonly` in the background (configurable), but only after passing several safety checks.

-----

## ✨ Key Features

- **Single entrypoint command:**
  - `dnf-auto-helper` in `/usr/local/bin` (installed by `DNF-auto.sh`).
  - Shell aliases for Bash, Zsh, and Fish so you can just type `dnf-auto-helper`.
  - Sub‑commands: `install`, `--verify`, `--repair`, `--diagnose`, `--check`, `--reset-config`, `--soar`, `--brew`, `--pip-package` (alias: `--pipx`), and scripted uninstall modes.

- **Background pre‑download of updates:**
  - Root systemd service + timer:
    - `dnf-autodownload.service`
    - `dnf-autodownload.timer`
  - Runs a controlled `dnf upgrade --downloadonly` pass using settings from `/etc/dnf-auto.conf`.
  - Writes machine‑readable status to `/var/log/dnf-auto/download-status.txt` (e.g. `refreshing`, `downloading:…`, `complete:…`, `idle`).
  - Default behaviour is **`DOWNLOADER_DOWNLOAD_MODE=full`** so packages are cached ahead of time. You can switch to `detect-only` if you only want notifications.

- **User‑space notifier with desktop integration:**
  - User service + timer in `~/.config/systemd/user`:
    - `dnf-notify-user.service`
    - `dnf-notify-user.timer`
  - Python notifier script: `~/.local/bin/dnf-notify-updater.py`.
  - Talks to your desktop session over D‑Bus and shows rich, clickable notifications.
  - Distinguishes laptops vs desktops, AC vs battery, metered vs unmetered connections using `upower`, `inxi`, and `nmcli` and only runs checks when it is safe.

- **Ready‑to‑Install helper:**
  - Clickable "Install" / "Install now" actions open a terminal and run a wrapper script:
    - `~/.local/bin/dnf-run-install`
  - That script drives `pkexec dnf upgrade` interactively, with additional post‑update checks.

- **Optional post‑update helpers:** (controlled via `/etc/dnf-auto.conf`)
  - Flatpak updates.
  - Snap refresh (if Snap is installed).
  - Soar (PkgForge) stable‑version check + `soar sync` + `soar update`.
  - Homebrew: `brew update` and conditional `brew upgrade`.
  - pipx: optional `pipx upgrade-all` so Python CLI tools stay in sync with system updates.

- **Health‑check & auto‑repair:**
  - `dnf-auto-helper --verify` runs a 12‑point check that verifies:
    - Root timers and services are active + enabled.
    - User timers/services exist and are active.
    - Helper scripts exist, are executable, and have valid syntax.
    - Log directories and status files exist.
    - Stale DNF PID locks are cleaned up when safe.
    - Root filesystem free space is sane (with optional `dnf clean all`).
  - Many common problems are auto‑fixed; remaining issues are summarised.
  - A root service + timer (`dnf-auto-verify.service` / `dnf-auto-verify.timer`) can run the same logic periodically.

- **Configuration in `/etc/dnf-auto.conf`:**
  - Timer intervals, log retention, notifier cache/snooze behaviour.
  - Optional helpers on/off flags (Flatpak, Snap, Soar, Homebrew, pipx).
  - Extra DNF solver flags via `DUP_EXTRA_FLAGS` (for both downloader and preview).
  - All values are validated; invalid values fall back to safe defaults and are logged.

- **Scripted uninstaller:**
  - `dnf-auto-helper --uninstall-zypper-helper` (retained to clean old *zypper* helper installations) removes the legacy zypper‑auto‑helper services/scripts/logs without touching DNF or Fedora configuration.
  - DNF‑auto‑helper’s own components are also removable via the same uninstaller logic.

- **Extensive logging:**
  - Installation logs and status under `/var/log/dnf-auto/`.
  - Service logs under `/var/log/dnf-auto/service-logs/`.
  - Notifier logs and status under `~/.local/share/dnf-notify/`.
  - Automatic log rotation and pruning.

- **Safety first:**
  - Installer disables common PackageKit background services that would otherwise compete for the DNF lock.
  - Downloader runs at low CPU/IO priority; safety decisions (AC, metered, etc.) are enforced in the notifier.

-----

## 🧱 Architecture Overview

There are three main components: the installer, the root‑level downloader/verification services, and the user‑level notifier.

### 1. Installer: `DNF-auto.sh`

Run once (or whenever you update config) as root:

- Cleans up any older helper installations (including legacy zypper‑auto‑helper units if present).
- Ensures dependencies are installed (e.g. `nmcli`, `upower`, `inxi`, `python3`, `python3-gobject`, `pkexec`, `semanage`).
- Writes systemd units for:
  - `dnf-autodownload.service` / `dnf-autodownload.timer`
  - `dnf-cache-cleanup.service` / `dnf-cache-cleanup.timer`
  - `dnf-auto-verify.service` / `dnf-auto-verify.timer`
- Sets up user units and scripts for the notifier:
  - `~/.config/systemd/user/dnf-notify-user.service` / `.timer`
  - `~/.local/bin/dnf-notify-updater.py`, `dnf-run-install`, `dnf-with-ps`, `dnf-view-changes`.
- Creates the `dnf-auto-helper` CLI in `/usr/local/bin` and shell aliases.
- Loads and validates `/etc/dnf-auto.conf`, writing a documented default file if it is missing.

### 2. Downloader (root service)

- **Service:** `/etc/systemd/system/dnf-autodownload.service`
  - Runs a preview + download pass using DNF (behaviour controlled by `DOWNLOADER_DOWNLOAD_MODE` and `DUP_EXTRA_FLAGS`).
  - Writes status to `/var/log/dnf-auto/download-status.txt`:
    - `refreshing`
    - `downloading:…`
    - `complete:…`
    - `idle`
- **Timer:** `/etc/systemd/system/dnf-autodownload.timer`
  - Interval derived from `DL_TIMER_INTERVAL_MINUTES` in `/etc/dnf-auto.conf`.
  - Allowed values: `1,5,10,15,30,60` minutes.
  - Mapped to simple schedules (`minutely`, `hourly`, or `*:0/N`).

### 3. Verification / Auto‑Repair (root service)

- **Service:** `/etc/systemd/system/dnf-auto-verify.service`
  - Runs the same verification logic that `dnf-auto-helper --verify` uses.
  - Optionally sends a short desktop notification when it fixes issues (controlled by `VERIFY_NOTIFY_USER_ENABLED`).
- **Timer:** `/etc/systemd/system/dnf-auto-verify.timer`
  - Interval from `VERIFY_TIMER_INTERVAL_MINUTES` (same allowed values as above).

### 4. Notifier (user service)

- **Service:** `~/.config/systemd/user/dnf-notify-user.service`
  - Runs `~/.local/bin/dnf-notify-updater.py` under your user.
  - Reads downloader status, re‑checks with a non‑interactive DNF preview, and drives notifications.
- **Timer:** `~/.config/systemd/user/dnf-notify-user.timer`
  - Interval from `NT_TIMER_INTERVAL_MINUTES` in `/etc/dnf-auto.conf`.

Typical flow:

1. Downloader timer fires and pre‑downloads updates using DNF.
2. Notifier timer wakes up, checks the cached status and DNF preview.
3. If updates are ready, you see a **"Updates Ready"** notification with buttons like **Install**, **View Changes**, **Snooze 1h/4h/1d**.
4. Clicking **Install** opens a terminal running `dnf-run-install`, which wraps `pkexec dnf upgrade` and post‑update helpers.

-----

## 🚀 Installation / Upgrade

You can run the installer on a fresh Fedora system or over an existing helper installation; it is idempotent.

```bash
chmod +x DNF-auto.sh
sudo ./DNF-auto.sh install
```

The installer will:

- Create/update `/etc/dnf-auto.conf` (if missing, a documented default is written).
- Install or update the `dnf-auto-helper` command.
- Set up root and user systemd units.
- Disable conflicting PackageKit background services.
- Run syntax checks and a verification pass.

After installation, restart your shell or open a new terminal so the `dnf-auto-helper` alias is available.

### Using `dnf-auto-helper`

```bash
dnf-auto-helper --help          # Show help and available commands
dnf-auto-helper install         # Re-run installation / upgrade
dnf-auto-helper --verify        # Full health check + auto-repair
dnf-auto-helper --repair        # Alias for --verify
dnf-auto-helper --diagnose      # Alias for --verify
dnf-auto-helper --check         # Syntax/self-check only
dnf-auto-helper --reset-config  # Reset /etc/dnf-auto.conf to defaults (with backup)
dnf-auto-helper --soar          # Optional Soar helper (install/upgrade)
dnf-auto-helper --brew          # Optional Homebrew helper (install/upgrade)
dnf-auto-helper --pip-package   # Optional pipx helper (install/upgrade, alias: --pipx)
```

You normally run `dnf-auto-helper` **without** `sudo`; it uses `pkexec` or root services internally when needed.

-----

## ⚙️ Configuration: `/etc/dnf-auto.conf`

The installer reads `/etc/dnf-auto.conf` on each run. If the file is missing, a documented template is generated.

Some important options (names match what `DNF-auto.sh` expects):

- **Post‑update helpers**
  - `ENABLE_FLATPAK_UPDATES`
  - `ENABLE_SNAP_UPDATES`
  - `ENABLE_SOAR_UPDATES`
  - `ENABLE_BREW_UPDATES`
  - `ENABLE_PIPX_UPDATES`

- **Timer intervals** (minutes; allowed: `1,5,10,15,30,60`)
  - `DL_TIMER_INTERVAL_MINUTES` – downloader timer frequency.
  - `NT_TIMER_INTERVAL_MINUTES` – user notifier frequency.
  - `VERIFY_TIMER_INTERVAL_MINUTES` – health‑check timer frequency.

- **Notifier cache / snooze**
  - `CACHE_EXPIRY_MINUTES` – how long a cached preview is trusted before forcing a new check.
  - `SNOOZE_SHORT_HOURS`, `SNOOZE_MEDIUM_HOURS`, `SNOOZE_LONG_HOURS` – real durations for the 1h / 4h / 1d snooze buttons.

- **Downloader behaviour and DNF flags**
  - `DOWNLOADER_DOWNLOAD_MODE` (case‑sensitive):
    - `full` (default) – run a full `dnf upgrade --downloadonly` and cache packages.
    - `detect-only` – only run a non‑interactive preview; no pre‑download.
  - `DUP_EXTRA_FLAGS` – extra flags appended to every DNF call made by the helper
    (both downloader and notifier). Useful for things like `--refresh` or repo
    selection flags.

- **Lock behaviour & reminders**
  - `LOCK_RETRY_MAX_ATTEMPTS`, `LOCK_RETRY_INITIAL_DELAY_SECONDS` – how the Ready‑to‑Install helper retries when the package manager lock is in use.
  - `LOCK_REMINDER_ENABLED` – whether to show a small "updates paused, DNF is in use" notification while another DNF/PackageKit instance holds the lock.
  - `NO_UPDATES_REMINDER_REPEAT_ENABLED` / `UPDATES_READY_REMINDER_REPEAT_ENABLED` – control whether identical "No updates" / "Updates ready" notifications can repeat.
  - `VERIFY_NOTIFY_USER_ENABLED` – whether periodic verification sends a summary notification when it fixes issues.

If values are missing or invalid, `DNF-auto.sh` falls back to safe defaults, logs warnings, and records them in `/var/log/dnf-auto/last-status.txt`. The helper may also suggest `dnf-auto-helper --reset-config`.

-----

## 🏃 Everyday Usage

Once installed you normally **don’t** need to run anything manually:

1. **Wait** – the downloader and notifier timers run in the background (by default every minute; configurable via `/etc/dnf-auto.conf`).
2. **Watch for notifications** – you’ll see a notification only when updates are actually pending.
3. **Click Install** – the **Install** button launches `dnf-run-install` in a terminal, which runs `pkexec dnf upgrade` plus any enabled helpers (Flatpak, Snap, Soar, Homebrew, pipx).

### Quick Status Checks

```bash
# High-level installation/system status
cat /var/log/dnf-auto/last-status.txt

# Notifier status
cat ~/.local/share/dnf-notify/last-run-status.txt

# Raw downloader status file
cat /var/log/dnf-auto/download-status.txt

# Health check + auto-repair
dnf-auto-helper --verify
```

-----

## 📊 Logging & Monitoring

- **System / installer logs:** `/var/log/dnf-auto/`
  - `install-YYYYMMDD-HHMMSS.log` – full log of each installer run.
  - `last-status.txt` – last high‑level status message.
  - `service-logs/*.log` – logs from downloader / verification services.
- **User / notifier logs:** `~/.local/share/dnf-notify/`
  - `notifier-detailed.log` – detailed notifier log.
  - `last-run-status.txt` – last notifier status.

Example commands:

```bash
# Show most recent install log
ls -t /var/log/dnf-auto/install-*.log | head -1 | xargs sudo cat

# Downloder service logs
sudo cat /var/log/dnf-auto/service-logs/downloader.log

# Notifier details
cat ~/.local/share/dnf-notify/notifier-detailed.log
```

Logs are automatically rotated and pruned; no manual maintenance is required.

-----

## 🗑️ Uninstallation

### Scripted uninstaller (recommended)

The helper includes a scripted uninstaller designed to **clean up helper components only** (it never removes DNF itself or Fedora configuration).

```bash
# From the directory containing DNF-auto.sh
sudo ./DNF-auto.sh --uninstall-zypper-helper   # cleans up legacy zypper helper + DNF helper units

# Or via the installed CLI
dnf-auto-helper --uninstall-zypper-helper
```

Typical effects:

- Stop & disable helper timers/services (dnf‑autodownload, dnf‑cache‑cleanup, dnf‑auto‑verify, notifier units).
- Remove helper systemd unit files and scripts.
- Remove user helper scripts, aliases, and notifier caches.
- Optionally keep or delete logs under `/var/log/dnf-auto/`.

Advanced flags like `--yes`, `--dry-run`, and `--keep-logs` are supported in the same way as in the legacy zypper helper.

-----

## 📣 Reporting Issues

When filing an issue, please include at least:

```bash
# 1) Most recent installer log
sudo cat $(ls -t /var/log/dnf-auto/install-*.log | head -1)

# 2) Installer status
cat /var/log/dnf-auto/last-status.txt

# 3) Notifier detailed log
cat ~/.local/share/dnf-notify/notifier-detailed.log

# 4) Notifier last run status
cat ~/.local/share/dnf-notify/last-run-status.txt
```

Also mention:

- Your Fedora version: `cat /etc/os-release`
- DNF version: `dnf --version` (and `dnf5 --version` if applicable)
- A short description of what you expected vs what happened.

Please **redact personal data** (usernames, hostnames, network names) from logs before posting.

-----

## 🛠️ How It Works: The v58 Architecture

This is a two-service system to provide both safety (Downloader) and persistence/user interaction (Notifier).

### 1. The Installer: `zypper-auto.sh`

* **Cleanup:** Explicitly stops and disables all timers/services from *any* previous version to ensure a clean state.
* **User Detection:** Reliably determines the `$SUDO_USER`'s home directory to place the user-specific systemd files and scripts (`~/.config/systemd/user`, `~/.local/bin`).
* **Enables Root Timer:** After writing the units, it runs `systemctl daemon-reload` and `systemctl enable --now zypper-autodownload.timer` automatically.

### 2. The Downloader (Root Service)

This service's only job is to download packages when it's safe, and report progress stages.

* **Service:** `/etc/systemd/system/zypper-autodownload.service`
    * This service runs `zypper refresh` and `zypper dup --download-only`.
    * It writes stage information to `/var/log/zypper-auto/download-status.txt`:
        * `refreshing` - Repositories being refreshed
        * `downloading:X` - Downloading X packages (includes count)
        * `complete` - Ready for installation
        * `idle` - No updates available
    * It will **only** start if `ConditionACPower=true` and `ConditionNotOnMeteredConnection=true` are met.
* **Timer:** `/etc/systemd/system/zypper-autodownload.timer`
*    * Default schedule is derived from the config option `DL_TIMER_INTERVAL_MINUTES` in `/etc/zypper-auto.conf` (allowed values: 1,5,10,15,30,60).
*    * For example:
*        * `1`  → runs minutely
*        * `10` → runs every 10 minutes (`OnCalendar=*:0/10`)
*        * `60` → runs hourly (`OnCalendar=hourly`)
*
### 3. Periodic Verification / Auto-Repair Service

In addition to the downloader, a small root service periodically runs the same
12-point verification and auto-repair logic as `zypper-auto-helper --verify`:

* **Service:** `/etc/systemd/system/zypper-auto-verify.service`
    * Runs `zypper-auto-helper --verify` as a oneshot root service.
    * Logs to `/var/log/zypper-auto/service-logs/verify.log`.
    * Automatically resets failed states for the core units it manages and,
      when configured, sends a short desktop notification whenever it fixes
      one or more issues.
    * Performs safety checks such as cleaning up stale `/run/zypp.pid`
      locks (when the PID is no longer running) and running
      `zypper clean --all` when free space on `/` falls below ~1 GiB.
* **Timer:** `/etc/systemd/system/zypper-auto-verify.timer`
    * Default schedule is derived from `VERIFY_TIMER_INTERVAL_MINUTES` in
      `/etc/zypper-auto.conf` (allowed values: `1,5,10,15,30,60`). The
      installer converts this into a simple calendar schedule in the same
      way as the downloader timer (minutely, hourly, or `*:0/N`).
+
+### 4. The Notifier (User Service)

* **Service:** `~/.config/systemd/user/zypper-notify-user.service`
    * Runs the Python script `~/.local/bin/zypper-notify-updater.py`.
    * Because it runs in user-space, it has the correct D-Bus environment variables to display notifications reliably.
* **Timer:** `~/.config/systemd/user/zypper-notify-user.timer`
    * Default schedule is derived from `NT_TIMER_INTERVAL_MINUTES` in `/etc/zypper-auto.conf` (same allowed values as above).
    * By changing `NT_TIMER_INTERVAL_MINUTES` (e.g. to 10 or 60) and re-running the installer, you can control how often the notifier checks and pops notifications.

### 4. The "Brains": `~/.local/bin/zypper-notify-updater.py`

This Python script is the core of the system, run by the `zypper-notify-user.service` on the schedule defined by the user timer.

1.  **Checks Download Stage:** Reads `/var/log/zypper-auto/download-status.txt` to determine if downloads are in progress:
    * `refreshing` → Shows "Checking for updates..." notification
    * `downloading:X` → Shows "Downloading X packages..." notification with count
    * `complete` or `idle` → Proceeds to normal update check
2.  **Checks Safety:** Uses `inxi`, `upower` and `nmcli` with extra heuristics to:
    * distinguish laptops (real internal battery + AC adapter) from desktops/UPS/embedded setups,
    * reliably classify any system with a real battery as a laptop, even when `upower` does not expose a `line_power` device,
    * treat desktops as always on AC for safety decisions,
    * treat NetworkManager failures as "unmetered" to avoid random false positives.
3.  **Runs Zypper:** Executes `pkexec zypper refresh` (if safe) and always runs `pkexec zypper dup --dry-run` to check for pending updates. On laptops, "safe" explicitly means **on AC and not on a metered connection**.
4.  **Parses Output:** Counts packages and finds the latest Tumbleweed snapshot version.
5.  **Sends Clickable Notification:** Uses PyGObject to send a rich notification with the snapshot version and an **"Install"** button.
6.  **Launches Terminal (Action):** Clicking "Install" runs the `~/.local/bin/zypper-run-install` script via `systemd-run --user --scope`, which launches your preferred terminal (`konsole`, `gnome-terminal`, etc.) to execute `pkexec zypper dup` interactively.
7.  **Post-Update Check:** After update completes, runs `zypper ps -s` to show which services need restart and provides reboot guidance if needed.
8.  **Debug Mode:** If `ZNH_DEBUG=1` (or `true/yes/debug`) is set in the environment, extra debug logs (e.g. `upower` / `nmcli` / `inxi` decisions) are printed to the journal.
9.  **Manual-Intervention Helper (v54+):** When `pkexec zypper dup --dry-run` or the background downloader encounter a solver/interaction problem (such as a vendor conflict), the notifier shows a dedicated, persistent "Updates require your decision" notification. It:
    - Includes a concise summary of the problem (first `Problem:` line when available).
    - Attempts to parse the dry-run output to show how many updates are pending and a short package preview, so you still see *what* is waiting to be installed even though zypper needs your choice.
    - Provides an **"Install Now"** / **"Open Helper"** action that launches `~/.local/bin/zypper-run-install` so you can resolve the conflict interactively in a terminal, plus snooze and "View Changes" actions.

-----

## 🚀 Installation / Upgrading

The script is idempotent. You can run this on a fresh install *or* on a PC with an older version.

1.  Download the latest `zypper-auto.sh` script.
2.  Make it executable:
    ```bash
    chmod +x zypper-auto.sh
    ```
3.  Run it with `sudo`. The script will handle everything automatically:
    ```bash
    sudo ./zypper-auto.sh install
    ```

**That's it!** The installer now:
- Installs the `zypper-auto-helper` command to `/usr/local/bin`
- Adds shell aliases to your `.bashrc`, `.zshrc`, or Fish config
- Enables both root and user services automatically
- Runs comprehensive verification and auto-repair
- Reports any issues and fixes them automatically

### Using the Installed Command

After installation (restart your shell or run `source ~/.bashrc`), you can use:

```bash
zypper-auto-helper --help          # Show help
zypper-auto-helper --verify        # Run health check and auto-repair
zypper-auto-helper --repair        # Alias for --verify
zypper-auto-helper --diagnose      # Alias for --verify
zypper-auto-helper --check         # Syntax check only
zypper-auto-helper install         # Reinstall/upgrade
zypper-auto-helper --reset-config  # Reset /etc/zypper-auto.conf to documented defaults (with backup)
zypper-auto-helper --soar          # Install/upgrade the optional Soar CLI helper
zypper-auto-helper --brew          # Install/upgrade Homebrew (brew) for the system/user
zypper-auto-helper --pip-package    # Install/guide pipx and manage Python CLI tools (alias: --pipx)
zypper-auto-helper --uninstall-zypper-helper  # Remove only this helper's services/scripts/logs (alias: --uninstall-zypper)
```

You normally run `zypper-auto-helper` **without** `sudo`; it will prompt for elevation internally when needed.

### Configuration File: `/etc/zypper-auto.conf`

The installer reads an optional config file at `/etc/zypper-auto.conf` on every run.
If the file does not exist, it generates a documented default template. You can
safely edit this file and re-run `sudo ./zypper-auto.sh install` to apply
changes.

Key options include:

- **Post-update helpers**
  - `ENABLE_FLATPAK_UPDATES` / `ENABLE_SNAP_UPDATES` / `ENABLE_SOAR_UPDATES` /
    `ENABLE_BREW_UPDATES` / `ENABLE_PIPX_UPDATES` – `true` / `false` flags to
    control whether Flatpak, Snap, Soar, Homebrew, and pipx helpers run after
    `zypper dup`. When `ENABLE_PIPX_UPDATES=true` and `pipx` is installed, the
    wrapper and Ready‑to‑Install helper automatically run `pipx upgrade-all`
    after system updates to keep Python command‑line tools up to date.

- **Timer intervals**
  - `DL_TIMER_INTERVAL_MINUTES` – how often the root downloader runs
    (allowed **only**: `1,5,10,15,30,60`; any other value is ignored and
    replaced with a safe default).
  - `NT_TIMER_INTERVAL_MINUTES` – how often the user notifier runs (same
    allowed set and behaviour as above).
  - `VERIFY_TIMER_INTERVAL_MINUTES` – how often the root verification/auto‑repair
    service runs (again, allowed **only**: `1,5,10,15,30,60`).
  - The installer converts these into appropriate `OnCalendar` values, e.g.
    `*:0/10` for every 10 minutes or `hourly` for 60.

- **Caching / snooze**
  - `CACHE_EXPIRY_MINUTES` – how long a cached `zypper dup --dry-run` result
    is considered valid before forcing a fresh check.
  - `SNOOZE_SHORT_HOURS`, `SNOOZE_MEDIUM_HOURS`, `SNOOZE_LONG_HOURS` – actual
    durations used by the `1h` / `4h` / `1d` snooze buttons in the desktop
    notification.

- **Zypper solver flags**
  - `DUP_EXTRA_FLAGS` – extra arguments appended to every `zypper dup` invocation
    run by the helper, for **both** the background downloader (`dup --download-only`)
    and the notifier (`dup --dry-run`). This is the right place to add flags such
    as `--allow-vendor-change` or `--from <repo>` without editing the scripts.
  - Do **not** include `--non-interactive`, `--download-only`, or `--dry-run` here;
    those are added automatically by the helper where appropriate.

- **Lock handling & downloader behaviour**
  - `LOCK_RETRY_MAX_ATTEMPTS` – how many times the Ready-to-Install helper should
    retry when zypper/Yast holds the system management lock before giving up and
    showing a friendly message. Each attempt waits a bit longer than the previous
    one. Default: `10`.
  - `LOCK_RETRY_INITIAL_DELAY_SECONDS` – base delay (in seconds) used for the first
    lock retry. Subsequent retries multiply this base (1×, 2×, 3×, …). Set to `0`
    to fail fast when the lock is held. Default: `1`.
  - `LOCK_REMINDER_ENABLED` – when `true` (default), the notifier shows a small
    "Updates paused while zypper is running" notification on every check while
    zypper/YaST holds the system management lock. When `false`, lock situations
    are logged but no desktop popup is shown.
  - `NO_UPDATES_REMINDER_REPEAT_ENABLED` – when `true` (default), identical
    "No updates found" notifications may be re-shown on later checks while the
    system remains fully up to date. When `false`, the "No updates" message is
    shown once per state and then suppressed until new updates appear.
  - `UPDATES_READY_REMINDER_REPEAT_ENABLED` – when `true` (default), identical
    "Snapshot XXXX Ready" / "Updates ready" notifications may be re-shown on
    later checks while the same snapshot is still pending. When `false`, each
    "Updates ready" state only generates one popup until the snapshot changes.
  - `VERIFY_NOTIFY_USER_ENABLED` – when `true` (default), the periodic
    verification/auto‑repair service sends a short desktop notification when it
    detects and fixes at least one issue; when `false`, verification remains
    fully automatic but quiet.
  - `DOWNLOADER_DOWNLOAD_MODE` – controls how the background downloader behaves.
    This value is **case-sensitive** and must be exactly:
      - `full`        – (default) run `zypper dup --download-only` to prefetch all
        packages into the cache.
      - `detect-only` – only run `zypper dup --dry-run` to detect whether updates
        are available; no pre-download is done. Useful on bandwidth-limited
        systems or when you only want notifications and manual installs.

If any values are invalid, the installer falls back to safe defaults, logs the
warnings, updates `last-status.txt`, and attempts to show a small desktop
notification suggesting `zypper-auto-helper --reset-config`.

### Config Health & Stale Configs

Over time, new versions add new keys to `/etc/zypper-auto.conf`. To keep
behaviour predictable, the installer performs a basic **config health check**
whenever it runs:

- If the config file is **missing** → a fresh, fully documented template is
  generated.
- If the config file **exists but is missing newer keys** (for example
  `DUP_EXTRA_FLAGS`) → the installer:
  - Detects which keys are missing.
  - Logs a warning listing each missing key and a short description of the
    affected feature.
  - Adds the warning to `CONFIG_WARNINGS` so it appears in
    `/var/log/zypper-auto/last-status.txt`.
  - Tries to send a desktop notification suggesting:
    `sudo zypper-auto-helper --reset-config`.
  - Applies safe defaults for those keys at runtime so the installer and
    services continue to work.

If you see a warning that `/etc/zypper-auto.conf` is from an older version and
lists missing keys, the **recommended fix** is:

```bash
sudo zypper-auto-helper --reset-config
sudo ./zypper-auto.sh install
```

This backs up your existing config and regenerates it with all current options
and comments.

-----

## 🏃 Usage

1.  **Wait.** The services run in the background. By default, both the downloader and notifier run every minute. You can change their frequency via `/etc/zypper-auto.conf` (`DL_TIMER_INTERVAL_MINUTES` / `NT_TIMER_INTERVAL_MINUTES`) and re-run `sudo ./zypper-auto.sh install`.
2.  **Get Notified.** You will get a notification *only* when new updates are pending.
    > **Snapshot 20251110-0 Ready**
    > 12 updates are pending. Click 'Install' to begin.
3.  **Install.** Click the **"Install"** button in the notification. This will open a terminal and prompt you for authentication to run `zypper dup`.

### Quick Status Check

You can check the current status at any time:

```bash
# Run comprehensive health check and auto-repair
zypper-auto-helper --verify

# Check installation/system status
cat /var/log/zypper-auto/last-status.txt

# Check notifier status
cat ~/.local/share/zypper-notify/last-run-status.txt

# Check download progress
cat /var/log/zypper-auto/download-status.txt
```

### Debugging

If you want more verbose logging from the notifier script (for example, to see detailed `upower`/`nmcli` decisions), enable debug mode:

```bash
export ZNH_DEBUG=1
systemctl --user restart zypper-notify-user.service
journalctl --user -u zypper-notify-user.service -n 50 --no-pager
```

### Verifying the Services

```bash
# 1. Check Root Timer (Downloader)
# Should show "active" and the next scheduled run time
systemctl list-timers zypper-autodownload.timer

# 2. Check User Timer (Notifier)
# Must be run as your regular user. Should show "active" and the next scheduled run time.
systemctl --user list-timers zypper-notify-user.timer

# 3. Check the status of the last DOWNLOADER run
systemctl status zypper-autodownload.service

# 4. View the detailed logs from the smart notification script
journalctl --user -u zypper-notify-user.service

# 5. Change schedules via the config file (recommended):
sudoedit /etc/zypper-auto.conf
# Adjust DL_TIMER_INTERVAL_MINUTES / NT_TIMER_INTERVAL_MINUTES, then re-run:
sudo ./zypper-auto.sh install

# 6. (Advanced) Reload timers manually if you edited units yourself:
sudo systemctl daemon-reload
sudo systemctl restart zypper-autodownload.timer
systemctl --user daemon-reload
systemctl --user restart zypper-notify-user.timer
```

-----

## 👩‍💻 Developer / Contributor Testing

This repository includes two small helpers designed to make reproducing and
debugging behaviour easier for contributors:

### 1. Notification UI Test Harness (`test.py`)

Located in the repo root, `test.py` exercises the full notification flow
without touching systemd units or zypper itself:

```bash
python3 test.py
```

What it does:

- Simulates the main **happy path** notification stages:
  - "Checking for updates…"
  - "Downloading updates…" with a progress bar
  - "✅ Downloads Complete!" summary
  - Persistent "Snapshot XXXXXXXX Ready" notification with **Install**,
    **View Changes**, and **Snooze 1h/4h/1d** buttons.
- Simulates the main **error/edge-case** notifications:
  - Solver/interaction error ("Updates require your decision") with an
    **Install Now** action.
  - PolicyKit/authentication failure ("Update check failed").
  - Config warning ("zypper-auto-helper config warnings – run
    `zypper-auto-helper --reset-config`").
- Uses the same `on_action` callback shape as the real notifier so that
  clicking **Install** attempts to run `~/.local/bin/zypper-run-install` or,
  if missing, falls back to opening `konsole`.

All activity is logged to `test.log` in the repo root (ignored by Git). Each
run is wrapped in clear markers:

```text
================ RUN 20260105-212612 START ================
...
================ RUN 20260105-212612 END ==================
```

The log includes:

- Python version and key environment variables (`DISPLAY`, `WAYLAND_DISPLAY`,
  `XDG_SESSION_TYPE`, `USER`, `HOME`, `PWD`).
- For each notification: title, body preview, icon name, timeout, and (when
  relevant) the helper script path that would be launched.
- For each action click: action id, resolved script path, whether it exists and
  is executable, PID of any launched helper/terminal process, and full
  tracebacks for any failures.

### 2. Integration Test Script (`integration-test.sh`)

Also in the repo root, `integration-test.sh` performs a higher-level
integration test of the installed helper, timers and configuration.

> **Important:** This script is **non-destructive** with respect to your
> persistent configuration. It temporarily tweaks `/etc/zypper-auto.conf` to
> inject a known-bad value, but always restores your original config before
> exiting (even if a later step fails).

Run it as root:

```bash
cd /path/to/zypper-automatik-helper-
sudo ./integration-test.sh
```

What it checks:

- Presence and executability of core components:
  - `/usr/local/bin/zypper-auto-helper`
  - `/usr/local/bin/zypper-download-with-progress`
  - User scripts such as `~/.local/bin/zypper-notify-updater.py`,
    `~/.local/bin/zypper-run-install`, `~/.local/bin/zypper-with-ps` (if
    installed for the primary user).
- Root/systemd units:
  - `zypper-autodownload.timer` / `zypper-autodownload.service` (enabled/active).
  - `zypper-cache-cleanup.timer` / `zypper-cache-cleanup.service`.
- User systemd units (for the primary non-root user, when detectable):
  - `zypper-notify-user.timer` (enabled/active).
- CLI health:
  - `zypper-auto-helper --check` (syntax/self-check).
  - `zypper-auto-helper --verify` (12‑point verification and auto‑repair).

Config validation test:

- Ensures `/etc/zypper-auto.conf` exists (running `zypper-auto-helper install`
  if needed).
- Backs it up to a timestamped file such as
  `/etc/zypper-auto.conf.integration-backup-YYYYMMDD-HHMMSS`.
- Rewrites `DOWNLOADER_DOWNLOAD_MODE` to an intentionally invalid value
  (`"INVALID-MODE"`).
- Runs a full `zypper-auto-helper install` to force `load_config` and
  `CONFIG_WARNINGS` to execute.
- Locates the newest `install-*.log` in `/var/log/zypper-auto/` and verifies
  that:
  - An `Invalid DOWNLOADER_DOWNLOAD_MODE=...` line appears.
  - An aggregate warning about one or more invalid settings in
    `/etc/zypper-auto.conf` was recorded.
- Restores the original `/etc/zypper-auto.conf` from the backup and runs a
  final `zypper-auto-helper --check` to confirm the restored config is healthy.

The integration script writes a concise, timestamped console log and is safe to
run repeatedly on development systems.

-----

## 📊 Logging & Monitoring (v47)

Version 47 introduces comprehensive logging to help you understand what's happening without needing to run commands.

### Log Locations

#### System Logs (Root Services)
**Location:** `/var/log/zypper-auto/`

| File | Purpose | What It Contains |
|------|---------|------------------|
| `install-YYYYMMDD-HHMMSS.log` | Installation logs | Complete log of each installation run with timestamps, all commands executed, and their results |
| `last-status.txt` | Current status | The most recent status message (e.g., "SUCCESS: Installation completed") |
| `service-logs/downloader.log` | Downloader output | Output from the background download service (`zypper refresh` and `zypper dup --download-only`) |
| `service-logs/downloader-error.log` | Downloader errors | Error output from the downloader service |

#### User Logs (Notifier Service)
**Location:** `~/.local/share/zypper-notify/`

| File | Purpose | What It Contains |
|------|---------|------------------|
| `notifier-detailed.log` | Complete notifier activity | All notifier operations: environment checks, safety decisions, update checks, errors with full tracebacks |
| `notifier-detailed.log.old` | Previous log backup | Previous log file (created when main log exceeds 5MB) |
| `last-run-status.txt` | Last run status | Status of the most recent notifier run (e.g., "Updates available: Snapshot 20251110-0 Ready") |
| `notifier.log` | Systemd stdout | Standard output captured by systemd |
| `notifier-error.log` | Systemd stderr | Standard error captured by systemd |

### What Gets Logged

#### Installation Phase
- ✅ Sanity checks (root privileges, user detection)
- ✅ Dependency verification and installation
- ✅ Old service cleanup
- ✅ Service/timer creation
- ✅ File permissions and ownership
- ✅ Syntax validation
- ✅ Final status summary

#### Runtime (Notifier Service)
- ✅ **Environment Detection:** Form factor (laptop/desktop), battery status, AC power state
- ✅ **Safety Checks:** Why updates are allowed or skipped (battery, metered connection, etc.)
- ✅ **Update Checks:** When zypper runs, what it finds, how many packages
- ✅ **Notifications:** What notifications are shown to the user
- ✅ **User Actions:** When the Install button is clicked
- ✅ **Errors:** Full error messages with Python tracebacks for debugging

### How to Access Logs

#### View Current Status (No Commands Needed)
```bash
# System/installation status
cat /var/log/zypper-auto/last-status.txt

# Notifier status (what's happening with update checks)
cat ~/.local/share/zypper-notify/last-run-status.txt
```

#### View Full Installation Log
```bash
# View the most recent installation
ls -lt /var/log/zypper-auto/install-*.log | head -1 | awk '{print $NF}' | xargs cat

# Or specify a date
cat /var/log/zypper-auto/install-20251119-183000.log
```

#### View Downloader Service Logs
```bash
# See what the background downloader is doing
sudo cat /var/log/zypper-auto/service-logs/downloader.log

# Check for download errors
sudo cat /var/log/zypper-auto/service-logs/downloader-error.log

# Or use journalctl for systemd-managed logs
journalctl -u zypper-autodownload.service
```

#### View Notifier Logs
```bash
# View detailed notifier activity log
cat ~/.local/share/zypper-notify/notifier-detailed.log

# View just recent entries (last 50 lines)
tail -50 ~/.local/share/zypper-notify/notifier-detailed.log

# Watch the log in real-time
tail -f ~/.local/share/zypper-notify/notifier-detailed.log

# View systemd service logs
journalctl --user -u zypper-notify-user.service

# View just the last run
journalctl --user -u zypper-notify-user.service -n 50 --no-pager
```

#### Search Logs for Specific Issues
```bash
# Find all errors in notifier log
grep "\[ERROR\]" ~/.local/share/zypper-notify/notifier-detailed.log

# Check why updates were skipped
grep "SKIPPED" ~/.local/share/zypper-notify/notifier-detailed.log

# See environment detection history
grep "Form factor detected" ~/.local/share/zypper-notify/notifier-detailed.log

# Find when updates were available
grep "packages to upgrade" ~/.local/share/zypper-notify/notifier-detailed.log
```

### Log Rotation & Cleanup

**Automatic cleanup happens on every installation:**
- Installation logs: Keep only the **last 10** log files
- Service logs: Rotate when exceeding **50MB**
- Notifier logs: Rotate when exceeding **5MB**

No manual maintenance required!

### Understanding Log Entries

Each log entry has a timestamp and severity level:

```
[2025-11-19 18:30:45] [INFO] Starting update check...
[2025-11-19 18:30:46] [DEBUG] Checking AC power status (form_factor: laptop)
[2025-11-19 18:30:46] [INFO] AC power detected: plugged in
[2025-11-19 18:30:47] [INFO] Environment is safe for updates
[2025-11-19 18:30:50] [INFO] Found 12 packages to upgrade (snapshot: 20251119)
[2025-11-19 18:30:51] [ERROR] Failed to show notification: [error details]
```

**Severity Levels:**
- `INFO` - Normal operation, status updates
- `DEBUG` - Detailed information for troubleshooting (only visible with `ZNH_DEBUG=1`)
- `ERROR` - Something went wrong, includes details
- `SUCCESS` - Operation completed successfully (installation logs only)

-----

## 📚 Additional Resources

### Reporting Issues on GitHub

**If you encounter a problem, please include these logs in your GitHub issue:**

#### For Installation Problems:
```bash
# 1. Most recent installation log (REQUIRED)
cat $(ls -t /var/log/zypper-auto/install-*.log | head -1)

# 2. Installation status (REQUIRED)
cat /var/log/zypper-auto/last-status.txt
```

#### For Notification/Update Check Problems:
```bash
# 1. Detailed notifier log (REQUIRED)
cat ~/.local/share/zypper-notify/notifier-detailed.log

# 2. Last run status (REQUIRED)
cat ~/.local/share/zypper-notify/last-run-status.txt

# 3. Systemd service status (HELPFUL)
systemctl --user status zypper-notify-user.service

# 4. Recent systemd logs (HELPFUL)
journalctl --user -u zypper-notify-user.service -n 100 --no-pager
```

#### For Download Problems:
```bash
# 1. Downloader logs (REQUIRED)
sudo cat /var/log/zypper-auto/service-logs/downloader.log
sudo cat /var/log/zypper-auto/service-logs/downloader-error.log

# 2. Service status (HELPFUL)
systemctl status zypper-autodownload.service
```

**Also include:**
- Your openSUSE Tumbleweed version: `cat /etc/os-release`
- Python version: `python3 --version`
- Description of the problem and what you expected to happen

**⚠️ IMPORTANT:** Please **redact any personal information** (usernames, hostnames, network names) before posting logs publicly!

### Troubleshooting Common Issues

**Problem: Updates not being downloaded**
- Check if the downloader timer is active: `systemctl status zypper-autodownload.timer`
- Check the downloader log for errors: `sudo cat /var/log/zypper-auto/service-logs/downloader-error.log`
- Verify conditions are met (AC power, not metered): Check systemd conditions

**Problem: Not receiving notifications**
- Check notifier timer: `systemctl --user status zypper-notify-user.timer`
- Check for errors: `cat ~/.local/share/zypper-notify/notifier-detailed.log | grep ERROR`
- Check last run status: `cat ~/.local/share/zypper-notify/last-run-status.txt`
- Verify PyGObject is installed: `python3 -c "import gi"`

**Problem: Updates skipped on laptop**
- Check if on battery: `cat ~/.local/share/zypper-notify/notifier-detailed.log | grep "AC power"`
- Check for metered connection: `grep "metered" ~/.local/share/zypper-notify/notifier-detailed.log`
- The system is working as designed - updates only run on AC power and unmetered connections

### Version History

- **v61** (2026-01-09): **pipx Integration, Reminder Controls & Smarter Download Completion**
  - 🐍 **NEW: pipx helper and automatic upgrades** – added a dedicated `zypper-auto-helper --pip-package` (alias: `--pipx`) mode that installs `python313-pipx` via zypper (on request), runs `pipx ensurepath`, and can optionally run `pipx upgrade-all` for the target user. This makes pipx the recommended/default way to manage Python command‑line tools like `yt-dlp`, `black`, `ansible`, and `httpie`.
  - 📦 **NEW: Config‑driven pipx post‑update step** – a new `ENABLE_PIPX_UPDATES` flag in `/etc/zypper-auto.conf` controls whether the zypper wrapper (`zypper-with-ps`) and the Ready‑to‑Install helper (`zypper-run-install`) run `pipx upgrade-all` after each `zypper dup`, so your pipx‑managed tools stay in sync with system updates.
  - 🔔 **NEW: Reminder control flags** – added `LOCK_REMINDER_ENABLED`, `NO_UPDATES_REMINDER_REPEAT_ENABLED`, and `UPDATES_READY_REMINDER_REPEAT_ENABLED` so you can choose whether lock notifications, "No updates found" messages, and "Updates ready" popups repeat on every check or only once per state.
  - 🩺 **NEW: Configurable auto‑verification timer & repair notifications** – added `VERIFY_TIMER_INTERVAL_MINUTES` to control how often the root health‑check service runs (using the same minute‑based presets as other timers) and `VERIFY_NOTIFY_USER_ENABLED` to toggle a short desktop notification whenever the periodic auto‑repair fixes at least one issue.
  - 🛠️ **IMPROVED: Auto‑repair robustness** – the verification helper now resets failed states on the core systemd units before attempting repairs, cleans up stale `/run/zypp.pid` locks when the recorded PID is no longer running, and runs `zypper clean --all` when free space on `/` falls below ~1 GiB (with a follow‑up check).
  - 🧠 **IMPROVED: "Downloads Complete" notification logic** – the notifier now re‑runs `pkexec zypper dup --dry-run` when it sees a `complete:` status from the downloader and **suppresses** the "✅ Downloads Complete!" popup if zypper reports "Nothing to do." This prevents misleading completion notifications after you have already installed all updates manually.
  - 🧹 **FIXED: duplicate Soar summary header** – the zypper wrapper no longer prints a second stray "Soar (stable) Update & Sync" header after the pipx section; Soar’s update/sync block now appears exactly once in the post‑update flow.

- **v59** (2026-01-02): **Ready-to-Install Konsole Fix & Install Helper Diagnostics**
  - 🪟 **FIXED: "Install Now" window closing immediately in Konsole** – the Ready-to-Install helper now runs via a dedicated `zypper-run-install --inner` mode inside the spawned terminal instead of relying on exported shell functions, so the Konsole window stays open reliably until you press Enter.
  - 📜 **NEW: `run-install.log` for install helper** – every Ready-to-Install run is logged to `~/.local/share/zypper-notify/run-install.log` with environment, terminal selection, and `pkexec zypper dup` status, making it much easier to debug installer-window issues.
  - 🧭 **IMPROVED: Soar detection in wrappers & helper** – the Soar post-update steps and the install helper now detect Soar from common per-user locations (like `~/.local/bin/soar` and `~/pkgforge`) before offering to install it, avoiding false "Soar is not installed" prompts when it is actually present.
  - 🧪 **IMPROVED: Test harness integration** – the Python test script and notifier paths now exercise the same helper/terminal flow as real updates, so Ready-to-Install behaviour can be reproduced and debugged consistently.

- **v58** (2025-12-31): **Scripted Uninstaller, External Config & Log Control**
  - 📝 **Short:** Safer uninstall, externalised config (including `DUP_EXTRA_FLAGS`), smarter config health warnings, and improved solver-conflict notifications that keep cached downloads and guide you to resolve conflicts.
  - 🗑️ **NEW: Safe scripted uninstaller** – `sudo ./zypper-auto.sh --uninstall-zypper-helper` (or `sudo zypper-auto-helper --uninstall-zypper-helper`) now removes all helper components (root timers/services, helper binaries, user systemd units, helper scripts, aliases, logs and caches) in a single, logged operation with a clear header and summary.
  - ⚙️ **NEW: Advanced uninstall flags** – `--yes` / `-y` / `--non-interactive` skip the confirmation prompt for automated or non-interactive environments; `--dry-run` shows exactly what **would** be removed without making any changes; `--keep-logs` preserves `/var/log/zypper-auto` install/service logs for debugging while still clearing per-user notifier caches.
  - 🧹 **IMPROVED: Clean systemd state on uninstall** – system and user units are stopped, disabled, removed from disk, and their "failed" states cleared via `systemctl reset-failed`/`systemctl --user reset-failed` so `systemctl status` no longer reports stale failures after uninstall.
  - 🧾 **NEW: External configuration file** – `/etc/zypper-auto.conf` now holds documented settings for post-update helpers (Flatpak/Snap/Soar/Brew), log retention, notifier cache/snooze behaviour, timer intervals, and per-installation zypper behaviour, so users can tweak behaviour without editing the script.
  - 🕒 **NEW: Config-driven timer intervals** – `DL_TIMER_INTERVAL_MINUTES` and `NT_TIMER_INTERVAL_MINUTES` (allowed: `1,5,10,15,30,60`) control how often the downloader and notifier run; the installer converts these into appropriate `OnCalendar` expressions.
  - 🧩 **NEW: `DUP_EXTRA_FLAGS` support** – a new `DUP_EXTRA_FLAGS` key in `/etc/zypper-auto.conf` lets you append extra solver flags (such as `--allow-vendor-change` or `--from <repo>`) to every `zypper dup` run by the helper (background downloader and notifier) without modifying the scripts.
  - 🚨 **NEW: Config validation & reset helper** – invalid values in `/etc/zypper-auto.conf` automatically fall back to safe defaults, are logged, surfaced in `last-status.txt`, and trigger a small desktop notification suggesting `zypper-auto-helper --reset-config`. A new `--reset-config` CLI mode resets the config to defaults with a timestamped backup.

- **v57** (2025-12-28): **Soar Stable Updater, Homebrew Integration & Notification UX**
  - 🧭 **NEW: Smarter Soar stable updater** – the helper and wrapper now compare `soar --version` against GitHub’s latest stable release tag (`releases/latest`) and only re-run the official Soar installer when a newer stable version exists, then run `soar sync` and `soar update`.
  - 🍺 **NEW: Homebrew `--brew` helper mode** – `sudo ./zypper-auto.sh --brew` (or `sudo zypper-auto-helper --brew`) now installs Homebrew on Linux for the target user if missing, or, when brew is already installed, runs `brew update` followed by `brew outdated --quiet` and `brew upgrade` only when there are outdated formulae, with clear log messages.
  - 🔗 **NEW: Homebrew wrapper integration** – the `zypper-with-ps` wrapper now treats `dup`, `dist-upgrade` and `update` as full updates and, after Flatpak/Snap/Soar steps, runs `brew update` and conditionally `brew upgrade`, with Soar-style status messages ("Homebrew is already up to date" vs "upgraded N formulae").
  - 🧩 **IMPROVED: Soar & Homebrew UX** – Soar’s GitHub API check no longer emits noisy `curl: (23)` errors and both Soar and Homebrew remain fully optional; if either tool is not installed, the scripts simply log a short hint instead of failing.
  - 📡 **IMPROVED: Downloader/Notifier coordination** – the downloader writes structured status (`refreshing`, `downloading:…`, `complete:…`, `idle`), handles zypper locks gracefully (marking itself idle and letting timers retry), and the notifier shows live progress, a cached-aware "✅ Downloads Complete!" notification, and a separate persistent "Snapshot XXXXXXXX Ready" notification for installation.
  - 🧱 **IMPROVED: Snapper status reporting** – Snapper root configs are detected more reliably; `snapper list` permission errors are treated as "snapshots exist (root-only)" rather than "not configured", and the current Snapper state is always surfaced in the update notification.
  - ⏱️ **IMPROVED: Timer defaults** – both the root downloader and user notifier timers now default to a simple minutely `OnCalendar` schedule for more predictable behaviour, instead of `OnActiveSec`-based intervals that could end up `active (elapsed)` with no next trigger.

- **v55** (2025-12-27): **Soar Integration, Smarter Detection & Timer Fixes**
  - 🔗 **NEW: Soar integration** – every `zypper dup` triggered via the helper or the shell wrapper now runs Flatpak updates, Snap refresh, and an optional `soar sync` step so app runtimes and Soar-managed apps stay in sync with system updates.
  - 🧩 **NEW: Optional Soar guidance & install helper** – if Soar is not installed for the user, the installer logs and (optionally) notifies with the exact install command (`curl -fsSL "https://raw.githubusercontent.com/pkgforge/soar/main/install.sh" | sh`), suggests `soar sync`, and shows a rich desktop notification with an **"Install Soar"** button that opens a terminal and runs the installer for you.
  - 🧭 **NEW: Smarter optional-tool detection & stable Soar updater** – Flatpak, Snap, and Soar are now detected using the user's PATH and common per-user locations (like `~/.local/bin` and `~/pkgforge`) to avoid false "missing" warnings; if Soar is already present, the install helper notification is suppressed. When Soar *is* installed, the wrapper/GUI helper now compares `soar --version` against GitHub’s latest stable release tag (`releases/latest`) and only re-runs the Soar installer when a newer stable version exists, then runs `soar sync`.
  - 📸 **IMPROVED: Snapper detection** – `snapper list-configs` is inspected so the default `root` config on Tumbleweed is recognised, and `snapper list` permission errors ("No permissions.") are treated as "snapper configured (root) but snapshots require root permissions to view" rather than "not configured".
  - ⏱️ **IMPROVED: Notifier timer behaviour** – the user timer now uses `OnActiveSec` plus an automatic restart after install so it no longer gets stuck in an `active (elapsed)` state with no future trigger.
- **v54** (2025-12-25): **Robust Conflict Handling & Helper Integration**
  - 🧠 **NEW: Smarter zypper error handling** that distinguishes PolicyKit/authentication failures, zypper locks, and normal solver/interaction errors.
  - 🧩 **NEW: "Updates require manual decision" notification** when `zypper dup --dry-run` needs interactive choices (e.g. vendor conflicts), including the first `Problem:` line from zypper output.
  - 🖱️ **NEW: "Open Helper" action button** on manual-intervention notifications that launches `zypper-run-install` in a terminal so you can resolve issues immediately.
  - 🔁 **FIXED: Stale downloader status handling** – old `refreshing` / `downloading:` states in `/var/log/zypper-auto/download-status.txt` are ignored after 5 minutes so the notifier always runs a fresh check.
- **v53** (2025-12-25): **Snooze Controls & Environment-Aware Safety Preflight**
  - ✨ **NEW: Snooze buttons (1h / 4h / 1d)** in the notification with persistent state under `~/.cache/zypper-notify`, so you can temporarily pause reminders.
  - 🔔 **NEW: Environment change notifications** when AC/battery or metered status changes, explaining why downloads are paused or allowed.
  - 🛡️ **NEW: Safety preflight checks** for disk space, Btrfs snapshots (snapper), and basic network quality, with warnings appended to the update notification instead of failing silently.
  - 👀 **NEW: "View Changes" helper** launched from the notification to show `zypper dup --dry-run --details` in a terminal.
  - ℹ️ **NEW: Optional Flatpak/Snap detection** after install with a desktop notification describing how to enable them for app updates.
- **v51** (2025-12-23): **Major Update - Command-Line Interface & Advanced Diagnostics**
  - ✨ **NEW: `zypper-auto-helper` command** - Installed to `/usr/local/bin` with automatic shell aliases
  - 🔧 **NEW: Advanced Verification System** - 12-point health check with multi-stage auto-repair
  - 🚀 **NEW: Real-Time Progress** - Download notifications update every 5 seconds with progress bar
  - 🎯 **NEW: Smart Cache Detection** - Doesn't notify about downloads if packages already cached
  - 🔄 **NEW: Manual Update Wrapper** - `sudo zypper dup` automatically runs post-update checks
  - 🚫 **NEW: Duplicate Prevention** - Synchronous notification IDs prevent popup spam
  - ⚡ **IMPROVED: High-Priority Downloads** - nice -20 and ionice realtime for faster downloads
  - 🛠️ **IMPROVED: Installation** - Fully automatic, no manual user service enabling required
  - 📊 **IMPROVED: Status Tracking** - Better progress reporting with percentage and package count
- **v50** (2025-11-20): Added stage-based download notifications with package count display
- **v49** (2025-11-20): Smart download detection - only notifies when updates are actually being downloaded
- **v48** (2025-11-20): Fixed battery detection logic (laptops no longer misidentified as desktops) and notification persistence (popups no longer disappear instantly)
- **v47** (2025-11-19): Added comprehensive logging system with automatic rotation
- **v46**: AC battery detection logical fix
- **v45**: Architecture improvements and user-space notifier
- **v43**: Enhanced Python notification script
- **v42**: PolicyKit/PAM error logging enhancements
- Earlier versions: Initial development and refinements

-----

## 🗑️ Uninstallation

### Recommended: Scripted Uninstaller (v58+)

Use the built-in uninstaller to safely remove all helper components:

```bash
# Run from the directory containing zypper-auto.sh (as root)
sudo ./zypper-auto.sh --uninstall-zypper-helper

# Or using the installed helper command (typically without sudo via shell alias)
zypper-auto-helper --uninstall-zypper-helper
# Shorthand alias:
zypper-auto-helper --uninstall-zypper
```

By default this will:
- Stop and disable the root timers/services (`zypper-autodownload`, `zypper-cache-cleanup`, `zypper-auto-verify`)
- Stop and disable the user notifier timer/service for your user
- Remove all helper systemd unit files and helper binaries
- Remove user helper scripts, shell aliases, and Fish config snippets
- Clear notifier caches and (by default) old helper logs under `/var/log/zypper-auto`
- Reload both system and user systemd daemons and clear any "failed" states

#### Advanced Uninstall Flags

You can customise the behaviour with optional flags:

```bash
# Skip the confirmation prompt (non-interactive)
sudo ./zypper-auto.sh --uninstall-zypper-helper --yes
# or
sudo ./zypper-auto.sh --uninstall-zypper-helper --non-interactive

# Show what WOULD be removed, but make no changes
sudo ./zypper-auto.sh --uninstall-zypper-helper --dry-run

# Keep logs under /var/log/zypper-auto for debugging
sudo ./zypper-auto.sh --uninstall-zypper-helper --yes --keep-logs

# Flags can be combined as needed
sudo ./zypper-auto.sh --uninstall-zypper-helper --dry-run --keep-logs
```

### Manual Uninstall (Advanced / Legacy)

If you prefer or need to remove components manually, the equivalent steps are:

```bash
# 1. Stop and disable the root timers
sudo systemctl disable --now zypper-autodownload.timer
sudo systemctl disable --now zypper-cache-cleanup.timer
sudo systemctl disable --now zypper-auto-verify.timer

# 2. Stop and disable the user timer (run as regular user)
systemctl --user disable --now zypper-notify-user.timer

# 3. Remove all systemd files and scripts
sudo rm /etc/systemd/system/zypper-autodownload.service
sudo rm /etc/systemd/system/zypper-autodownload.timer
sudo rm /etc/systemd/system/zypper-cache-cleanup.service
sudo rm /etc/systemd/system/zypper-cache-cleanup.timer
sudo rm /etc/systemd/system/zypper-auto-verify.service
sudo rm /etc/systemd/system/zypper-auto-verify.timer
sudo rm /usr/local/bin/zypper-download-with-progress
sudo rm /usr/local/bin/zypper-auto-helper

# Replace $HOME with your actual home directory (or run as regular user)
rm -f $HOME/.config/systemd/user/zypper-notify-user.service
rm -f $HOME/.config/systemd/user/zypper-notify-user.timer
rm -f $HOME/.local/bin/zypper-notify-updater.py
rm -f $HOME/.local/bin/zypper-run-install
rm -f $HOME/.local/bin/zypper-with-ps
rm -f $HOME/.local/bin/zypper-view-changes
rm -f $HOME/.config/fish/conf.d/zypper-wrapper.fish
rm -f $HOME/.config/fish/conf.d/zypper-auto-helper-alias.fish

# Remove shell aliases from config files
sed -i '/# Zypper wrapper for auto service check/d' $HOME/.bashrc $HOME/.zshrc 2>/dev/null
sed -i '/alias zypper=/d' $HOME/.bashrc $HOME/.zshrc 2>/dev/null
sed -i '/# zypper-auto-helper command alias/d' $HOME/.bashrc $HOME/.zshrc 2>/dev/null
sed -i '/alias zypper-auto-helper=/d' $HOME/.bashrc $HOME/.zshrc 2>/dev/null

# 4. (Optional) Remove logs
sudo rm -rf /var/log/zypper-auto
rm -rf $HOME/.local/share/zypper-notify
rm -rf $HOME/.cache/zypper-notify

# 5. Reload the systemd daemons
sudo systemctl daemon-reload
systemctl --user daemon-reload
```
