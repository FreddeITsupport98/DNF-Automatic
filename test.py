#!/usr/bin/env python3
#
# test-notification.py
#
# This script sends a fake "Updates Ready" notification
# using the Python (gi) library and logs its actions
# to 'test.log' in the *same folder as this script*.
#
# Run it directly from your terminal as your user.

import sys
import subprocess
import os
import logging
import traceback
import time

# --- Setup Logging (v2 - Log to script directory) ---
try:
    # Get the directory where this script is located (normally the repo root)
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
    # Create the log file in that same directory, named test.log so other
    # developers can easily grab it from the repository folder.
    LOG_FILE = os.path.join(SCRIPT_DIR, "test.log")

    logging.basicConfig(
        filename=LOG_FILE,
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        filemode='a'  # Append new runs to a shared test.log
    )
except Exception as e:
    print(f"Error setting up logging: {e}")
    sys.exit(1)
# ---------------------

# This test MUST run as the normal desktop user so it can talk to the
# user's notification daemon over their DBus session. When run under
# sudo/root, it will often hang or fail to show any notifications
# because it is not attached to the correct session bus.
if os.geteuid() == 0:
    msg = "Do not run test.py with sudo. Run it as your normal user in the desktop session."
    print(msg)
    logging.error("Refusing to run as root: %s", msg)
    sys.exit(1)

try:
    import gi
    gi.require_version("Notify", "0.7")
    from gi.repository import Notify, GLib
    logging.info("PyGObject (gi) imported successfully.")
except ImportError:
    error_msg = "Error: PyGObject (gi) not found. This is a problem."
    logging.error(error_msg)
    logging.error("Please install 'python3-gobject' and try again.")
    print(error_msg) # Also print to terminal
    sys.exit(1)

def _launch_fake_lock_retry_terminal() -> None:
    """Open a konsole window that *simulates* the DNF lock-retry loop.

    This does not touch the real /run/dnf.pid lock file or run dnf.
    Instead, it reads the same LOCK_RETRY_* config from /etc/dnf-auto.conf
    and prints the "Retry 1/10..." style messages so we can visually check
    the UX of the prebuilt lock retry behaviour.
    """

    bash_script = r"""
CONFIG_FILE="/etc/dnf-auto.conf"
# Default values (will be overridden by the config if present)
LOCK_RETRY_MAX_ATTEMPTS=${LOCK_RETRY_MAX_ATTEMPTS:-10}
LOCK_RETRY_INITIAL_DELAY_SECONDS=${LOCK_RETRY_INITIAL_DELAY_SECONDS:-1}

if [ -r "$CONFIG_FILE" ]; then
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
fi

max_attempts=${LOCK_RETRY_MAX_ATTEMPTS:-10}
base_delay=${LOCK_RETRY_INITIAL_DELAY_SECONDS:-1}

echo ""
echo "=========================================="
echo "  Running System Update (LOCK TEST)"
echo "=========================================="
echo ""

attempt=1
while [ "$attempt" -le "$max_attempts" ]; do
    delay=$((base_delay * attempt))
    echo ""
    echo "System management is currently locked by another update tool (dnf/PackageKit)."
    echo "Retry $attempt/$max_attempts: waiting $delay second(s) for the other updater to finish..."
    sleep "$delay"
    attempt=$((attempt + 1))
done

echo ""
echo "System management is still locked by another update tool."
echo "Close that other update tool (or wait for it to finish), then run"
echo "this 'Ready to Install' action again."
echo ""
echo "Press Enter to close this window..."
read || sleep 5
"""

    try:
        logging.info("lock-test: launching konsole with fake lock-retry script")
        subprocess.Popen(
            ["konsole", "-e", "bash", "-lc", bash_script]
        )
    except Exception:
        logging.error("lock-test: failed to launch konsole for fake lock retry")
        logging.error(traceback.format_exc())


def on_action(notification, action_id, user_data_script):
    """Callback to run when a notification action button is clicked.

    Logs detailed diagnostic information about the chosen action,
    the resolved script path, and any launcher process that is started.
    """
    logging.info("on_action: action_id=%r raw_user_data_script=%r", action_id, user_data_script)

    # Special test action: open a konsole window that *simulates the
    # DNF lock retry loop using the same timing config.
    if action_id == "retry-lock-test":
        _launch_fake_lock_retry_terminal()
        try:
            notification.close()
        except Exception:
            logging.error("on_action: failed to close notification after lock test")
            logging.error(traceback.format_exc())
        GLib.MainLoop().quit()
        return

    try:
        # We try to find the install script, but fall back to a generic one
        # for this test.
        if not os.path.exists(user_data_script):
            resolved = os.path.expanduser("~/.local/bin/dnf-run-install")
            logging.info("on_action: primary script missing, falling back to %r", resolved)
            user_data_script = resolved

        if not os.path.exists(user_data_script):
            logging.warning(
                "on_action: action=%r, no runnable script at %r. Did you run the installer?",
                action_id,
                user_data_script,
            )
            # Fallback: just open a terminal to give the user some context
            logging.info("on_action: falling back to launching 'konsole'")
            try:
                proc = subprocess.Popen(["konsole"])  # type: ignore[arg-type]
                logging.info("on_action: launched konsole, pid=%s", getattr(proc, "pid", "unknown"))
            except Exception:
                logging.error("on_action: failed to launch konsole")
                logging.error(traceback.format_exc())
        else:
            is_exec = os.access(user_data_script, os.X_OK)
            logging.info(
                "on_action: executing script=%r exists=%s executable=%s",
                user_data_script,
                True,
                is_exec,
            )
            try:
                proc = subprocess.Popen([user_data_script])  # type: ignore[arg-type]
                logging.info(
                    "on_action: launched helper script pid=%s cmd=%r",
                    getattr(proc, "pid", "unknown"),
                    [user_data_script],
                )
            except Exception:
                logging.error("on_action: failed to spawn helper script %r", user_data_script)
                logging.error(traceback.format_exc())

    except Exception as e:
        logging.error("on_action: unexpected failure: %s", e)
        logging.error(traceback.format_exc())

    try:
        notification.close()
    except Exception:
        logging.error("on_action: failed to close notification")
        logging.error(traceback.format_exc())
    # The real notifier uses a GLib main loop; simulate a clean exit here.
    GLib.MainLoop().quit()

def _show_checking_stage():
    """Simulate the "refreshing" stage (checking for updates)."""
    title = "Checking for updates... (Test)"
    body = "Refreshing repositories..."
    icon = "emblem-synchronizing"
    logging.info(
        "CHECKING: title=%r body=%r icon=%r timeout_ms=%d", title, body, icon, 2000
    )
    n = Notify.Notification.new(title, body, icon)
    # Use same synchronous ID as real downloader so notifications replace each other
    n.set_timeout(2000)
    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "dnf-download-status"))
    n.show()
    time.sleep(2)


def _show_downloading_stage():
    """Simulate the "downloading" stage with a progress bar."""
    total_pkgs = 10
    download_size = "120 MiB"
    logging.info(
        "DOWNLOADING: total_pkgs=%d download_size=%r bar_len=%d step_delay=%.2fs",
        total_pkgs,
        download_size,
        20,
        0.7,
    )

    for downloaded in range(0, total_pkgs + 1):
        percent = int(downloaded * 100 / total_pkgs)
        bar_len = 20
        filled = int(bar_len * percent / 100)
        bar = "█" * filled + "░" * (bar_len - filled)
        progress_text = f"[{bar}] {percent}%"

        msg_lines = [
            f"Downloading {downloaded} of {total_pkgs} packages",
            progress_text,
            f"{download_size} total • HIGH priority",
        ]
        msg = "\n".join(msg_lines)

        n = Notify.Notification.new(
            "Downloading updates... (Test)",
            msg,
            "emblem-downloads",
        )
        # Progress hint + category like the real notifier
        n.set_hint("value", GLib.Variant("i", percent))
        n.set_category("transfer.progress")
        n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "dnf-download-status"))
        n.set_timeout(1200)
        n.show()
        time.sleep(0.7)


def _show_complete_stage():
    """Simulate the "downloads complete" summary notification."""
    msg = (
        "Downloaded 10 packages in 1m 23s.\n\n"
        "Including: kernel, dnf, glibc, and more.\n\n"
        "Ready to install."
    )
    logging.info(
        "COMPLETE: title=%r body_preview=%r icon=%r timeout_ms=%d",
        "✅ Downloads Complete! (Test)",
        msg.replace("\n", " ")[:160],
        "emblem-default",
        4000,
    )
    n = Notify.Notification.new(
        "✅ Downloads Complete! (Test)",
        msg,
        "emblem-default",
    )
    n.set_timeout(4000)
    n.set_urgency(Notify.Urgency.NORMAL)
    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "dnf-download-complete"))
    n.show()
    time.sleep(4)


def _show_updates_ready_stage():
    """Final persistent "Updates Ready" notification with buttons, like real flow."""
    title = "Updates Ready (Test)"
    message = (
        "10 updates are pending. Click 'Install' to begin.\n\n"
        "Including: kernel, dnf, glibc, and more."
    )

    action_script = os.path.expanduser("~/.local/bin/dnf-run-install")
    logging.info(
        "UPDATES_READY: title=%r body_preview=%r icon=%r script=%r",
        title,
        message.replace("\n", " ")[:160],
        "system-software-update",
        action_script,
    )

    n = Notify.Notification.new(title, message, "system-software-update")
    # Persistent: keep until user interacts
    n.set_timeout(0)
    n.set_urgency(Notify.Urgency.CRITICAL)
    n.set_hint("desktop-entry", GLib.Variant("s", "dnf-updater"))
    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "dnf-updates"))

    # Buttons similar to real notifier
    n.add_action("install", "Install Now", on_action, action_script)
    n.add_action("view-changes", "View Changes", on_action, None)
    n.add_action("snooze-1h", "1h", on_action, None)
    n.add_action("snooze-4h", "4h", on_action, None)
    n.add_action("snooze-1d", "1d", on_action, None)

    # Main loop so the notification stays until user acts
    loop = GLib.MainLoop()
    n.connect("closed", lambda *args: loop.quit())

    n.show()
    logging.info("Updates Ready notification sent. Waiting for user interaction...")
    loop.run()
    logging.info("Updates Ready stage finished (user interacted or closed notification)")


def _show_solver_error_notification():
    """Simulate the solver/conflict error notification from the real helper."""
    title = "Updates require your decision (Test)"
    message = (
        "Background download of updates hit a DNF solver error.\n\n"
        "Some packages may already be cached, but DNF needs your decision to continue.\n\n"
        "Open a terminal and run:\n"
        "  sudo dnf upgrade\n"
        "or click 'Install Now' to open the helper, then follow DNF's prompts to resolve the conflicts."
    )

    action_script = os.path.expanduser("~/.local/bin/dnf-run-install")
    logging.info(
        "SOLVER_ERROR: title=%r body_preview=%r icon=%r script=%r",
        title,
        message.replace("\n", " ")[:200],
        "system-software-update",
        action_script,
    )

    n = Notify.Notification.new(
        title,
        message,
        "system-software-update",
    )
    n.set_timeout(0)
    n.set_urgency(Notify.Urgency.CRITICAL)
    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "dnf-updates-conflict"))

    n.add_action("install", "Install Now", on_action, action_script)
    n.add_action("view-changes", "View Changes", on_action, None)
    n.add_action("snooze-1h", "1h", on_action, None)
    n.add_action("snooze-4h", "4h", on_action, None)
    n.add_action("snooze-1d", "1d", on_action, None)

    loop = GLib.MainLoop()
    n.connect("closed", lambda *args: loop.quit())

    n.show()
    logging.info("Solver-error notification sent. Waiting for user interaction...")
    loop.run()
    logging.info("Solver-error test notification finished")


def _show_policykit_error_notification():
    """Simulate the PolicyKit/auth failure notification used by the helper."""

    title = "Update check failed (Test)"
    message = (
        "The updater could not authenticate with PolicyKit.\n"
        "This may be a configuration issue.\n\n"
        "Try running 'pkexec dnf upgrade --assumeno' manually to test."
    )

    logging.info(
        "POLKIT_ERROR: title=%r body_preview=%r icon=%r timeout_ms=%d",
        title,
        message.replace("\n", " ")[:160],
        "dialog-error",
        30000,
    )

    n = Notify.Notification.new(title, message, "dialog-error")
    n.set_timeout(30000)  # 30 seconds
    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "dnf-error"))
    n.set_urgency(Notify.Urgency.CRITICAL)
    n.show()

    logging.info("PolicyKit-error notification sent (30s timeout)")
    time.sleep(3)


def _show_config_warning_notification():
    """Simulate the config-warning notification from dnf-auto-helper."""

    title = "DNF Auto-Helper config warnings (Test)"
    message = (
        "Some settings in /etc/dnf-auto.conf were invalid and reset to safe defaults.\n\n"
        "Check the install log or run: dnf-auto-helper --reset-config"
    )

    logging.info(
        "CONFIG_WARNING: title=%r body_preview=%r icon=%r timeout_ms=%d",
        title,
        message.replace("\n", " ")[:160],
        "dialog-warning",
        20000,
    )

    n = Notify.Notification.new(title, message, "dialog-warning")
    n.set_timeout(20000)
    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "dnf-config-warning"))
    n.set_urgency(Notify.Urgency.NORMAL)
    n.show()

    logging.info("Config-warning notification sent (20s timeout)")
    time.sleep(2)


def _show_lock_retry_notification():
    """Simulate a DNF lock notification with a Retry action.

    This models the UX where system management is locked by another
    updater (dnf, PackageKit, etc.) and the user is invited
    to close the other tool and click "Retry" to launch the helper
    again.
    """

    title = "System management is locked (Test)"
    message = (
        "Another update tool is currently using DNF.\n\n"
        "Close the other updater (or wait for it to finish), then click "
        "'Retry' to open the Ready-to-Install helper again."
    )

    action_script = os.path.expanduser("~/.local/bin/dnf-run-install")
    logging.info(
        "LOCK_RETRY: title=%r body_preview=%r icon=%r script=%r",
        title,
        message.replace("\n", " ")[:200],
        "dialog-warning",
        action_script,
    )

    n = Notify.Notification.new(title, message, "dialog-warning")
    n.set_timeout(0)
    n.set_urgency(Notify.Urgency.NORMAL)
    n.set_hint("x-canonical-private-synchronous", GLib.Variant("s", "dnf-lock"))

    # Primary action: Retry (Test Only) – this simulates a lock by
    # opening a konsole window that prints the same retry messages
    # the real helper uses, without needing a real DNF lock.
    n.add_action("retry-lock-test", "Retry (Test Only)", on_action, None)
    # Secondary action: just close/dismiss the notification.
    n.add_action("dismiss", "Dismiss", on_action, None)

    loop = GLib.MainLoop()
    n.connect("closed", lambda *args: loop.quit())

    n.show()
    logging.info("Lock-retry notification sent. Waiting for user interaction...")
    loop.run()
    logging.info("Lock-retry test notification finished")


def main():
    run_id = time.strftime("%Y%m%d-%H%M%S")
    logging.info("================ RUN %s START ================", run_id)
    logging.info("Python version: %s", sys.version.replace("\n", " "))
    logging.info("ENV DISPLAY=%s WAYLAND_DISPLAY=%s XDG_SESSION_TYPE=%s", os.environ.get("DISPLAY"), os.environ.get("WAYLAND_DISPLAY"), os.environ.get("XDG_SESSION_TYPE"))
    logging.info("User: %s, HOME=%s, PWD=%s", os.environ.get("USER"), os.environ.get("HOME"), os.getcwd())
    print(f"Sending staged test notifications... Log file at: {LOG_FILE}")
    try:
        Notify.init("dnf-updater-test")

        # Simulate the main happy-path stages the real system uses
        _show_checking_stage()
        _show_downloading_stage()
        _show_complete_stage()
        _show_updates_ready_stage()

        # Simulate the main error / edge-case notifications used by the
        # real notifier and installer so we can visually verify them.
        _show_solver_error_notification()
        _show_policykit_error_notification()
        _show_config_warning_notification()
        _show_lock_retry_notification()

        logging.info("Test finished.")
        print("Test finished.")

    except Exception as e:
        logging.error(f"An error occurred in main: {e}")
        logging.error(traceback.format_exc())
    finally:
        Notify.uninit()
        logging.info("================ RUN %s END ==================", run_id)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Graceful handling when the user presses Ctrl+C so we do not
        # dump a noisy traceback from deep inside gi/Notify.
        logging.info("Test interrupted by user (KeyboardInterrupt)")
        try:
            Notify.uninit()
        except Exception:
            pass
        sys.exit(1)
