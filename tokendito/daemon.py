# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Daemon management for tokendito auto-renewal on macOS."""

import logging
import os
import plistlib
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def get_launchd_plist_path():
    """Get the path to the launchd plist file.

    :return: Path to plist file
    """
    home = Path.home()
    launchd_dir = home / "Library" / "LaunchAgents"
    return launchd_dir / "com.tokendito.renewal.plist"


def get_log_dir():
    """Get the directory for daemon logs.

    :return: Path to log directory
    """
    home = Path.home()
    log_dir = home / "Library" / "Logs" / "tokendito"
    return log_dir


def create_launchd_plist(config_file=None):
    """Create launchd plist file for auto-renewal daemon.

    :param config_file: Path to tokendito config file
    :return: True if successful, False otherwise
    """
    if sys.platform != "darwin":
        logger.error("Launchd is only available on macOS")
        return False

    plist_path = get_launchd_plist_path()
    log_dir = get_log_dir()

    # Ensure directories exist
    plist_path.parent.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    # Find the tokendito-renew-daemon entry point
    # Using shutil.which to locate it in PATH
    import shutil  # noqa: C0415
    daemon_cmd = shutil.which("tokendito-renew-daemon")

    if not daemon_cmd:
        # Fallback to python -m if entry point not found
        logger.warning("tokendito-renew-daemon not found in PATH, using python -m fallback")
        daemon_cmd = sys.executable
        program_args = [daemon_cmd, "-m", "tokendito.renewal"]
    else:
        # Use the entry point directly (shows better name in macOS)
        program_args = [daemon_cmd]
    if config_file:
        program_args.extend(["--config-file", config_file])

    # Get user's PATH to ensure tokendito command can be found
    user_path = os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")

    # Create plist structure
    plist_data = {
        "Label": "com.tokendito.renewal",
        "ProgramArguments": program_args,
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": str(log_dir / "renewal.log"),
        "StandardErrorPath": str(log_dir / "renewal.error.log"),
        "StartInterval": 600,  # Run every 10 minutes as fallback
        "EnvironmentVariables": {
            "PATH": user_path,  # Include user's PATH so tokendito command can be found
        },
    }

    try:
        with open(plist_path, "wb") as f:
            plistlib.dump(plist_data, f)

        logger.info(f"Created launchd plist at {plist_path}")
        return True

    except (OSError, ValueError) as err:
        logger.error(f"Error creating launchd plist: {err}")
        return False


def load_launchd_service():
    """Load the tokendito renewal service with launchd.

    :return: True if successful, False otherwise
    """
    if sys.platform != "darwin":
        logger.error("Launchd is only available on macOS")
        return False

    plist_path = get_launchd_plist_path()

    if not plist_path.exists():
        logger.error(f"Plist file not found at {plist_path}")
        return False

    try:
        # Unload first if already loaded (ignore errors)
        subprocess.run(
            ["launchctl", "unload", str(plist_path)],
            capture_output=True,
            check=False
        )

        # Load the service
        result = subprocess.run(
            ["launchctl", "load", str(plist_path)],
            capture_output=True,
            text=True,
            check=True
        )

        logger.info("Successfully loaded tokendito renewal service")
        return True

    except subprocess.CalledProcessError as err:
        logger.error(f"Error loading launchd service: {err.stderr}")
        return False
    except Exception as err:
        logger.error(f"Unexpected error loading service: {err}")
        return False


def unload_launchd_service():
    """Unload the tokendito renewal service from launchd.

    :return: True if successful, False otherwise
    """
    if sys.platform != "darwin":
        logger.error("Launchd is only available on macOS")
        return False

    plist_path = get_launchd_plist_path()

    if not plist_path.exists():
        logger.debug(f"Plist file not found at {plist_path}, nothing to unload")
        return True

    try:
        result = subprocess.run(
            ["launchctl", "unload", str(plist_path)],
            capture_output=True,
            text=True,
            check=True
        )

        logger.info("Successfully unloaded tokendito renewal service")
        return True

    except subprocess.CalledProcessError as err:
        # Service might not be loaded, which is fine
        if "Could not find specified service" in err.stderr:
            logger.debug("Service was not loaded")
            return True
        logger.error(f"Error unloading launchd service: {err.stderr}")
        return False
    except Exception as err:
        logger.error(f"Unexpected error unloading service: {err}")
        return False


def get_service_status():
    """Check if the tokendito renewal service is running.

    :return: dict with status information
    """
    status = {
        "running": False,
        "loaded": False,
        "plist_exists": False,
        "platform_supported": sys.platform == "darwin",
    }

    if not status["platform_supported"]:
        return status

    plist_path = get_launchd_plist_path()
    status["plist_exists"] = plist_path.exists()

    if not status["plist_exists"]:
        return status

    try:
        # Check if service is loaded
        result = subprocess.run(
            ["launchctl", "list"],
            capture_output=True,
            text=True,
            check=True
        )

        if "com.tokendito.renewal" in result.stdout:
            status["loaded"] = True

            # Try to get more detailed status
            detail_result = subprocess.run(
                ["launchctl", "list", "com.tokendito.renewal"],
                capture_output=True,
                text=True,
                check=False
            )

            if detail_result.returncode == 0:
                # Parse output to check if it's running
                # Output format: {"Label": "...", "PID": ..., "LastExitStatus": ...}
                if '"PID"' in detail_result.stdout or 'PID =' in detail_result.stdout:
                    status["running"] = True

    except Exception as err:
        logger.debug(f"Error checking service status: {err}")

    return status


def enable_auto_renewal(profiles, config_file=None):
    """Enable auto-renewal for specified profiles.

    :param profiles: List of profile names to monitor
    :param config_file: Path to tokendito config file
    :return: True if successful, False otherwise
    """
    from tokendito.renewal import get_auto_renew_config, save_auto_renew_config

    # Get current settings
    settings = get_auto_renew_config(config_file)

    # Update settings
    settings["enabled"] = True
    settings["profiles"] = list(set(settings.get("profiles", []) + profiles))

    # Save configuration
    if not save_auto_renew_config(settings, config_file):
        logger.error("Failed to save auto-renewal configuration")
        return False

    # On macOS, set up launchd service
    if sys.platform == "darwin":
        if not create_launchd_plist(config_file):
            logger.error("Failed to create launchd plist")
            return False

        if not load_launchd_service():
            logger.error("Failed to load launchd service")
            return False

        logger.info("Auto-renewal enabled and service started")
    else:
        logger.warning(
            "Automatic daemon management is only supported on macOS. "
            "You can manually run 'tokendito-renew-daemon' to start the renewal service."
        )

    return True


def disable_auto_renewal(config_file=None):
    """Disable auto-renewal.

    :param config_file: Path to tokendito config file
    :return: True if successful, False otherwise
    """
    from tokendito.renewal import get_auto_renew_config, save_auto_renew_config

    # Get current settings
    settings = get_auto_renew_config(config_file)

    # Update settings
    settings["enabled"] = False

    # Save configuration
    if not save_auto_renew_config(settings, config_file):
        logger.error("Failed to save auto-renewal configuration")
        return False

    # On macOS, stop launchd service
    if sys.platform == "darwin":
        if not unload_launchd_service():
            logger.error("Failed to unload launchd service")
            return False

        logger.info("Auto-renewal disabled and service stopped")
    else:
        logger.info("Auto-renewal disabled")

    return True


def display_status(config_file=None):
    """Display auto-renewal status.

    :param config_file: Path to tokendito config file
    """
    from tokendito.renewal import get_auto_renew_config, get_credential_expiration

    settings = get_auto_renew_config(config_file)
    service_status = get_service_status()

    print("\nTokendito Auto-Renewal Status")
    print("=" * 60)
    print(f"Enabled: {settings['enabled']}")
    print(f"Renewal threshold: {settings['renewal_threshold_minutes']} minutes")
    print(f"Check interval: {settings['check_interval_minutes']} minutes (fallback)")
    print(f"Max sleep time: {settings['max_sleep_minutes']} minutes (config refresh)")

    if sys.platform == "darwin":
        print(f"\nDaemon Service:")
        print(f"  Plist exists: {service_status['plist_exists']}")
        print(f"  Loaded: {service_status['loaded']}")
        print(f"  Running: {service_status['running']}")

        if service_status['plist_exists']:
            plist_path = get_launchd_plist_path()
            print(f"  Plist location: {plist_path}")

        log_dir = get_log_dir()
        print(f"  Log directory: {log_dir}")

    print(f"\nMonitored Profiles ({len(settings['profiles'])}):")
    if settings['profiles']:
        for profile in settings['profiles']:
            expiration = get_credential_expiration(profile)
            if expiration:
                from datetime import datetime, timezone
                now = datetime.now(timezone.utc)
                time_left = expiration - now
                hours = time_left.total_seconds() / 3600
                print(f"  - {profile}: expires in {hours:.1f} hours ({expiration})")
            else:
                print(f"  - {profile}: no valid credentials")
    else:
        print("  (none)")

    print()
