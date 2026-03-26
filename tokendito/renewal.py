# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Credential auto-renewal management for tokendito."""

import configparser
import logging
import os
import time
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


def parse_expiration_time(expiration_str):
    """Parse AWS credential expiration timestamp.

    AWS stores expiration in ISO 8601 format with timezone.

    :param expiration_str: ISO 8601 timestamp string
    :return: datetime object or None
    """
    try:
        # Parse ISO 8601 format: 2026-03-20T08:00:46+00:00
        if expiration_str:
            # Handle both +00:00 and Z timezone formats
            expiration_str = expiration_str.replace('Z', '+00:00')
            dt = datetime.fromisoformat(expiration_str)
            return dt
    except (ValueError, AttributeError) as err:
        logger.debug(f"Could not parse expiration time '{expiration_str}': {err}")
    return None


def get_credential_expiration(profile_name, credentials_file=None):
    """Get expiration time for a specific AWS profile.

    :param profile_name: AWS profile name
    :param credentials_file: Path to AWS credentials file (default: ~/.aws/credentials)
    :return: datetime object or None
    """
    if not credentials_file:
        credentials_file = os.path.join(os.path.expanduser("~"), ".aws", "credentials")

    if not os.path.exists(credentials_file):
        logger.debug(f"Credentials file not found: {credentials_file}")
        return None

    try:
        config = configparser.RawConfigParser()
        config.read(credentials_file)

        if not config.has_section(profile_name):
            logger.debug(f"Profile '{profile_name}' not found in credentials file")
            return None

        # AWS CLI stores expiration as x_security_token_expires
        expiration_key = "x_security_token_expires"
        if config.has_option(profile_name, expiration_key):
            expiration_str = config.get(profile_name, expiration_key)
            return parse_expiration_time(expiration_str)

        logger.debug(f"No expiration time found for profile '{profile_name}'")
        return None

    except (configparser.Error, OSError) as err:
        logger.error(f"Error reading credentials file: {err}")
        return None


def check_profile_needs_renewal(profile_name, renewal_threshold_minutes=30, credentials_file=None):
    """Check if a profile needs renewal.

    :param profile_name: AWS profile name
    :param renewal_threshold_minutes: Minutes before expiration to trigger renewal
    :param credentials_file: Path to AWS credentials file
    :return: tuple (needs_renewal: bool, time_until_expiration: timedelta or None)
    """
    expiration = get_credential_expiration(profile_name, credentials_file)

    if not expiration:
        logger.debug(f"Profile '{profile_name}' has no expiration time, needs renewal")
        return (True, None)

    now = datetime.now(timezone.utc)
    time_until_expiration = expiration - now

    # Check if expired or within threshold
    threshold = timedelta(minutes=renewal_threshold_minutes)
    needs_renewal = time_until_expiration <= threshold

    logger.debug(
        f"Profile '{profile_name}': expires in {time_until_expiration}, "
        f"threshold {threshold}, needs_renewal={needs_renewal}"
    )

    return (needs_renewal, time_until_expiration)


def renew_profiles(profile_names, config_file=None):
    """Renew credentials for multiple profiles at once.

    This executes tokendito with --multi-profiles to renew all profiles
    with a single Okta authentication.

    :param profile_names: List of profile names from tokendito config
    :param config_file: Path to tokendito config file
    :return: True if successful, False otherwise
    """
    import shutil
    import subprocess

    if not profile_names:
        logger.warning("No profiles provided for renewal")
        return True

    # Find the tokendito command (important for launchd which doesn't have user's PATH)
    tokendito_cmd = shutil.which("tokendito")
    if not tokendito_cmd:
        logger.error("tokendito command not found in PATH")
        return False

    # Build command with --multi-profiles for each profile
    cmd = [tokendito_cmd]
    for profile_name in profile_names:
        cmd.extend(["--multi-profiles", profile_name])

    if config_file:
        cmd.extend(["--config-file", config_file])

    profile_list = ", ".join(profile_names)
    logger.info(f"Renewing credentials for {len(profile_names)} profiles: {profile_list}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout for multiple profiles
        )

        if result.returncode == 0:
            logger.info(f"Successfully renewed credentials for all {len(profile_names)} profiles")
            return True
        else:
            logger.error(
                f"Failed to renew credentials: {result.stderr}"
            )
            return False

    except subprocess.TimeoutExpired:
        logger.error(f"Timeout renewing credentials for profiles: {profile_list}")
        return False
    except Exception as err:
        logger.error(f"Error renewing credentials: {err}")
        return False


def get_auto_renew_config(config_file=None):
    """Read auto-renewal configuration from tokendito config file.

    :param config_file: Path to tokendito config file
    :return: dict with auto-renewal settings
    """
    if not config_file:
        from tokendito.config import config as default_config
        config_file = default_config.user["config_file"]

    config_file = os.path.expanduser(config_file)

    settings = {
        "enabled": False,
        "profiles": [],
        "renewal_threshold_minutes": 30,
        "check_interval_minutes": 10,
        "max_sleep_minutes": 60,
    }

    if not os.path.exists(config_file):
        logger.debug(f"Config file not found: {config_file}")
        return settings

    try:
        config = configparser.RawConfigParser()
        config.read(config_file)

        section = "auto-renewal"
        if config.has_section(section):
            if config.has_option(section, "enabled"):
                settings["enabled"] = config.getboolean(section, "enabled")

            if config.has_option(section, "profiles"):
                profiles_str = config.get(section, "profiles")
                # Support comma-separated list
                settings["profiles"] = [p.strip() for p in profiles_str.split(",") if p.strip()]

            if config.has_option(section, "renewal_threshold_minutes"):
                settings["renewal_threshold_minutes"] = config.getint(
                    section, "renewal_threshold_minutes"
                )

            if config.has_option(section, "check_interval_minutes"):
                settings["check_interval_minutes"] = config.getint(
                    section, "check_interval_minutes"
                )

            if config.has_option(section, "max_sleep_minutes"):
                settings["max_sleep_minutes"] = config.getint(
                    section, "max_sleep_minutes"
                )

        logger.debug(f"Auto-renewal settings: {settings}")
        return settings

    except (configparser.Error, ValueError) as err:
        logger.error(f"Error reading auto-renewal config: {err}")
        return settings


def save_auto_renew_config(settings, config_file=None):
    """Save auto-renewal configuration to tokendito config file.

    :param settings: dict with auto-renewal settings
    :param config_file: Path to tokendito config file
    :return: True if successful, False otherwise
    """
    if not config_file:
        from tokendito.config import config as default_config
        config_file = default_config.user["config_file"]

    config_file = os.path.expanduser(config_file)

    # Ensure directory exists
    config_dir = os.path.dirname(config_file)
    os.makedirs(config_dir, exist_ok=True)

    try:
        config = configparser.RawConfigParser()
        if os.path.exists(config_file):
            config.read(config_file)

        section = "auto-renewal"
        if not config.has_section(section):
            config.add_section(section)

        config.set(section, "enabled", str(settings.get("enabled", False)).lower())

        profiles = settings.get("profiles", [])
        config.set(section, "profiles", ", ".join(profiles))

        config.set(
            section,
            "renewal_threshold_minutes",
            str(settings.get("renewal_threshold_minutes", 30))
        )

        config.set(
            section,
            "check_interval_minutes",
            str(settings.get("check_interval_minutes", 10))
        )

        config.set(
            section,
            "max_sleep_minutes",
            str(settings.get("max_sleep_minutes", 60))
        )

        with open(config_file, "w") as f:
            config.write(f)

        logger.info(f"Saved auto-renewal configuration to {config_file}")
        return True

    except (configparser.Error, OSError) as err:
        logger.error(f"Error saving auto-renewal config: {err}")
        return False


def run_renewal_check(config_file=None):
    """Run a single renewal check for all configured profiles.

    Collects all profiles that need renewal and renews them together
    using --multi-profiles for a single Okta authentication.

    :param config_file: Path to tokendito config file
    :return: Number of profiles renewed
    """
    settings = get_auto_renew_config(config_file)

    if not settings["enabled"]:
        logger.info("Auto-renewal is disabled")
        return 0

    if not settings["profiles"]:
        logger.warning("No profiles configured for auto-renewal")
        return 0

    logger.info(f"Checking {len(settings['profiles'])} profiles for renewal")

    # Collect all profiles that need renewal
    profiles_to_renew = []
    for profile_name in settings["profiles"]:
        needs_renewal, time_left = check_profile_needs_renewal(
            profile_name,
            settings["renewal_threshold_minutes"]
        )

        if needs_renewal:
            logger.info(f"Profile '{profile_name}' needs renewal")
            profiles_to_renew.append(profile_name)
        else:
            if time_left:
                logger.debug(
                    f"Profile '{profile_name}' does not need renewal yet "
                    f"(expires in {time_left})"
                )

    # Renew all profiles at once with a single Okta authentication
    if profiles_to_renew:
        logger.info(
            f"Renewing {len(profiles_to_renew)} profiles with single authentication"
        )
        if renew_profiles(profiles_to_renew, config_file):
            logger.info(f"Successfully renewed {len(profiles_to_renew)} profiles")
            return len(profiles_to_renew)
        else:
            logger.error("Failed to renew profiles")
            return 0
    else:
        logger.info("No profiles need renewal at this time")
        return 0


def calculate_next_check_time(profiles, renewal_threshold_minutes, check_interval_minutes, max_sleep_minutes=60):
    """Calculate when the next credential check should occur.

    Checks all profiles and returns the time to sleep until the earliest
    credential needs renewal. Falls back to check_interval if no expirations found.

    Sleep time is capped at max_sleep_minutes to ensure config changes are picked up
    promptly (e.g., if user adds a new profile with shorter expiration).

    :param profiles: List of profile names to check
    :param renewal_threshold_minutes: Minutes before expiration to trigger renewal
    :param check_interval_minutes: Default check interval as fallback
    :param max_sleep_minutes: Maximum sleep time in minutes (default: 60)
    :return: Number of seconds to sleep
    """
    from datetime import datetime, timedelta, timezone

    earliest_renewal = None
    now = datetime.now(timezone.utc)

    for profile_name in profiles:
        expiration = get_credential_expiration(profile_name)
        if expiration:
            # Calculate when renewal should happen (threshold before expiration)
            renewal_time = expiration - timedelta(minutes=renewal_threshold_minutes)

            if renewal_time > now:  # Only consider future renewals
                if earliest_renewal is None or renewal_time < earliest_renewal:
                    earliest_renewal = renewal_time

    if earliest_renewal:
        # Calculate sleep time with a small buffer (1 minute early)
        sleep_seconds = max(60, (earliest_renewal - now).total_seconds() - 60)

        # Cap at max_sleep_minutes to allow config changes to be picked up
        max_sleep_seconds = max_sleep_minutes * 60
        if sleep_seconds > max_sleep_seconds:
            logger.debug(
                f"Next renewal needed at {earliest_renewal}, "
                f"but capping sleep at {max_sleep_minutes} minutes to check for config changes"
            )
            return max_sleep_seconds

        logger.debug(
            f"Next renewal needed at {earliest_renewal}, "
            f"sleeping for {sleep_seconds / 60:.1f} minutes"
        )
        return sleep_seconds
    else:
        # No valid expirations found, use default interval
        logger.debug(
            f"No valid expiration times found, using default interval of "
            f"{check_interval_minutes} minutes"
        )
        return check_interval_minutes * 60


def run_renewal_daemon(config_file=None):
    """Run the renewal daemon - continuously check and renew credentials.

    This function intelligently schedules checks based on credential expiration times
    rather than polling at fixed intervals.

    :param config_file: Path to tokendito config file
    """
    logger.info("Starting tokendito renewal daemon")

    while True:
        try:
            settings = get_auto_renew_config(config_file)

            if not settings["enabled"]:
                logger.info("Auto-renewal disabled, exiting daemon")
                break

            # Run renewal check
            run_renewal_check(config_file)

            # Calculate optimal sleep time based on credential expirations
            sleep_seconds = calculate_next_check_time(
                settings["profiles"],
                settings["renewal_threshold_minutes"],
                settings["check_interval_minutes"],
                settings["max_sleep_minutes"],
            )

            logger.debug(f"Sleeping for {sleep_seconds / 60:.1f} minutes")
            time.sleep(sleep_seconds)

        except KeyboardInterrupt:
            logger.info("Renewal daemon interrupted by user")
            break
        except Exception as err:
            logger.error(f"Error in renewal daemon: {err}", exc_info=True)
            # Sleep a bit before retrying
            time.sleep(60)


def main():
    """Entry point for renewal daemon."""
    import argparse
    parser = argparse.ArgumentParser(description="Tokendito credential auto-renewal daemon")
    parser.add_argument(
        "--config-file",
        help="Path to tokendito configuration file"
    )
    parser.add_argument(
        "--check-once",
        action="store_true",
        help="Run a single renewal check and exit"
    )
    args = parser.parse_args()

    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s |%(name)s %(funcName)s():%(lineno)i| %(message)s"
    )

    if args.check_once:
        run_renewal_check(args.config_file)
    else:
        run_renewal_daemon(args.config_file)


if __name__ == "__main__":
    main()
