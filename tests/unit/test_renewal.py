# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Unit tests for the renewal module."""

import configparser
import os
import tempfile
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, Mock, patch

import pytest


def test_parse_expiration_time():
    """Test parsing various expiration time formats."""
    from tokendito.renewal import parse_expiration_time

    # Test ISO 8601 with timezone
    result = parse_expiration_time("2026-03-20T08:00:46+00:00")
    assert result is not None
    assert isinstance(result, datetime)
    assert result.year == 2026
    assert result.month == 3
    assert result.day == 20

    # Test ISO 8601 with Z timezone
    result = parse_expiration_time("2026-03-20T08:00:46Z")
    assert result is not None

    # Test invalid format
    result = parse_expiration_time("invalid")
    assert result is None

    # Test None input
    result = parse_expiration_time(None)
    assert result is None


def test_get_credential_expiration():
    """Test reading credential expiration from AWS credentials file."""
    from tokendito.renewal import get_credential_expiration

    # Create temporary credentials file
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".ini") as f:
        f.write("[default]\n")
        f.write("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
        f.write("aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n")
        f.write("aws_session_token = example_token\n")
        f.write("x_security_token_expires = 2026-03-20T08:00:46+00:00\n")
        creds_file = f.name

    try:
        # Test reading expiration
        result = get_credential_expiration("default", creds_file)
        assert result is not None
        assert isinstance(result, datetime)

        # Test non-existent profile
        result = get_credential_expiration("nonexistent", creds_file)
        assert result is None

        # Test non-existent file
        result = get_credential_expiration("default", "/nonexistent/file")
        assert result is None

    finally:
        os.unlink(creds_file)


def test_check_profile_needs_renewal():
    """Test checking if a profile needs renewal."""
    from tokendito.renewal import check_profile_needs_renewal

    # Create temporary credentials file with credentials expiring in 1 hour
    expiration = datetime.now(timezone.utc) + timedelta(hours=1)
    expiration_str = expiration.isoformat()

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".ini") as f:
        f.write("[test_profile]\n")
        f.write("aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n")
        f.write("x_security_token_expires = " + expiration_str + "\n")
        creds_file = f.name

    try:
        # Test with 30-minute threshold (should not need renewal)
        needs_renewal, time_left = check_profile_needs_renewal(
            "test_profile", renewal_threshold_minutes=30, credentials_file=creds_file
        )
        assert needs_renewal is False
        assert time_left is not None

        # Test with 90-minute threshold (should need renewal)
        needs_renewal, time_left = check_profile_needs_renewal(
            "test_profile", renewal_threshold_minutes=90, credentials_file=creds_file
        )
        assert needs_renewal is True

        # Test with non-existent profile (should need renewal)
        needs_renewal, time_left = check_profile_needs_renewal(
            "nonexistent", renewal_threshold_minutes=30, credentials_file=creds_file
        )
        assert needs_renewal is True
        assert time_left is None

    finally:
        os.unlink(creds_file)


@patch("subprocess.run")
def test_renew_profiles_success(mock_run):
    """Test successful renewal of multiple profiles."""
    from tokendito.renewal import renew_profiles

    # Mock successful subprocess run
    mock_result = Mock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    # Test renewal of multiple profiles
    profiles = ["profile1", "profile2", "profile3"]
    result = renew_profiles(profiles)

    assert result is True
    mock_run.assert_called_once()

    # Verify the command includes --multi-profiles for each profile
    call_args = mock_run.call_args
    cmd = call_args[0][0]
    assert "tokendito" in cmd
    assert "--multi-profiles" in cmd
    assert cmd.count("--multi-profiles") == 3


@patch("subprocess.run")
def test_renew_profiles_failure(mock_run):
    """Test failed renewal of profiles."""
    from tokendito.renewal import renew_profiles

    # Mock failed subprocess run
    mock_result = Mock()
    mock_result.returncode = 1
    mock_result.stderr = "Authentication failed"
    mock_run.return_value = mock_result

    # Test renewal failure
    profiles = ["profile1", "profile2"]
    result = renew_profiles(profiles)

    assert result is False


@patch("subprocess.run")
def test_renew_profiles_timeout(mock_run):
    """Test renewal timeout."""
    from tokendito.renewal import renew_profiles
    import subprocess

    # Mock timeout
    mock_run.side_effect = subprocess.TimeoutExpired("tokendito", 600)

    # Test renewal timeout
    profiles = ["profile1"]
    result = renew_profiles(profiles)

    assert result is False


def test_renew_profiles_empty_list():
    """Test renewal with empty profile list."""
    from tokendito.renewal import renew_profiles

    # Test with empty list
    result = renew_profiles([])
    assert result is True


def test_get_auto_renew_config():
    """Test reading auto-renewal configuration."""
    from tokendito.renewal import get_auto_renew_config

    # Create temporary config file
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".ini") as f:
        f.write("[auto-renewal]\n")
        f.write("enabled = true\n")
        f.write("profiles = profile1, profile2, profile3\n")
        f.write("renewal_threshold_minutes = 45\n")
        f.write("check_interval_minutes = 15\n")
        f.write("max_sleep_minutes = 120\n")
        config_file = f.name

    try:
        # Test reading config
        settings = get_auto_renew_config(config_file)

        assert settings["enabled"] is True
        assert settings["profiles"] == ["profile1", "profile2", "profile3"]
        assert settings["renewal_threshold_minutes"] == 45
        assert settings["check_interval_minutes"] == 15
        assert settings["max_sleep_minutes"] == 120

    finally:
        os.unlink(config_file)


def test_get_auto_renew_config_defaults():
    """Test default auto-renewal configuration."""
    from tokendito.renewal import get_auto_renew_config

    # Test with non-existent file (should return defaults)
    settings = get_auto_renew_config("/nonexistent/file")

    assert settings["enabled"] is False
    assert settings["profiles"] == []
    assert settings["renewal_threshold_minutes"] == 30
    assert settings["check_interval_minutes"] == 10
    assert settings["max_sleep_minutes"] == 60


def test_save_auto_renew_config():
    """Test saving auto-renewal configuration."""
    from tokendito.renewal import get_auto_renew_config, save_auto_renew_config

    # Create temporary config file
    with tempfile.TemporaryDirectory() as tmpdir:
        config_file = os.path.join(tmpdir, "test.ini")

        # Test saving config
        settings = {
            "enabled": True,
            "profiles": ["dev", "staging", "prod"],
            "renewal_threshold_minutes": 60,
            "check_interval_minutes": 5,
            "max_sleep_minutes": 30,
        }

        result = save_auto_renew_config(settings, config_file)
        assert result is True

        # Verify saved config
        loaded = get_auto_renew_config(config_file)
        assert loaded["enabled"] == settings["enabled"]
        assert loaded["profiles"] == settings["profiles"]
        assert loaded["renewal_threshold_minutes"] == settings["renewal_threshold_minutes"]
        assert loaded["check_interval_minutes"] == settings["check_interval_minutes"]
        assert loaded["max_sleep_minutes"] == settings["max_sleep_minutes"]


def test_calculate_next_check_time():
    """Test calculating next check time based on credential expirations."""
    from tokendito.renewal import calculate_next_check_time

    # Create temporary credentials file with various expiration times
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".ini") as f:
        now = datetime.now(timezone.utc)

        # Profile expiring in 2 hours
        exp1 = now + timedelta(hours=2)
        f.write("[profile_2h]\n")
        f.write(f"x_security_token_expires = {exp1.isoformat()}\n")

        # Profile expiring in 6 hours
        exp2 = now + timedelta(hours=6)
        f.write("[profile_6h]\n")
        f.write(f"x_security_token_expires = {exp2.isoformat()}\n")

        creds_file = f.name

    try:
        with patch("tokendito.renewal.get_credential_expiration") as mock_get_exp:
            # Mock returning expiration times
            def get_exp_side_effect(profile_name, creds_file=None):
                if profile_name == "profile_2h":
                    return now + timedelta(hours=2)
                elif profile_name == "profile_6h":
                    return now + timedelta(hours=6)
                return None

            mock_get_exp.side_effect = get_exp_side_effect

            # Test with 30-minute threshold
            # Should wake up for profile_2h in 1.5 hours (90 minutes)
            sleep_seconds = calculate_next_check_time(
                ["profile_2h", "profile_6h"],
                renewal_threshold_minutes=30,
                check_interval_minutes=10,
                max_sleep_minutes=60,
            )

            # Should be capped at 60 minutes
            assert sleep_seconds == 60 * 60

            # Test with no valid profiles (should use fallback)
            sleep_seconds = calculate_next_check_time(
                ["nonexistent"],
                renewal_threshold_minutes=30,
                check_interval_minutes=15,
                max_sleep_minutes=60,
            )

            # Should use check_interval_minutes
            assert sleep_seconds == 15 * 60

    finally:
        os.unlink(creds_file)


@patch("tokendito.renewal.time.sleep")
@patch("tokendito.renewal.get_auto_renew_config")
@patch("tokendito.renewal.run_renewal_check")
def test_run_renewal_daemon(mock_check, mock_config, mock_sleep):
    """Test the renewal daemon main loop."""
    from tokendito.renewal import run_renewal_daemon

    # Configure mock to stop after one iteration
    call_count = [0]

    def config_side_effect(config_file=None):
        call_count[0] += 1
        if call_count[0] == 1:
            return {
                "enabled": True,
                "profiles": ["profile1"],
                "renewal_threshold_minutes": 30,
                "check_interval_minutes": 10,
                "max_sleep_minutes": 60,
            }
        else:
            # Disable on second call to exit loop
            return {
                "enabled": False,
                "profiles": [],
                "renewal_threshold_minutes": 30,
                "check_interval_minutes": 10,
                "max_sleep_minutes": 60,
            }

    mock_config.side_effect = config_side_effect
    mock_check.return_value = 0

    # Run daemon (should exit after checking once)
    run_renewal_daemon()

    # Verify daemon checked for renewals
    assert mock_check.called
    assert mock_sleep.called


@patch("tokendito.renewal.renew_profiles")
@patch("tokendito.renewal.check_profile_needs_renewal")
@patch("tokendito.renewal.get_auto_renew_config")
def test_run_renewal_check(mock_config, mock_check_profile, mock_renew):
    """Test running a single renewal check."""
    from tokendito.renewal import run_renewal_check

    # Configure mocks
    mock_config.return_value = {
        "enabled": True,
        "profiles": ["profile1", "profile2", "profile3"],
        "renewal_threshold_minutes": 30,
        "check_interval_minutes": 10,
        "max_sleep_minutes": 60,
    }

    # Make profile1 and profile3 need renewal
    def check_side_effect(profile_name, threshold):
        if profile_name in ["profile1", "profile3"]:
            return (True, timedelta(minutes=20))
        return (False, timedelta(hours=5))

    mock_check_profile.side_effect = check_side_effect
    mock_renew.return_value = True

    # Run renewal check
    result = run_renewal_check()

    # Should have renewed 2 profiles
    assert result == 2

    # Verify renew_profiles called with correct profiles
    mock_renew.assert_called_once()
    call_args = mock_renew.call_args[0][0]
    assert "profile1" in call_args
    assert "profile3" in call_args
    assert "profile2" not in call_args


@patch("tokendito.renewal.get_auto_renew_config")
def test_run_renewal_check_disabled(mock_config):
    """Test renewal check when auto-renewal is disabled."""
    from tokendito.renewal import run_renewal_check

    # Configure mock with disabled auto-renewal
    mock_config.return_value = {
        "enabled": False,
        "profiles": ["profile1"],
        "renewal_threshold_minutes": 30,
        "check_interval_minutes": 10,
        "max_sleep_minutes": 60,
    }

    # Run renewal check
    result = run_renewal_check()

    # Should return 0 (nothing renewed)
    assert result == 0


@patch("tokendito.renewal.get_auto_renew_config")
def test_run_renewal_check_no_profiles(mock_config):
    """Test renewal check when no profiles are configured."""
    from tokendito.renewal import run_renewal_check

    # Configure mock with no profiles
    mock_config.return_value = {
        "enabled": True,
        "profiles": [],
        "renewal_threshold_minutes": 30,
        "check_interval_minutes": 10,
        "max_sleep_minutes": 60,
    }

    # Run renewal check
    result = run_renewal_check()

    # Should return 0 (nothing renewed)
    assert result == 0
