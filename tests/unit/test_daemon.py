# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Unit tests for the daemon module."""

import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

import pytest


@pytest.mark.skipif(sys.platform != "darwin", reason="launchd only available on macOS")
def test_get_launchd_plist_path():
    """Test getting the launchd plist path."""
    from tokendito.daemon import get_launchd_plist_path

    result = get_launchd_plist_path()

    assert isinstance(result, Path)
    assert str(result).endswith("com.tokendito.renewal.plist")
    assert "LaunchAgents" in str(result)


@pytest.mark.skipif(sys.platform != "darwin", reason="launchd only available on macOS")
def test_get_log_dir():
    """Test getting the log directory path."""
    from tokendito.daemon import get_log_dir

    result = get_log_dir()

    assert isinstance(result, Path)
    assert "tokendito" in str(result)
    assert "Logs" in str(result)


@pytest.mark.skipif(sys.platform != "darwin", reason="launchd only available on macOS")
def test_create_launchd_plist():
    """Test creating launchd plist file."""
    from tokendito.daemon import create_launchd_plist

    with tempfile.TemporaryDirectory() as tmpdir:
        # Mock the plist path to use temp directory
        test_plist = Path(tmpdir) / "test.plist"

        with patch("tokendito.daemon.get_launchd_plist_path") as mock_path:
            with patch("tokendito.daemon.get_log_dir") as mock_log:
                mock_path.return_value = test_plist
                mock_log.return_value = Path(tmpdir) / "logs"

                result = create_launchd_plist()

                assert result is True
                assert test_plist.exists()

                # Verify plist content is valid
                import plistlib

                with open(test_plist, "rb") as f:
                    plist_data = plistlib.load(f)

                assert plist_data["Label"] == "com.tokendito.renewal"
                assert "ProgramArguments" in plist_data
                assert plist_data["RunAtLoad"] is True
                assert plist_data["KeepAlive"] is True


@pytest.mark.skipif(sys.platform != "darwin", reason="launchd only available on macOS")
@patch("tokendito.daemon.subprocess.run")
def test_load_launchd_service_success(mock_run):
    """Test successfully loading the launchd service."""
    from tokendito.daemon import load_launchd_service

    # Mock successful load
    mock_result = Mock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    with tempfile.TemporaryDirectory() as tmpdir:
        test_plist = Path(tmpdir) / "test.plist"
        test_plist.touch()

        with patch("tokendito.daemon.get_launchd_plist_path") as mock_path:
            mock_path.return_value = test_plist

            result = load_launchd_service()

            assert result is True
            # Should call launchctl unload then load
            assert mock_run.call_count == 2


@pytest.mark.skipif(sys.platform != "darwin", reason="launchd only available on macOS")
@patch("tokendito.daemon.subprocess.run")
def test_load_launchd_service_failure(mock_run):
    """Test failed loading of launchd service."""
    from tokendito.daemon import load_launchd_service
    import subprocess

    # Mock failed load
    mock_run.side_effect = subprocess.CalledProcessError(1, "launchctl", stderr="Error")

    with tempfile.TemporaryDirectory() as tmpdir:
        test_plist = Path(tmpdir) / "test.plist"
        test_plist.touch()

        with patch("tokendito.daemon.get_launchd_plist_path") as mock_path:
            mock_path.return_value = test_plist

            result = load_launchd_service()

            assert result is False


@pytest.mark.skipif(sys.platform != "darwin", reason="launchd only available on macOS")
def test_load_launchd_service_no_plist():
    """Test loading service when plist doesn't exist."""
    from tokendito.daemon import load_launchd_service

    with patch("tokendito.daemon.get_launchd_plist_path") as mock_path:
        mock_path.return_value = Path("/nonexistent/file.plist")

        result = load_launchd_service()

        assert result is False


@pytest.mark.skipif(sys.platform != "darwin", reason="launchd only available on macOS")
@patch("tokendito.daemon.subprocess.run")
def test_unload_launchd_service_success(mock_run):
    """Test successfully unloading the launchd service."""
    from tokendito.daemon import unload_launchd_service

    # Mock successful unload
    mock_result = Mock()
    mock_result.returncode = 0
    mock_run.return_value = mock_result

    with tempfile.TemporaryDirectory() as tmpdir:
        test_plist = Path(tmpdir) / "test.plist"
        test_plist.touch()

        with patch("tokendito.daemon.get_launchd_plist_path") as mock_path:
            mock_path.return_value = test_plist

            result = unload_launchd_service()

            assert result is True
            mock_run.assert_called_once()


@pytest.mark.skipif(sys.platform != "darwin", reason="launchd only available on macOS")
@patch("tokendito.daemon.subprocess.run")
def test_unload_launchd_service_not_loaded(mock_run):
    """Test unloading service that is not loaded."""
    from tokendito.daemon import unload_launchd_service
    import subprocess

    # Mock "not found" error (service not loaded)
    mock_run.side_effect = subprocess.CalledProcessError(
        1, "launchctl", stderr="Could not find specified service"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        test_plist = Path(tmpdir) / "test.plist"
        test_plist.touch()

        with patch("tokendito.daemon.get_launchd_plist_path") as mock_path:
            mock_path.return_value = test_plist

            result = unload_launchd_service()

            # Should return True (service wasn't loaded anyway)
            assert result is True


@pytest.mark.skipif(sys.platform != "darwin", reason="launchd only available on macOS")
@patch("tokendito.daemon.subprocess.run")
def test_get_service_status(mock_run):
    """Test getting service status."""
    from tokendito.daemon import get_service_status

    # Mock launchctl list output with the service
    mock_result = Mock()
    mock_result.returncode = 0
    mock_result.stdout = "12345\t0\tcom.tokendito.renewal"
    mock_run.return_value = mock_result

    with tempfile.TemporaryDirectory() as tmpdir:
        test_plist = Path(tmpdir) / "test.plist"
        test_plist.touch()

        with patch("tokendito.daemon.get_launchd_plist_path") as mock_path:
            mock_path.return_value = test_plist

            result = get_service_status()

            assert result["platform_supported"] is True
            assert result["plist_exists"] is True
            assert result["loaded"] is True


def test_get_service_status_non_macos():
    """Test getting service status on non-macOS platform."""
    from tokendito.daemon import get_service_status

    with patch("sys.platform", "linux"):
        result = get_service_status()

        assert result["platform_supported"] is False
        assert result["running"] is False


@patch("tokendito.renewal.save_auto_renew_config")
@patch("tokendito.renewal.get_auto_renew_config")
@patch("tokendito.daemon.create_launchd_plist")
@patch("tokendito.daemon.load_launchd_service")
def test_enable_auto_renewal(mock_load, mock_create, mock_get, mock_save):
    """Test enabling auto-renewal."""
    from tokendito.daemon import enable_auto_renewal

    # Configure mocks
    mock_get.return_value = {
        "enabled": False,
        "profiles": [],
        "renewal_threshold_minutes": 30,
        "check_interval_minutes": 10,
        "max_sleep_minutes": 60,
    }
    mock_save.return_value = True
    mock_create.return_value = True
    mock_load.return_value = True

    with patch("sys.platform", "darwin"):
        result = enable_auto_renewal(["profile1", "profile2"])

        assert result is True
        mock_save.assert_called_once()
        mock_create.assert_called_once()
        mock_load.assert_called_once()

        # Verify profiles were added
        saved_settings = mock_save.call_args[0][0]
        assert "profile1" in saved_settings["profiles"]
        assert "profile2" in saved_settings["profiles"]
        assert saved_settings["enabled"] is True


@patch("tokendito.renewal.save_auto_renew_config")
@patch("tokendito.renewal.get_auto_renew_config")
def test_enable_auto_renewal_save_failure(mock_get, mock_save):
    """Test enabling auto-renewal when save fails."""
    from tokendito.daemon import enable_auto_renewal

    # Configure mocks
    mock_get.return_value = {
        "enabled": False,
        "profiles": [],
        "renewal_threshold_minutes": 30,
        "check_interval_minutes": 10,
        "max_sleep_minutes": 60,
    }
    mock_save.return_value = False

    result = enable_auto_renewal(["profile1"])

    assert result is False


@patch("tokendito.renewal.save_auto_renew_config")
@patch("tokendito.renewal.get_auto_renew_config")
@patch("tokendito.daemon.unload_launchd_service")
def test_disable_auto_renewal(mock_unload, mock_get, mock_save):
    """Test disabling auto-renewal."""
    from tokendito.daemon import disable_auto_renewal

    # Configure mocks
    mock_get.return_value = {
        "enabled": True,
        "profiles": ["profile1"],
        "renewal_threshold_minutes": 30,
        "check_interval_minutes": 10,
        "max_sleep_minutes": 60,
    }
    mock_save.return_value = True
    mock_unload.return_value = True

    with patch("sys.platform", "darwin"):
        result = disable_auto_renewal()

        assert result is True
        mock_save.assert_called_once()
        mock_unload.assert_called_once()

        # Verify enabled was set to False
        saved_settings = mock_save.call_args[0][0]
        assert saved_settings["enabled"] is False


@patch("tokendito.renewal.get_auto_renew_config")
@patch("tokendito.daemon.get_service_status")
@patch("tokendito.renewal.get_credential_expiration")
def test_display_status(mock_get_exp, mock_status, mock_config, capsys):
    """Test displaying auto-renewal status."""
    from tokendito.daemon import display_status
    from datetime import datetime, timedelta, timezone

    # Configure mocks
    mock_config.return_value = {
        "enabled": True,
        "profiles": ["profile1", "profile2"],
        "renewal_threshold_minutes": 30,
        "check_interval_minutes": 10,
        "max_sleep_minutes": 60,
    }

    mock_status.return_value = {
        "platform_supported": True,
        "plist_exists": True,
        "loaded": True,
        "running": True,
    }

    # Mock credential expiration
    exp_time = datetime.now(timezone.utc) + timedelta(hours=2)
    mock_get_exp.return_value = exp_time

    with patch("sys.platform", "darwin"):
        display_status()

    # Capture output
    captured = capsys.readouterr()

    # Verify output contains expected information
    assert "Auto-Renewal Status" in captured.out
    assert "Enabled: True" in captured.out
    assert "profile1" in captured.out
    assert "profile2" in captured.out
    assert "Daemon Service:" in captured.out
