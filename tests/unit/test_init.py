# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Unit tests, and local fixtures for the Tokendito module."""
import os
import sys

import semver

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_import_location():
    """Ensure module imported is the local one."""
    import tokendito

    local_path = os.path.realpath(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/../tokendito/__init__.py"
    )
    imported_path = os.path.realpath(tokendito.__file__)
    assert imported_path.startswith(local_path)


def test_semver_version():
    """Ensure the package version is semver compliant."""
    from tokendito import __version__ as version

    assert semver.VersionInfo.parse(version)
