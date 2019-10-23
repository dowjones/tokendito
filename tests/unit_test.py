# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Unit tests, and local fixtures."""
from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

from builtins import (ascii, bytes, chr, dict, filter, hex, input,  # noqa: F401
                      int, list, map, next, object, oct, open, pow, range,
                      round, str, super, zip)
from os import path
import sys

from future import standard_library
import pytest
import semver


sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))
standard_library.install_aliases()


@pytest.fixture
def valid_settings():
    """Return a dict with valid settings for the tokendito.settings module."""
    from tokendito import settings
    builtins_and_methods = [
        '__builtins__', '__cached__', '__doc__', '__file__', '__loader__',
        '__name__', '__package__', '__spec__', 'absolute_import', 'ascii',
        'bytes', 'chr', 'dict', 'division', 'encoding', 'filter', 'hex',
        'input', 'int', 'list', 'map', 'next', 'object', 'oct', 'open',
        'pow', 'print_function', 'range', 'role_arn', 'round',
        'standard_library', 'str', 'super', 'sys', 'unicode_literals', 'zip']

    settings_keys = dir(settings)
    unmatched_keys = list(set(settings_keys) - set(builtins_and_methods))

    valid_keys = {str(key): key + '_pytest_patched' for key in unmatched_keys}
    return valid_keys


@pytest.fixture
def invalid_settings():
    """Return a dict with invalid settings for the tokendito.settings module."""
    invalid_keys = {
        "okta": "okta_pytest_patched",
        "okta_deadbeef": "okta_deadbeef_pytest_patched",
        "aws_deadbeef": "aws_deadbeef_pytest_patched",
        "pytest_bad_value": "pytest_bad_value_pytest_patched"
    }
    return invalid_keys


def test_import_location():
    """Ensure module imported is the local one."""
    import tokendito
    local_path = path.realpath(path.dirname(path.dirname(
        path.abspath(__file__))) + '/tokendito/__init__.py')
    imported_path = path.realpath(tokendito.__file__)
    assert imported_path.startswith(local_path)


def test_semver_version():
    """Ensure the package version is semver compliant."""
    from tokendito.__version__ import __version__ as version
    assert semver.parse_version_info(version)


def test__version__var_names():
    """Ensure variables follow the __varname__ convention."""
    from tokendito import __version__
    for item in vars(__version__):
        assert item.startswith('__')
        assert item.endswith('__')


@pytest.mark.parametrize('string', [r'raw_string', u'unicode_string', r'byte_string'])
def test_to_unicode(string):
    """Test whether to_unicode returns unicode strings."""
    from tokendito import helpers
    new_str = helpers.to_unicode(string)
    assert isinstance(new_str, str)


def test_set_okta_username(monkeypatch):
    """Test whether data sent is the same as data returned."""
    from tokendito import helpers, settings

    monkeypatch.setattr('tokendito.helpers.input', lambda _: 'pytest_patched')
    val = helpers.set_okta_username()

    assert val == 'pytest_patched'
    assert settings.okta_username == 'pytest_patched'


def test_set_okta_password(monkeypatch):
    """Test whether data sent is the same as data returned."""
    from tokendito import helpers, settings
    import getpass

    monkeypatch.setattr(getpass, 'getpass', lambda: 'pytest_patched')
    val = helpers.set_okta_password()

    assert val == 'pytest_patched'
    assert settings.okta_password == 'pytest_patched'


def test_process_environment(monkeypatch, valid_settings, invalid_settings):
    """Test whether environment variables are set in settings.*."""
    from tokendito import helpers, settings
    import os

    # ENV standard is uppercase
    valid_keys = {key.upper(): val for (key, val) in valid_settings.items()}
    invalid_keys = {key.upper(): val for (key, val) in invalid_settings.items()}

    # Python 2.7 does not support {**dict1, **dict2} for concatenation
    env_keys = valid_keys.copy()
    env_keys.update(invalid_keys)

    monkeypatch.setattr(os, 'environ', env_keys)
    helpers.process_environment()

    for key in valid_settings:
        assert getattr(settings, key) == valid_settings[key]

    for key in invalid_settings:
        assert getattr(settings, key, 'not_found') == 'not_found'


def test_process_arguments(valid_settings, invalid_settings):
    """Test whether arguments are correctly set in settings.*."""
    from tokendito import helpers, settings
    from argparse import Namespace

    # Python 2.7 does not support {**dict1, **dict2} for concatenation
    args = valid_settings.copy()
    args.update(invalid_settings)

    helpers.process_arguments(Namespace(**args))

    for key_name in valid_settings:
        assert getattr(settings, key_name) == valid_settings[key_name]

    for key_name in invalid_settings:
        assert getattr(settings, key_name, 'not_found') == 'not_found'

@pytest.mark.skipif(sys.version_info[:2] == (3, 5),
                    reason="ConfigParser bug, see https://bugs.python.org/issue29623")
def test_process_ini_file(tmpdir, valid_settings, invalid_settings):
    """Test whether ini config elements are correctly set in settings.*."""
    from tokendito import helpers, settings
    # Create a mock config file
    data = '[default]\nokta_username = pytest\n\n[pytest]\n'
    data += ''.join('{} = {}\n'.format(key, val) for key, val in valid_settings.items())
    data += ''.join('{} = {}\n'.format(key, val) for key, val in invalid_settings.items())
    data += '\n[pytest_end]\n'
    data += ''.join('{} = {}\n'.format(key, val) for key, val in invalid_settings.items())

    # Python 3.7 supports patching builtins.open(), which gives us the ability
    # to bypass file creation with:
    # mocker.patch('builtins.open', mocker.mock_open(read_data=data), create=True)
    # There is no (easy) way to achieve the same on earlier versions, so we create
    # an actual file instead. tmpdir keeps the last 3 files/dirs behind for inspection
    path = tmpdir.mkdir('pytest').join('pytest_tokendito.ini')
    path.write(data)

    # Ensure we fail if the section is not found
    with pytest.raises(SystemExit) as err:
        helpers.process_ini_file(path, 'expected_failure')
        # assert err.type == SystemExit
        assert err.value.code == 2

    helpers.process_ini_file(path, 'pytest')
    # Test that correct options are set
    for key_name in valid_settings:
        assert getattr(settings, key_name) == valid_settings[key_name]
    # Test that incorrect options aren't set
    for key_name in invalid_settings:
        assert getattr(settings, key_name, 'not_found') == 'not_found'
