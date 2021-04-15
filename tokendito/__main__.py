#!/usr/bin/env python
# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""tokendito module entry point."""

from __future__ import absolute_import, division, print_function, unicode_literals

from builtins import (  # noqa: F401
    ascii,
    bytes,
    chr,
    dict,
    filter,
    hex,
    input,
    int,
    list,
    map,
    next,
    object,
    oct,
    open,
    pow,
    range,
    round,
    str,
    super,
    zip,
)
import sys

from future import standard_library

standard_library.install_aliases()


def main(args=None):  # needed for console script
    """Packge entry point."""
    if __package__ is None:
        import os.path

        path = os.path.dirname(os.path.dirname(__file__))
        sys.path[0:0] = [path]
    from tokendito.tool import cli

    try:
        return cli(args)
    except KeyboardInterrupt:
        print("\nInterrupted")
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
