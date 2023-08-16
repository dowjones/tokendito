#!/usr/bin/env python
# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Tokendito module entry point."""
import sys


def main(args=None):  # needed for console script
    """Packge entry point."""
    if __package__ is None:
        import os.path

        path = os.path.dirname(os.path.dirname(__file__))
        sys.path[0:0] = [path]
    from tokendito.user import cmd_interface

    try:
        return cmd_interface(args)
    except KeyboardInterrupt:
        print("\nInterrupted")
        sys.exit(1)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
