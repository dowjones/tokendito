# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""Reusable functions."""
import subprocess


def string_decode(bytestring):
    """Convert a str into a Unicode object.

    The `decode()` method is only available in byte strings. Calling on
    other string objects generates a `NameError`, and the same string is
    returned unmodified.

    :param bytestring:
    :return: decoded string
    """
    decoded_string = bytestring
    try:
        decoded_string = bytestring.decode("utf-8")
    except (NameError, TypeError):
        # If a TypeError is raised, this is a no-op.
        pass

    return decoded_string


def run_process(proc):
    """Spawn a child process.

    Returns a dict with stdout, sdterr, exit status, and command executed.
    """
    process = subprocess.Popen(proc, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (stdoutdata, stderrdata) = process.communicate()

    proc_status = {
        "stdout": string_decode(stdoutdata),
        "stderr": string_decode(stderrdata),
        "name": " ".join(proc),
        "exit_status": process.returncode,
    }
    return proc_status
