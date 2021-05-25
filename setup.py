#!/usr/bin/env python
# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""`tokendito` is in Github: <https://github.com/dowjones/tokendito>_."""

from codecs import open
import datetime
import os
import sys

from setuptools import find_packages, setup


here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, "README.rst"), encoding=sys.stdin.encoding) as f:
    long_description = f.read()

with open("requirements.txt") as f:
    required = f.read().splitlines()

about = {}
with open(os.path.join(here, "tokendito", "__version__.py"), "r") as f:
    exec(f.read(), about)

if "DEVBUILD" in os.environ:
    now = datetime.datetime.now()
    about["__version__"] = about["__version__"] + ".dev" + now.strftime("%Y%m%d%H%M%S")

setup(
    name="tokendito",
    version=about["__version__"],
    description=about["__description__"],
    long_description=long_description,
    long_description_content_type=about["__long_description_content_type__"],
    url=about["__url__"],
    author=about["__author__"],
    author_email=about["__author_email__"],
    classifiers=[
        "License :: OSI Approved :: Apache Software License",
        "Development Status :: 5 - Production/Stable",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Programming Language :: Python",
        "Intended Audience :: End Users/Desktop",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
    ],
    keywords=["okta", "aws", "sts"],
    packages=find_packages(exclude=["contrib", "docs", "tests", ".tox"]),
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*",
    license=about["__license__"],
    zip_safe=False,
    install_requires=[required],
    entry_points={
        "console_scripts": ["tokendito=tokendito.__main__:main"],
    },
    # $ pip install -e . [dev,test]
)
