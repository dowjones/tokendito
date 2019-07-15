#!/usr/bin/env python
# vim: set filetype=python ts=4 sw=4
# -*- coding: utf-8 -*-
"""`tokendito` is in Github: <https://github.com/dowjones/tokendito>_."""

from codecs import open
import os
from os import path
import sys

from setuptools import find_packages, setup

here = path.abspath(path.dirname(__file__))

with open(path.join(here, 'README.rst'), encoding=sys.stdin.encoding) as f:
    long_description = f.read()

with open('requirements.txt') as f:
    required = f.read().splitlines()

about = {}
with open(os.path.join(here, 'tokendito', '__version__.py'), 'r') as f:
    exec(f.read(), about)

setup(
    name='tokendito',
    version=about['__version__'],
    description=about['__description__'],
    long_description=long_description,
    long_description_content_type=about['__long_description_content_type__'],
    url=about['__url__'],
    author=about['__author__'],
    author_email=about['__author_email__'],
    classifiers=[
        'License :: OSI Approved :: Apache Software License',
        'Development Status :: 5 - Production/Stable',
        'Operating System :: OS Independent',
        'Natural Language :: English',
        'Environment :: Console',
        'Programming Language :: Python',
        'Intended Audience :: End Users/Desktop',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
    keywords=['okta', 'aws', 'sts'],
    packages=find_packages(exclude=['contrib', 'docs', 'tests', '.tox']),
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*, !=3.5.*",
    license=about['__license__'],
    zip_safe=False,
    install_requires=[required],
    entry_points={
        'console_scripts': ['tokendito=tokendito.__main__:main'],
    },

    # $ pip install -e . [dev,test]
)
