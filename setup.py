#!/usr/bin/env python
# encoding: utf-8

import os, sys
from setuptools import setup

setup(
    # metadata
    name='PyCDB',
    description='A python wrapper for the CDB Debugger',
    long_description="""
        A python wrapper for Microsoft's CDB command-line debugger.
    """,
    license='MIT',
    version='0.2',
    author='@fishstiqz',
    maintainer='@fishstiqz',
    author_email='',
    url='https://github.com/fishstiqz/pycdb',
    platforms='Microsoft Windows',
    install_requires = open(os.path.join(os.path.dirname(__file__), "requirements.txt")).read().split("\n"),
    classifiers = [
        # has not been tested on Python 2 since Python 3 support was added
        # 'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ],
    scripts = [
            # no scripts current exist
            # os.path.join("bin", "pycdb"),
    ],

    # add non-python files to this array, relative to the project root and set
    # include_package_data to True
    package_data = {
        "pycdb": [],
    },
    include_package_data=False,

    # include all modules/submodules here
    packages=['pycdb']
)
