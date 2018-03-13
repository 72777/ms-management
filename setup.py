#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

from setuptools import setup, find_packages

script_path = os.path.dirname(os.path.abspath(__file__))

with open(script_path + '/requirements.txt', 'r') as f:
    requires = f.read().splitlines()

with open(script_path + '/project/VERSION', 'r') as f:
    VERSION = f.read().strip()

setup(
    name='managment',
    version=VERSION,
    description="Management API for public and internal operations",
    long_description=__doc__,
    url="https://github.com/factioninc/ms-management",
    download_url="https://github.com/factioninc/ms-management/archive/%s.tar.gz" % VERSION,
    keywords=[],
    packages=find_packages(exclude=["*.tests", "*.tests.*", "tests.*", "tests"]),
    include_package_data=True,
    install_requires=[requires],
    setup_requires=['pytest-runner'],
    tests_require=['pytest'],
    dependency_links=['https://artifacts.factioninc.com/repository/faction-pypi/']
)
