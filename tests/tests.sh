#!/bin/sh
pip install -r tests/requirements.txt
pytest --junitxml=/tmp/unit_test.xml tests