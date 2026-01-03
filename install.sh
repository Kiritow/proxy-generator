#!/bin/bash
set -euxo pipefail
python3 -m venv venv
. venv/bin/activate
pip install pydantic PyYAML
mkdir -p nginx-certs nginx-cache nginx-pid
