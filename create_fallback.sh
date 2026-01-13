#!/bin/bash
set -euxo pipefail
openssl req -x509 -newkey rsa:4096 -keyout fallback.key -out fallback.cer -days 3650 -nodes -subj "/CN=example.com"