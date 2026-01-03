#!/bin/bash
set -euxo pipefail
venv/bin/python3 generate.py --config config.yaml --output proxy.conf --copy-cert $(pwd)/nginx-certs:/certs
sudo podman rm -f -t 3 nginx-server || true
sudo podman run --name nginx-server --restart=always -d --network=host \
    --read-only \
    -v $(pwd)/nginx-cache:/var/cache/nginx \
    -v $(pwd)/nginx-pid:/var/run \
    -v $(pwd)/nginx-certs:/certs:ro \
    -v $(pwd)/proxy.conf:/etc/nginx/conf.d/default.conf:ro \
    docker.io/nginx:latest
