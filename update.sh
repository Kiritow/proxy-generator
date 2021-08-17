#!/bin/bash
set -x
python3 generate.py
sudo cp local/generated.proxy /etc/nginx/sites-enabled/
sudo nginx -t
echo 'Nginx pre-check OK. Reload nginx in 5 sec...'
sleep 5
sudo systemctl reload nginx
