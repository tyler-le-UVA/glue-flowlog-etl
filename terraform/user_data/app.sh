#!/bin/bash
# "app" instance: a plain nginx web server on port 80.
set -euxo pipefail

dnf install -y nginx
echo "<h1>glue-flowlog-etl lab app</h1>" > /usr/share/nginx/html/index.html
systemctl enable --now nginx
