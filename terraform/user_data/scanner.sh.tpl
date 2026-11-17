#!/bin/bash
# "scanner" instance: generates three kinds of traffic on a schedule.
# Rendered by Terraform templatefile(); ${app_ip} is filled in at plan time.
set -euxo pipefail

dnf install -y nmap cronie
systemctl enable --now crond

cat > /etc/cron.d/flowlog-traffic <<CRON
# 1) Normal traffic: HTTP to the app every 5 min  -> ACCEPT records
*/5 * * * * root curl -s -o /dev/null --max-time 5 http://${app_ip}/

# 2) Port scan of the app's top 200 ports every hour -> mostly REJECT records
#    (only port 80 is allowed by the app's security group)
0 * * * * root nmap -Pn -T3 --top-ports 200 ${app_ip} > /dev/null 2>&1

# 3) Outbound to public sites every 15 min -> "external destination" records
*/15 * * * * root curl -s -o /dev/null --max-time 10 https://aws.amazon.com/
*/15 * * * * root curl -s -o /dev/null --max-time 10 https://www.wikipedia.org/
CRON

chmod 644 /etc/cron.d/flowlog-traffic
