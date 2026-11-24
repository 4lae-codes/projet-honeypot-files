#!/bin/bash
# Ajoute les redirections 22->2222 et 23->2223 dans UFW (idempotent)
grep -q 'REDIRECT --to-port 2222' /etc/ufw/before.rules && { echo "deja present"; exit 0; }
cp /etc/ufw/before.rules /etc/ufw/before.rules.bak
sed -i '1i *nat\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222\n-A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223\nCOMMIT\n' /etc/ufw/before.rules
ufw reload
