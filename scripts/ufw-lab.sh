#!/bin/bash
# usage: ./ufw-lab.sh 172.20.10.9
KALI=$1; PC=$2
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw limit from $PC to any port 22022 proto tcp comment 'admin SSH'
for ip in $KALI $PC; do 
 for p in 21 80 3306 2222 2223; do 
  ufw allow from $ip to any port $p proto tcp comment "honeypot $p"
 done
done
ufw default deny outgoing
ufw allow out 53
ufw allow out 67/udp
ufw allow out 123/udp
ufw allow out 80/tcp
ufw allow out 443/tcp
ufw --force enable
ufw status numbered
