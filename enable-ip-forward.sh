#!/bin/bash

iptables -P FORWARD ACCEPT
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p