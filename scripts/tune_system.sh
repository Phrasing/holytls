#!/bin/bash
# Copyright 2024 Chad-TLS Authors
# SPDX-License-Identifier: MIT
#
# Chad-TLS High-Concurrency System Tuning
# Run as root before stress testing for optimal performance.

set -e

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root: sudo $0"
    exit 1
fi

echo "=== Chad-TLS High-Concurrency System Tuning ==="

# File descriptor limits (system-wide)
echo "Setting file descriptor limits..."
sysctl -w fs.file-max=2097152

# Ephemeral port range (55k ports available)
echo "Expanding ephemeral port range..."
sysctl -w net.ipv4.ip_local_port_range="10000 65535"

# TCP socket memory (min/default/max in pages)
echo "Tuning TCP socket memory..."
sysctl -w net.ipv4.tcp_rmem="4096 87380 16777216"
sysctl -w net.ipv4.tcp_wmem="4096 65536 16777216"

# Core socket buffer limits
sysctl -w net.core.rmem_max=16777216
sysctl -w net.core.wmem_max=16777216
sysctl -w net.core.rmem_default=262144
sysctl -w net.core.wmem_default=262144

# TIME_WAIT handling
echo "Configuring TIME_WAIT handling..."
sysctl -w net.ipv4.tcp_tw_reuse=1
sysctl -w net.ipv4.tcp_fin_timeout=15

# SYN backlog for burst handling
echo "Increasing SYN backlog..."
sysctl -w net.ipv4.tcp_max_syn_backlog=4096
sysctl -w net.core.somaxconn=4096

# Connection tracking (if using iptables/nftables)
echo "Configuring connection tracking..."
sysctl -w net.netfilter.nf_conntrack_max=262144 2>/dev/null || true

# BBR congestion control (better throughput)
echo "Enabling BBR congestion control..."
if modprobe tcp_bbr 2>/dev/null; then
    sysctl -w net.ipv4.tcp_congestion_control=bbr 2>/dev/null || true
fi

# Reduce orphan socket overhead
sysctl -w net.ipv4.tcp_max_orphans=32768

# Enable TCP Fast Open (client + server)
sysctl -w net.ipv4.tcp_fastopen=3

# Increase netdev budget for high throughput
sysctl -w net.core.netdev_budget=600
sysctl -w net.core.netdev_budget_usecs=8000

# Set process ulimits (applies to current shell and children)
echo "Setting process ulimits..."
ulimit -n 100000 2>/dev/null || echo "  (ulimit -n requires pam_limits.conf for persistence)"

echo ""
echo "=== System Tuning Complete ==="
echo ""
echo "For persistent changes, add to /etc/sysctl.d/99-chad-tls.conf:"
echo "  fs.file-max = 2097152"
echo "  net.ipv4.ip_local_port_range = 10000 65535"
echo "  net.ipv4.tcp_rmem = 4096 87380 16777216"
echo "  net.ipv4.tcp_wmem = 4096 65536 16777216"
echo "  net.ipv4.tcp_tw_reuse = 1"
echo "  net.ipv4.tcp_fin_timeout = 15"
echo "  net.ipv4.tcp_max_syn_backlog = 4096"
echo "  net.core.somaxconn = 4096"
echo ""
echo "For ulimit persistence, add to /etc/security/limits.conf:"
echo "  * soft nofile 100000"
echo "  * hard nofile 100000"
echo ""
