#!/bin/sh
# SPDX-License-Identifier: MIT
umask 077
config="${1:-}"
[ -n "$config" ] && [ -w "$config" ] || exit 0
runtime=/tmp/amneziawg-asus/policy

add_conf() {
    [ -s "$1" ] || return 0
    grep -qxF "conf-file=$1" "$config" || printf '\nconf-file=%s\n' "$1" >> "$config"
}

if [ -f "$runtime/dns-active" ]; then
    add_conf "$runtime/dnsmasq_awg.conf"
    if [ -s "$runtime/dnsmasq_tunnel.conf" ]; then
        sed -i '/^servers-file=/d; /^resolv-file=/d' "$config"
        add_conf "$runtime/dnsmasq_tunnel.conf"
    fi
fi
add_conf "$runtime/dnsmasq_analyze.conf"
