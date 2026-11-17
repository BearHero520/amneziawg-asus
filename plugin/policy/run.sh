#!/bin/sh
# SPDX-License-Identifier: MIT
export PATH=/bin:/usr/bin:/sbin:/usr/sbin:/koolshare/bin
umask 077
root=/koolshare/amneziawg/policy
runtime=/tmp/amneziawg-asus/policy
mkdir -p "$runtime" || exit 1
. "$root/merlin.sh" || exit 1

get_router_ip() { nvram get lan_ipaddr; }

reload_dnsmasq() {
    service restart_dnsmasq
}

case "${1:-}" in
    prepare)
        setup_policy_data || { echo '未能建立分流地址集'; exit 1; }
        ;;
    fetch)
        SETTINGS="$AWG_DIR/fetch-settings"
        dl_clear_failed
        if ! download_all_geo >/dev/null 2>&1; then
            echo '有规则列表未能下载，已保留现有数据'
            exit 1
        fi
        ;;
    dns-on)
        if [ -s "$runtime/dnsmasq_tunnel.conf" ]; then
            dnsmasq --test --conf-file="$runtime/dnsmasq_tunnel.conf" || exit 1
        fi
        : > "$runtime/dns-active" || exit 1
        reload_dnsmasq || exit 1
        ;;
    dns-off)
        if [ -f "$runtime/dns-active" ]; then
            rm -f "$runtime/dns-active"
            reload_dnsmasq || { : > "$runtime/dns-active"; exit 1; }
        fi
        ;;
    dns-refresh)
        [ ! -f "$runtime/dns-active" ] || reload_dnsmasq
        ;;
    dns-fallback)
        mv "$runtime/dnsmasq_tunnel.conf" "$runtime/dnsmasq_tunnel.stopped" || exit 1
        if ! reload_dnsmasq; then
            mv "$runtime/dnsmasq_tunnel.stopped" "$runtime/dnsmasq_tunnel.conf"
            exit 1
        fi
        rm -f "$runtime/dnsmasq_tunnel.stopped"
        ;;
    check-dns)
        if iptables-save -t nat 2>/dev/null | grep -Eq -- '--dport 53 .*-(j|g) (REDIRECT|DNAT|DNSFILTER)' ||
           iptables-save -t mangle 2>/dev/null | grep -Eq -- '--dport 53 .*-(j|g) TPROXY'; then
            echo '已发现路由器上的 DNS 接管规则，请选沿用路由器 DNS'
            exit 1
        fi
        ;;
    analyze-start)
        if [ ! -r /proc/net/nf_conntrack ] && [ ! -r /proc/net/ip_conntrack ]; then
            echo '固件未提供连接跟踪统计'
            exit 1
        fi
        do_analyze_start
        ;;
    analyze-stop)
        do_analyze_stop
        ;;
    clear)
        if [ -f "$ANALYZE_FLAG" ] || [ -f "$ANALYZE_DNS_CONF" ]; then do_analyze_stop quiet; fi
        destroy_owned_sets || exit 1
        rm -f "$DNSMASQ_AWG_CONF" "$runtime/dnsmasq_tunnel.conf"
        ;;
    *) exit 2 ;;
esac
