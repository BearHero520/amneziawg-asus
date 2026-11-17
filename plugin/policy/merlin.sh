#!/bin/sh
# SPDX-License-Identifier: MIT
# Geo list and traffic analysis helpers adapted from asuswrt-merlin-amneziawg v1.5.30.
# See the upstream copyright in licenses/merlin-addon-MIT.txt.

AWG_DIR="/tmp/amneziawg-asus/policy"
ANALYZE_MAX_SECONDS=600
ANALYZE_FILE="/tmp/amneziawg-asus/policy/awg_analyze.htm"
ANALYZE_FLAG="/tmp/amneziawg-asus/policy/.awg_analyze_run"
ANALYZE_PID="/tmp/amneziawg-asus/policy/.awg_analyze.pid"
ANALYZE_STARTED="/tmp/amneziawg-asus/policy/.awg_analyze_started"
ANALYZE_ENTRIES="/tmp/amneziawg-asus/policy/.awg_analyze_entries"
ANALYZE_SEEN="/tmp/amneziawg-asus/policy/.awg_analyze_seen"
ANALYZE_MAP="/tmp/amneziawg-asus/policy/.awg_analyze_map"
ANALYZE_DNS_LOG="/tmp/amneziawg-asus/policy/awg_analyze_dns.log"
ANALYZE_DNS_CONF="$AWG_DIR/dnsmasq_analyze.conf" # temp dnsmasq snippet enabling query logging
ANALYZE_MAX_ENTRIES=200
OWNED_SETS="/tmp/amneziawg-asus/policy/.awg_owned_sets"
SETTINGS="/tmp/amneziawg-asus/policy/settings"
GEO_DIR="/tmp/amneziawg-asus/policy/geo"
IPSET_NAME="awgp_dst"
IPSET_MAXELEM=262144
DNSMASQ_AWG_CONF="$AWG_DIR/dnsmasq_awg.conf"
PRERSLV_STATE="/tmp/amneziawg-asus/policy/.awg_preresolve_state"
PRERSLV_EEX="/tmp/amneziawg-asus/policy/.awg_preresolve_eex"
PRERSLV_RETRY="/tmp/amneziawg-asus/policy/.awg_preresolve_retry"
GEOSET_GEN="/tmp/amneziawg-asus/policy/.awg_geoset_gen"
GEOSTATIC_SIG="/tmp/amneziawg-asus/policy/.awg_geostatic_sig"
GEODYN_STASH="/tmp/amneziawg-asus/policy/.awg_geodyn_stash"
GEODYN_BORN="/tmp/amneziawg-asus/policy/.awg_geodyn_born"
GEODYN_STASH_TTL=3600
GEODYN_STASH_MAX=30000
SCRIPT_NAME="amneziawg-policy"
V2FLY_GEOIP_BASE="https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text"

AWG_IPSET_BIN=""; AWG_IPSET_LIB=""

_awg_try_ipset(){   # $1=binary  $2=libdir (optional)
    [ -x "$1" ] || return 1
    if [ -n "$2" ]; then LD_LIBRARY_PATH="$2${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$1" version >/dev/null 2>&1
    else "$1" version >/dev/null 2>&1; fi
}
if   _awg_try_ipset /usr/sbin/ipset;          then AWG_IPSET_BIN=/usr/sbin/ipset
elif _awg_try_ipset /sbin/ipset;              then AWG_IPSET_BIN=/sbin/ipset
elif _awg_try_ipset /opt/sbin/ipset /opt/lib; then AWG_IPSET_BIN=/opt/sbin/ipset; AWG_IPSET_LIB=/opt/lib
fi
ipset(){
    [ -n "$AWG_IPSET_BIN" ] || return 127
    if [ -z "$AWG_IPSET_LIB" ]; then
        "$AWG_IPSET_BIN" "$@"
    else
        LD_LIBRARY_PATH="$AWG_IPSET_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" "$AWG_IPSET_BIN" "$@"
    fi
}

log_msg(){
    logger -t "$SCRIPT_NAME" "$1"
}

get_setting(){
    LC_ALL=C awk -v key="$1" 'index($0, key " ") == 1 {print substr($0, length(key) + 2); exit}' "$SETTINGS" 2>/dev/null
}

setting_is_cut(){
    case "${#2}" in 2999|3000|3001) return 0 ;; esac
    [ "${#2}" -eq $((3038 - ${#1})) ]
}

b64d_init(){
    [ -n "$AWG_B64D" ] && return 0
    if [ "$(echo aGk= | base64 -d 2>/dev/null)" = hi ]; then AWG_B64D=base64
    elif [ "$(echo aGk= | openssl base64 -d -A 2>/dev/null)" = hi ]; then AWG_B64D=openssl
    else AWG_B64D=awk; fi
}

b64d(){
    b64d_init
    LC_ALL=C awk '{ gsub(/[^A-Za-z0-9+\/=]/, ""); s = s $0 }
        END { p = index(s, "="); if (p > 0) s = substr(s, 1, p - 1)
              n = length(s); r = n % 4
              if (r == 1) s = substr(s, 1, n - 1); else if (r == 2) s = s "=="; else if (r == 3) s = s "="
              if (s != "") print s }' |
    case "$AWG_B64D" in
        base64)  base64 -d 2>/dev/null ;;
        openssl) openssl base64 -d -A 2>/dev/null ;;
        *) LC_ALL=C awk '
            BEGIN { a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
                    for (i = 0; i < 64; i++) v[substr(a, i + 1, 1)] = i }
            { s = s $0 }
            END { n = length(s)
                  for (i = 1; i + 3 <= n; i += 4) {
                      c3 = substr(s, i + 2, 1); c4 = substr(s, i + 3, 1)
                      x = v[substr(s, i, 1)] * 262144 + v[substr(s, i + 1, 1)] * 4096 + v[c3] * 64 + v[c4]
                      printf "%c", int(x / 65536)
                      if (c3 != "=") printf "%c", int(x / 256) % 256
                      if (c4 != "=") printf "%c", x % 256
                  } }' ;;
    esac
}

url_key(){
    local h
    h=$(echo "$1" | sha256sum 2>/dev/null | awk '{print $1}')
    [ -n "$h" ] || h=$(echo "$1" | openssl dgst -sha256 2>/dev/null | awk '{print $NF}')
    echo "$h" | cut -c1-16
}

geo_ids(){
    local raw out id
    raw=$(get_setting awg_geo_policies)
    [ -z "$raw" ] && { echo 1; return; }
    out=$(printf '%s\n' "$raw" | tr ';' '\n' | while IFS=: read -r id _; do
        id=$(printf '%s' "$id" | tr -cd '0-9')
        [ -n "$id" ] && printf '%s ' "$id"
    done)
    out=$(echo $out)
    [ -z "$out" ] && out=1
    echo "$out"
}

geo_key(){
    local id="$1" suf="$2"
    if [ "$suf" = antifilter_lists ]; then
        [ "$id" = 1 ] && echo "awg_antifilter_lists" || echo "awg_antifilter_${id}_lists"
    else
        [ "$id" = 1 ] && echo "awg_geo_${suf}" || echo "awg_geo_${id}_${suf}"
    fi
}

geo_ipset(){
    [ "$1" = 1 ] && echo "$IPSET_NAME" || echo "${IPSET_NAME}$1"
}

geo_mode(){
    [ "$(get_setting "$(geo_key "$1" mode)")" = direct ] && echo direct || echo vpn
}

geo_exc_ipset(){
    echo "$(geo_ipset "$1")_x"
}

policy_has_exc(){
    local id="$1"
    [ -n "$(get_setting "$(geo_key "$id" exc_domains)")$(get_setting "$(geo_key "$id" exc_ips)")$(get_setting "$(geo_key "$id" exc_files)")$(get_setting "$(geo_key "$id" exc_urls)")" ]
}

geo_union_geoip(){ local id; for id in $(geo_ids); do selected_geoip "$id"; done | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' '; }

geo_union_antifilter(){ local id; for id in $(geo_ids); do selected_antifilter "$id"; done | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' '; }

geo_union_geosite(){ local id; for id in $(geo_ids); do get_setting "$(geo_key "$id" v2fly)" | tr ',' ' '; done | tr ' ' '\n' | sed 's/[^A-Za-z0-9_.!-]//g' | grep -v '^$' | sort -u | tr '\n' ' '; }

policy_urls(){
    local k v
    if [ "${2:-inc}" = exc ]; then k=$(geo_key "$1" exc_urls); else k=$(geo_key "$1" custom_urls); fi
    v=$(get_setting "$k"); [ -n "$v" ] || return 0
    printf '%s' "$v" | b64d
    printf '\n'
}

geo_union_urls(){
    local id
    b64d_init
    for id in $(geo_ids); do
        policy_urls "$id" inc
        policy_urls "$id" exc
    done | tr ' \t\r' '\n\n\n' | grep -E '^https?://' | sort -u
}

policy_url_keys(){
    local id="$1" kind="${2:-inc}" u
    b64d_init
    policy_urls "$id" "$kind" | tr ' \t\r' '\n\n\n' | grep -E '^https?://' | while read -r u; do
        url_key "$u"
    done
}

register_owned_set(){
    grep -qxF "$1" "$OWNED_SETS" 2>/dev/null || echo "$1" >> "$OWNED_SETS"
}

geoset_gen_bump(){
    local _g="" _x
    { read -r _g < /proc/sys/kernel/random/uuid; } 2>/dev/null
    [ -n "$_g" ] || { { read -r _g _x < /proc/uptime; } 2>/dev/null; _g="${_g}.$$"; }
    echo "$_g" > "$GEOSET_GEN" 2>/dev/null
    rm -f "$PRERSLV_STATE" "$PRERSLV_EEX" "$PRERSLV_RETRY" "$PRERSLV_RETRY.strike"
}

geo_preresolve_quiesce(){
    local _ph _x _i=0
    while [ $_i -lt 20 ]; do
        [ -d /tmp/amneziawg-asus/policy/.awg_dnsreload ] || return 0
        _ph=""; { read -r _ph _x < /tmp/amneziawg-asus/policy/.awg_dnsreload/beat; } 2>/dev/null
        [ "$_ph" = preresolve ] || return 0
        true 2>/dev/null > /tmp/amneziawg-asus/policy/.awg_dnsreload/preempt
        sleep 1; _i=$((_i + 1))
    done
}

geo_static_sig(){
    local id k f _inputs _sig
    _inputs=$(
        for id in $(geo_ids); do
            for k in v2fly_ip antifilter_lists custom_ips custom_files custom_urls exc_ips exc_files exc_urls; do
                echo "$id $k $(get_setting "$(geo_key "$id" "$k")")"
            done
        done
        # setup_firewall prunes the shared pool first. Hash its downloaded CIDRs once each:
        # an update of the SAME URL/list can remove a permanent /32 without changing a setting.
        # Pasted-file CIDRs are regenerated later; their source settings are already above.
        for f in "$GEO_DIR"/geoip/v2fly_*.cidr "$GEO_DIR"/geoip/userurl_*.cidr "$GEO_DIR"/antifilter/af_*.cidr; do
            [ -f "$f" ] || continue
            md5sum "$f" 2>/dev/null || exit 1
        done
        true
    ) || return 1
    _sig=$(printf '%s\n' "$_inputs" | md5sum 2>/dev/null) || return 1
    _sig=${_sig%% *}
    case "$_sig" in ''|*[!0-9a-f]*) return 1 ;; esac
    [ ${#_sig} -eq 32 ] || return 1
    echo "$_sig"
}

geo_swap_window_close(){
    local _why="" _ph _x _old
    [ "${1%%|*}" = "$(cat "$GEOSET_GEN" 2>/dev/null)" ] || _why="-"
    if [ -z "$_why" ]; then
        _ph=""; { read -r _ph _x < /tmp/amneziawg-asus/policy/.awg_dnsreload/beat; } 2>/dev/null
        if [ "${1#*|}" != "$(cat "$PRERSLV_STATE" 2>/dev/null)" ] \
           || { [ -d /tmp/amneziawg-asus/policy/.awg_dnsreload ] && [ "$_ph" = preresolve ]; }; then
            _why="a geo pre-resolve was feeding while the sets were rebuilt"
        fi
    fi
    _old=$(cat "$GEOSTATIC_SIG" 2>/dev/null)
    if [ -z "$2" ]; then
        rm -f "$GEOSTATIC_SIG"
        [ -z "$_why" ] && _why="the static geo sources could not be fingerprinted"
    elif [ "$2" != "$_old" ]; then
        echo "$2" > "$GEOSTATIC_SIG" 2>/dev/null
        [ -z "$_why" ] && _why="the static geo sources changed"
    fi
    case "$_why" in
        ''|-) ;;
        *) geoset_gen_bump
           log_msg "Geo domain pre-resolve: will re-feed from the start at the next reload — $_why" ;;
    esac
    return 0
}

destroy_owned_sets(){
    local s failed="$OWNED_SETS.failed"
    # Park what the sets learned from DNS before they go (see geodyn_stash_save).
    geodyn_stash_save
    geoset_gen_bump
    [ -f "$OWNED_SETS" ] || return 0
    : > "$failed" || return 1
    while read -r s; do
        [ -z "$s" ] && continue
        if ipset list "$s" -t >/dev/null 2>&1 && ! ipset destroy "$s" 2>/dev/null; then
            printf '%s\n' "$s" >> "$failed"
        fi
    done < "$OWNED_SETS"
    mv "$failed" "$OWNED_SETS"
    [ ! -s "$OWNED_SETS" ]
}

geo_set_ours(){
    grep -qxF "$2" "$OWNED_SETS" 2>/dev/null
}

geo_policy_of_ref(){
    case "$1" in
        vpn_geo)   echo 1 ;;
        vpn_geo_*) echo "${1#vpn_geo_}" ;;
        *)         echo 1 ;;
    esac
}

geo_maxelem(){
    local total="$1" n per floor=16384
    n=$(geo_ids | wc -w | tr -d ' '); [ -z "$n" ] && n=1
    [ "$n" -lt 1 ] 2>/dev/null && n=1
    per=$((total / n))
    # Apply the comfort floor ONLY while it doesn't push the SUM (n*floor) past the budget —
    # otherwise (many policies on a low-RAM box) it would defeat the OOM cap it sits inside.
    [ "$per" -lt "$floor" ] && [ $((floor * n)) -le "$total" ] && per=$floor
    [ "$per" -lt 1 ] && per=1
    echo "$per"
}

prune_orphan_policies(){
    local active=" $(geo_ids) " id f
    # custom-domains files: custom_p<id>.txt (include) + custom_exc_p<id>.txt (exclusions)
    for f in "$GEO_DIR"/domains/custom_p*.txt; do
        [ -f "$f" ] || continue
        id=$(basename "$f" .txt); id=${id#custom_p}
        case "$active" in *" $id "*) ;; *) rm -f "$f" ;; esac
    done
    for f in "$GEO_DIR"/domains/custom_exc_p*.txt; do
        [ -f "$f" ] || continue
        id=$(basename "$f" .txt); id=${id#custom_exc_p}
        case "$active" in *" $id "*) ;; *) rm -f "$f" ;; esac
    done
    # pasted-file outputs: usercustom_p<id>_* (include) + excustom_p<id>_* (exclusions)
    for f in "$GEO_DIR"/domains/usercustom_p*.txt "$GEO_DIR"/geoip/usercustom_p*.cidr; do
        [ -f "$f" ] || continue
        id=$(basename "$f"); id=${id#usercustom_p}; id=${id%%_*}
        case "$active" in *" $id "*) ;; *) rm -f "$f" ;; esac
    done
    for f in "$GEO_DIR"/domains/excustom_p*.txt "$GEO_DIR"/geoip/excustom_p*.cidr; do
        [ -f "$f" ] || continue
        id=$(basename "$f"); id=${id#excustom_p}; id=${id%%_*}
        case "$active" in *" $id "*) ;; *) rm -f "$f" ;; esac
    done
}

fetch_with_mirrors(){
    local url="$1" out="$2" timeout="${3:-60}" mirror
    if curl -gfsL --proto '=http,https' --proto-redir '=http,https' --connect-timeout 6 --max-time "$timeout" "$url" -o "$out" 2>/dev/null && [ -s "$out" ]; then
        return 0
    fi
    [ "$4" != custom ] || return 1
    case "$url" in
        "$V2FLY_GEOIP_BASE"/*)
            mirror="https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/text/${url##*/}"
            curl -gfsL --proto '=https' --proto-redir '=https' --connect-timeout 6 --max-time "$timeout" "$mirror" -o "$out" 2>/dev/null && [ -s "$out" ]
            ;;
        *) return 1 ;;
    esac
}

dl_fail_stamp(){ echo "$GEO_DIR/.dlfail_$1"; }

dl_recently_failed(){
    local f _now _then
    f=$(dl_fail_stamp "$1")
    [ -f "$f" ] || return 1
    _now=$(date +%s); _then=$(cat "$f" 2>/dev/null)
    case "$_then" in ''|*[!0-9]*) return 1 ;; esac
    [ $((_now - _then)) -lt 21600 ]
}

dl_mark_failed(){ mkdir -p "$GEO_DIR" 2>/dev/null; date +%s > "$(dl_fail_stamp "$1")" 2>/dev/null; }

dl_clear_failed(){ rm -f "$GEO_DIR"/.dlfail_* 2>/dev/null; }

download_geoip_service(){
    local svc="$1" tmp
    mkdir -p "$GEO_DIR/geoip"
    tmp="$GEO_DIR/geoip/.dl_${svc}.tmp"
    if fetch_with_mirrors "${V2FLY_GEOIP_BASE}/${svc}.txt" "$tmp" 30 &&
       grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$tmp" > "$tmp.ip"; then
        mv "$tmp.ip" "$GEO_DIR/geoip/v2fly_${svc}.cidr" || return 1
        rm -f "$tmp"
        return 0
    fi
    rm -f "$tmp" "$tmp.ip"
    dl_mark_failed "geoip_${svc}"
    return 1
}

selected_geoip(){
    local id="${1:-1}"
    echo $(get_setting "$(geo_key "$id" v2fly_ip)" | tr ',' ' ' | tr 'A-Z' 'a-z')
}

prune_geoip(){
    local sel=" $(geo_union_geoip) " f fsvc
    for f in "$GEO_DIR"/geoip/v2fly_*.cidr; do
        [ -f "$f" ] || continue
        fsvc=$(basename "$f" .cidr); fsvc=${fsvc#v2fly_}
        case "$sel" in *" $fsvc "*) ;; *) rm -f "$f" ;; esac
    done
}

antifilter_url(){
    case "$1" in
        allyouneed)        echo "https://antifilter.download/list/allyouneed.lst" ;;
        ipsum)             echo "https://antifilter.download/list/ipsum.lst" ;;
        subnet)            echo "https://antifilter.download/list/subnet.lst" ;;
        ip)                echo "https://antifilter.download/list/ip.lst" ;;
        ipresolve)         echo "https://antifilter.download/list/ipresolve.lst" ;;
        community)         echo "https://community.antifilter.download/list/community.lst" ;;
        community_domains) echo "https://community.antifilter.download/list/domains.lst" ;;
    esac
}

antifilter_is_domain(){ [ "$1" = "community_domains" ]; }

selected_antifilter(){
    local id="${1:-1}"
    echo $(get_setting "$(geo_key "$id" antifilter_lists)" | tr ',' ' ' | tr 'A-Z' 'a-z')
}

download_antifilter_list(){
    local key="$1" url out tmp pattern
    url=$(antifilter_url "$key"); [ -n "$url" ] || return 1
    if antifilter_is_domain "$key"; then
        out="$GEO_DIR/domains/antifilter_${key}.lst"
        pattern='^[a-zA-Z0-9_-]+\.[a-zA-Z0-9]'
    else
        out="$GEO_DIR/antifilter/af_${key}.cidr"
        pattern='^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
    fi
    mkdir -p "${out%/*}"
    tmp="$out.download"
    if fetch_with_mirrors "$url" "$tmp" 60 && grep -E "$pattern" "$tmp" > "$tmp.list"; then
        mv "$tmp.list" "$out" || return 1
        rm -f "$tmp"
        return 0
    fi
    rm -f "$tmp" "$tmp.list"
    dl_mark_failed "af_${key}"
    return 1
}

prune_antifilter(){
    local sel=" $(geo_union_antifilter) " f fkey
    for f in "$GEO_DIR"/antifilter/af_*.cidr; do
        [ -f "$f" ] || continue
        fkey=$(basename "$f" .cidr); fkey=${fkey#af_}
        case "$sel" in *" $fkey "*) ;; *) rm -f "$f" ;; esac
    done
    for f in "$GEO_DIR"/domains/antifilter_*.lst; do
        [ -f "$f" ] || continue
        fkey=$(basename "$f" .lst); fkey=${fkey#antifilter_}
        case "$sel" in *" $fkey "*) ;; *) rm -f "$f" ;; esac
    done
}

download_geosite(){
    mkdir -p "$GEO_DIR/domains"
    log_msg "Downloading v2fly domain database..."
    local tmp_yml="$GEO_DIR/v2fly_all.yml.tmp"
    # Validate the body before the swap: a flaky mirror (ghproxy) can return HTTP 200 with an
    # HTML/JSON error page that curl -f accepts and [ -s ] passes — an unconditional mv would
    # then overwrite a good DB with garbage and silently empty every GeoSite category. Require
    # at least one real category marker (mirrors the GeoIP/antifilter validators); otherwise
    # keep the existing v2fly_all.yml.
    if fetch_with_mirrors "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat_plain.yml" "$tmp_yml" 120 && [ -s "$tmp_yml" ] && grep -q '^ *- name: ' "$tmp_yml"; then
        mv "$tmp_yml" "$GEO_DIR/v2fly_all.yml"
        # 2026-07: upstream switched to quoting the name scalars (`- name: "xai"`) — strip the
        # quotes here, or the UI autocomplete offers `"xai"` and users save quote-polluted
        # category lists into custom_settings (field-seen; harmless to the sanitized read
        # paths but it pollutes settings and eats the value-length budget).
        grep '^ *- name: ' "$GEO_DIR/v2fly_all.yml" | sed 's/.*- name: *//; s/^["'\'' ]*//; s/["'\'' ]*$//' | grep -v '^$' | sort -u > "$GEO_DIR/v2fly_categories.txt"
        cp "$GEO_DIR/v2fly_categories.txt" /tmp/amneziawg-asus/policy/v2fly_categories.htm 2>/dev/null
        log_msg "GeoSite: $(wc -l < "$GEO_DIR/v2fly_categories.txt") categories downloaded"
    else
        rm -f "$tmp_yml"
        log_msg "WARNING: v2fly domain download failed or invalid (kept existing DB)"
        return 1
    fi
}

prune_custom_urls(){
    local sel f fkey u
    sel=" $(geo_union_urls | while read -r u; do u=$(echo "$u" | tr -d ' \r'); [ -z "$u" ] && continue; url_key "$u"; done | tr '\n' ' ') "
    for f in "$GEO_DIR"/domains/userurl_*.txt "$GEO_DIR"/geoip/userurl_*.cidr; do
        [ -f "$f" ] || continue
        fkey=$(basename "$f"); fkey=${fkey#userurl_}; fkey=${fkey%.txt}; fkey=${fkey%.cidr}
        case "$sel" in *" $fkey "*) ;; *) rm -f "$f" ;; esac
    done
}

download_custom_urls(){
    local mode="$1" urls url key tmp prev
    urls=$(geo_union_urls)
    [ -n "$urls" ] || return 0
    mkdir -p "$GEO_DIR/domains" "$GEO_DIR/geoip"
    printf '%s\n' "$urls" | while read -r url; do
        url=$(echo "$url" | tr -d ' \r')
        [ -z "$url" ] && continue
        case "$url" in http://*|https://*) ;; *) continue ;; esac
        key=$(url_key "$url")
        if [ -z "$key" ]; then
            log_msg "Custom URL skipped: neither sha256sum nor openssl is available to name its files"
            continue
        fi
        tmp="$GEO_DIR/.url_${key}.tmp"
        rm -f "$tmp.d" "$tmp.c"
        prev="No previous copy to fall back on"
        { [ -f "$GEO_DIR/domains/userurl_${key}.txt" ] || [ -f "$GEO_DIR/geoip/userurl_${key}.cidr" ]; } && prev="Previous copy kept"
        # "missing" (ensure_geo after an Apply): only URLs with no copy yet and not in their 6h
        # back-off — log_url_backoff has just told the user they are paused.
        if [ "$mode" = missing ]; then
            [ "$prev" = "Previous copy kept" ] && continue
            dl_recently_failed "url_${key}" && continue
        fi
        if fetch_with_mirrors "$url" "$tmp" 60 custom && [ -s "$tmp" ]; then
            if awk 'NR <= 30' "$tmp" | grep -qiE '<(!doctype|html|head|body)[ >]'; then
                dl_mark_failed "url_${key}"
                log_msg "Custom URL rejected: returned an HTML page, not a list — use the direct link to the raw file (for GitHub: raw.githubusercontent.com/…, not github.com/…/blob/…). $prev; retries paused for 6h ('Update now' retries at once)"
            else
                # shellcheck disable=SC2046
                set -- $(classify_user_list "$tmp" "$tmp.d" "$tmp.c")
                # Usable = IPv4 + real domains; bare whole-TLD words ($5) alone don't make a list
                # (a plain-text "Page not found" body must not replace a good copy).
                if [ $((${1:-0} + ${2:-0} - ${5:-0})) -gt 0 ]; then
                    rm -f "$GEO_DIR/domains/userurl_${key}.txt" "$GEO_DIR/geoip/userurl_${key}.cidr"
                    [ -f "$tmp.d" ] && mv "$tmp.d" "$GEO_DIR/domains/userurl_${key}.txt"
                    [ -f "$tmp.c" ] && mv "$tmp.c" "$GEO_DIR/geoip/userurl_${key}.cidr"
                    rm -f "$(dl_fail_stamp "url_${key}")" 2>/dev/null
                    log_msg "Custom URL: $url ($key): $(user_list_summary "$@")"
                else
                    dl_mark_failed "url_${key}"
                    log_msg "Custom URL rejected: has no usable entries: $(user_list_summary "$@") — expected one IPv4/CIDR or domain per line. $prev; retries paused for 6h ('Update now' retries at once)"
                fi
            fi
        else
            dl_mark_failed "url_${key}"
            log_msg "Custom URL download failed: ($(echo "$prev" | tr 'PN' 'pn'); retries paused for 6h — 'Update now' retries at once)"
        fi
        rm -f "$tmp" "$tmp.d" "$tmp.c"
    done
}

user_list_summary(){
    local s="${1:-0} IPv4, ${2:-0} domains"
    [ "${5:-0}" -gt 0 ] 2>/dev/null && s="$s (${5} of them whole-TLD rules like 'ru')"
    [ "${3:-0}" -gt 0 ] 2>/dev/null && s="$s, ${3} IPv6 skipped (only IPv4 is routed)"
    [ "${4:-0}" -gt 0 ] 2>/dev/null && s="$s, ${4} unrecognized entries skipped"
    echo "$s"
}

download_all_geo(){
    b64d_init
    mkdir -p "$GEO_DIR/geoip" "$GEO_DIR/domains" "$GEO_DIR/antifilter"
    log_msg "Downloading all geo databases..."

    local failed=0
    if [ -n "$(geo_union_geosite)" ]; then download_geosite || failed=1; fi

    # GeoIP service lists — the UNION across all policies, one download per unique service.
    local geoip_list count=0 total=0 ok=0 svc af_key
    geoip_list=$(geo_union_geoip)
    for svc in $geoip_list; do total=$((total + 1)); done
    for svc in $geoip_list; do
        count=$((count + 1))
        log_msg "GeoIP: downloading $svc ($count/$total)..."
        if download_geoip_service "$svc"; then ok=$((ok + 1)); else log_msg "WARNING: GeoIP $svc failed"; failed=1; fi
    done
    log_msg "GeoIP: $ok/$total service lists downloaded"

    # Antifilter lists — the union, one download per unique list.
    for af_key in $(geo_union_antifilter); do
        log_msg "Antifilter: downloading $af_key..."
        download_antifilter_list "$af_key" || { log_msg "WARNING: Antifilter $af_key failed"; failed=1; }
    done

    # GeoCustom URL sources — the union, one download per unique URL.
    download_custom_urls

    # Save timestamp
    date +%s > "$GEO_DIR/.last_update"
    ls "$GEO_DIR"/.dlfail_* >/dev/null 2>&1 && failed=1
    return "$failed"
}

ipv4_restore_lines(){
    LC_ALL=C awk -v s="$1" '
        function ip4(t,   a) {
            if (t !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) return ""
            split(t, a, ".")
            if (a[1] + 0 > 255 || a[2] + 0 > 255 || a[3] + 0 > 255 || a[4] + 0 > 255) return ""
            return (a[1] + 0) "." (a[2] + 0) "." (a[3] + 0) "." (a[4] + 0)
        }
        function num(t,   a) { split(t, a, "."); return ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4] }
        function dq(n) { return int(n / 16777216) % 256 "." int(n / 65536) % 256 "." int(n / 256) % 256 "." n % 256 }
        # An a-b range is emitted as its minimal CIDR cover (<= 62 lines, widest /1): the kernel
        # rejects or mis-walks wide ranges in hash:net ("covers the whole address space", "Hash is
        # full" for spans >= 2^31) and that one line aborted the whole restore.
        function range(x, y,   lo, hi, bits, blk) {
            lo = num(x); hi = num(y)
            while (lo <= hi) {
                bits = 0; blk = 1
                while (bits < 31 && lo % (blk * 2) == 0 && lo + blk * 2 - 1 <= hi) { blk *= 2; bits++ }
                print "add " s " " dq(lo) "/" (32 - bits) " timeout 0"
                lo += blk
            }
        }
        function emit(t,   a, p, x, y) {
            if (t ~ /^[0-9.]+-[0-9.]+$/) {
                split(t, a, "-"); x = ip4(a[1]); y = ip4(a[2])
                if (x != "" && y != "" && num(x) <= num(y)) range(x, y)
                return
            }
            p = split(t, a, "/"); if (p > 2) return
            x = ip4(a[1]); if (x == "") return
            if (p == 2) { if (a[2] !~ /^[0-9]+$/ || a[2] + 0 < 1 || a[2] + 0 > 32) return; x = x "/" (a[2] + 0) }
            print "add " s " " x " timeout 0"
        }
        /^(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])(\/([1-9]|[12][0-9]|3[0-2]))?$/ {
            print "add " s " " $0 " timeout 0"; next
        }
        {
            gsub(/\r/, ""); sub(/#.*/, "")
            n = split($0, t, /[ \t,;|]+/)
            for (i = 1; i <= n; i++)
                if (t[i] ~ /^[0-9][0-9.\/-]*$/) emit(t[i])
        }'
}

ipset_load_file(){
    local file="$1"
    local setname="$2"
    [ ! -f "$file" ] && return
    ipv4_restore_lines "$setname" < "$file" | ipset restore -! 2>/dev/null
}

classify_user_list(){
    local infile="$1" dom_out="$2" cidr_out="$3"
    [ -f "$infile" ] || { echo "0 0 0 0 0"; return 0; }
    LC_ALL=C awk -v dout="$dom_out" -v cout="$cidr_out" -v bom="$(printf '\357\273\277')" '
        function v4ok(t,   a, p) {
            p = split(t, a, /[.\/]/)
            if (p < 4 || p > 5 || t !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/) return 0
            if (a[1] + 0 > 255 || a[2] + 0 > 255 || a[3] + 0 > 255 || a[4] + 0 > 255) return 0
            if (p == 5 && (a[5] + 0 < 1 || a[5] + 0 > 32)) return 0
            return 1
        }
        function num(t,   a) { split(t, a, "."); return ((a[1] * 256 + a[2]) * 256 + a[3]) * 256 + a[4] }
        NR == 1 && index($0, bom) == 1 { $0 = substr($0, length(bom) + 1) }
        {
            gsub(/\r/, ""); sub(/#.*/, ""); sub(/^[ \t]*(;|\/\/|!).*/, "")
            n = split($0, tok, /[ \t,;|]+/); nt = 0
            for (i = 1; i <= n; i++) if (tok[i] != "") nt++
            for (i = 1; i <= n; i++) {
                t = tolower(tok[i]); q = (t ~ /["'\''`]/ || index(t, "[") || index(t, "]") || index(t, "{") || index(t, "}"))
                gsub(/["'\''`]/, "", t)
                gsub(/\[/, "", t); gsub(/\]/, "", t); gsub(/\{/, "", t); gsub(/\}/, "", t)
                if (t == "") continue
                if (t ~ /^(domain|full):/) sub(/^(domain|full):/, "", t)
                else if (t ~ /^(regexp|keyword|include|geosite|geoip|ext):/) { nbad++; continue }
                else if (t ~ /^[a-z][a-z0-9+.-]*:\/\//) {
                    sub(/^[a-z][a-z0-9+.-]*:\/\//, "", t); sub(/[\/?#].*$/, "", t); sub(/^.*@/, "", t)
                }
                if (t ~ /^[^:]+:[0-9]+$/) sub(/:[0-9]+$/, "", t)
                if (t ~ /^[0-9.]+-[0-9.]+$/) {
                    split(t, rg, "-")
                    if (v4ok(rg[1]) && v4ok(rg[2]) && num(rg[1]) <= num(rg[2])) { print t > cout; nv4++ } else nbad++
                    continue
                }
                if (t ~ /^[0-9.\/]+$/) { if (v4ok(t)) { print t > cout; nv4++ } else nbad++; continue }
                if (t ~ /:/) { if (t ~ /^[0-9a-f:.\/]+$/ && t ~ /:.*:/) nv6++; else nbad++; continue }
                sub(/^(\*|\+)?\./, "", t); sub(/\.$/, "", t)
                if (length(t) > 253 || t ~ /[^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.][^.]/) { nbad++; continue }
                lab = t; sub(/^.*\./, "", lab)
                if (t ~ /^[a-z0-9_-]+(\.[a-z0-9_-]+)+$/ && lab ~ /[a-z]/) { print t > dout; ndom++ }
                else if (nt == 1 && !q && (t ~ /^[a-z][a-z]+$/ || t ~ /^xn--[a-z0-9-]+$/)) { print t > dout; ndom++; ntld++ }
                else nbad++
            }
        }
        END { printf "%d %d %d %d %d\n", nv4, ndom, nv6, nbad, ntld }' "$infile"
}

apply_custom_geo(){
    local id="${1:-1}" kind="${2:-inc}" key pfx
    if [ "$kind" = exc ]; then key=exc_files; pfx="excustom_p${id}_"; else key=custom_files; pfx="usercustom_p${id}_"; fi
    rm -f "$GEO_DIR"/domains/${pfx}*.txt "$GEO_DIR"/geoip/${pfx}*.cidr 2>/dev/null
    local blob
    blob=$(get_setting "$(geo_key "$id" "$key")")
    [ -z "$blob" ] && return 0
    b64d_init
    mkdir -p "$GEO_DIR/domains" "$GEO_DIR/geoip"
    # A cut value (setting_is_cut: the firmware's own truncation fingerprints) lost the tail of its
    # LAST file, usually mid-line (the page now refuses to save over 2900). That half-line must not
    # load: a /24 cut to "/2" is a VALID CIDR routing a quarter of IPv4. If the cut fell inside the
    # NEXT file's name, that whole file is gone — say so instead of skipping it silently.
    local trunc=0 chan="" prev="" tailcut=0
    setting_is_cut "$(geo_key "$id" "$key")" "$blob" && trunc=1
    # Cut exactly after a ';' — the last file is intact and the NEXT one is gone entirely (IFS
    # splitting drops the trailing empty field, so it must not be mistaken for a cut last file).
    [ "$trunc" = 1 ] && case "$blob" in *';'|*'=') tailcut=1; trunc=0 ;; esac
    [ "$kind" = exc ] && chan=", exclusions"
    local oldifs="$IFS" entry name b64 tmp base n seen=" " idx=0 last=0 cnt
    IFS=';'; set -f
    # shellcheck disable=SC2086
    set -- $blob
    set +f; IFS="$oldifs"
    for entry in "$@"; do idx=$((idx + 1)); [ -n "$entry" ] && last=$idx; done
    idx=0
    for entry in "$@"; do
        idx=$((idx + 1))
        [ -z "$entry" ] && continue
        name=${entry%%,*}
        b64=${entry#*,}
        case "$entry" in *,*) ;; *) name="" ;; esac   # need a name,content pair
        # Sanitized AND capped: the name becomes part of file names (.uc_<pfx><name>.tmp, ...), and
        # a very long one exceeded NAME_MAX, so the file silently failed to load.
        name=$(echo "$name" | sed 's/[^a-zA-Z0-9]/_/g' | cut -c1-48)
        if [ -z "$name" ]; then
            if [ "$trunc" = 1 ] && [ "$idx" = "$last" ]; then
                local _after="the start"; [ -n "$prev" ] && _after="file '$prev'"
                log_msg "WARNING: GeoCustom files (policy $id$chan): the firmware settings store (~3000 chars per value, about 2 KB of list) cut off everything after $_after — a file after it was lost entirely. Re-add it smaller, or put a big list online and add it under URL sources"
            fi
            continue
        fi
        # Uniquify on sanitized-name collision (e.g. "my.list" and "my-list" both -> "my_list"),
        # else the second file's classify output would truncate/overwrite the first's — data loss.
        base="$name"; n=1
        while case "$seen" in *" $name "*) true ;; *) false ;; esac; do
            n=$((n + 1)); name="${base}_${n}"
        done
        seen="$seen$name "
        tmp="$GEO_DIR/.uc_${pfx}${name}.tmp"
        printf '%s' "$b64" | b64d > "$tmp"
        if [ "$trunc" = 1 ] && [ "$idx" = "$last" ]; then
            # Only a PARTIAL last line goes (echo first: a complete newline-terminated line stays).
            { cat "$tmp"; echo; } | sed '$d' > "$tmp.t" 2>/dev/null && mv "$tmp.t" "$tmp"
            if [ -s "$tmp" ]; then
                log_msg "WARNING: GeoCustom file '$name' (policy $id$chan) was cut off by the firmware settings store (~3000 chars per value, about 2 KB of list) — only its first part loads, the partial last line is dropped. Shrink it, or put a big list online and add it under URL sources"
            else
                log_msg "WARNING: GeoCustom file '$name' (policy $id$chan) was lost to the firmware settings store's cut (~3000 chars per value, about 2 KB of list) — nothing of it survived. Re-add it smaller, or put a big list online and add it under URL sources"
            fi
        fi
        if [ -s "$tmp" ]; then
            cnt=$(classify_user_list "$tmp" "$GEO_DIR/domains/${pfx}${name}.txt" "$GEO_DIR/geoip/${pfx}${name}.cidr")
            # shellcheck disable=SC2086
            log_msg "GeoCustom file '$name' (policy $id$chan): $(user_list_summary $cnt)"
        fi
        rm -f "$tmp"
        prev="$name"
    done
    [ "$tailcut" = 1 ] && log_msg "WARNING: GeoCustom files (policy $id$chan): the firmware settings store (~3000 chars per value, about 2 KB of list) cut off everything after file '$prev' — a file after it was lost entirely. Re-add it smaller, or put a big list online and add it under URL sources"
    return 0
}

build_geosite_domains(){
    mkdir -p "$GEO_DIR/domains"
    local union=" $(geo_union_geosite) " f cat _gs_cats=0 _gs_ok=0
    for f in "$GEO_DIR"/domains/v2fly_*.txt; do
        [ -f "$f" ] || continue
        cat=$(basename "$f" .txt); cat=${cat#v2fly_}
        case "$union" in *" $cat "*) ;; *) rm -f "$f" ;; esac
    done
    [ -f "$GEO_DIR/v2fly_all.yml" ] || return 0
    for cat in $(geo_union_geosite); do
        [ -z "$cat" ] && continue
        # 2026-07: upstream switched dlc.dat_plain.yml to quoted name scalars (`- name: "xai"`;
        # rule lines were always quoted) — the old exact `$NF==c` match kept the quotes and
        # silently wrote EMPTY files for every category (only custom domains reached dnsmasq,
        # plus a misleading "pre-resolve: ipset UNCHANGED" warning). Accept quoted AND unquoted
        # names/rules at any list indent; c arrives quote-free (geo_union_geosite sanitizes).
        # Trailing ":@attr" tags are kept as before — the dnsmasq conf builder strips them.
        awk -v c="$cat" '
            /^ *- name:/ {
                if (found) exit
                name=$0; sub(/^ *- name: */,"",name)
                sub(/^["'\'' ]*/,"",name); sub(/["'\'' ]*$/,"",name)
                found=(name==c); next
            }
            found && /^ *- ["'\'' ]*domain:/ { sub(/^ *- ["'\'' ]*domain:/,""); sub(/["'\'' ]*$/,""); print }
            found && /^ *- ["'\'' ]*full:/ { sub(/^ *- ["'\'' ]*full:/,""); sub(/["'\'' ]*$/,""); print }
        ' "$GEO_DIR/v2fly_all.yml" > "$GEO_DIR/domains/v2fly_${cat}.txt"
        _gs_cats=$((_gs_cats+1))
        [ -s "$GEO_DIR/domains/v2fly_${cat}.txt" ] && _gs_ok=$((_gs_ok+1))
    done
    # Self-diagnosis (the fingerprint of the 2026-07 breakage): DB present, categories selected,
    # yet EVERY extraction came out empty — the upstream YAML format changed again, or none of
    # the selected names exist anymore. One empty file among non-empty ones is NOT flagged
    # (that's just a single renamed/typo'd category).
    if [ "$_gs_cats" -gt 0 ] && [ "$_gs_ok" -eq 0 ]; then
        log_msg "WARNING: GeoSite extraction produced 0 domains for ALL $_gs_cats selected categories — the v2fly DB format may have changed (check for an addon update), or the selected category names no longer exist"
    fi
}

migrate_geocustom_layout(){
    [ -f "$GEO_DIR/.geocustom_migrated" ] && return 0
    local f b
    for f in "$GEO_DIR"/domains/usercustom_*.txt "$GEO_DIR"/geoip/usercustom_*.cidr; do
        [ -f "$f" ] || continue
        b=$(basename "$f")
        case "$b" in usercustom_p[0-9]*) ;; *) rm -f "$f" ;; esac   # keep new namespaced, drop legacy flat
    done
    rm -f "$GEO_DIR/domains/custom.txt"   # legacy single-policy custom-domains file
    touch "$GEO_DIR/.geocustom_migrated"
}

build_custom_domains(){
    local id="${1:-1}" kind="${2:-inc}" key out cd
    if [ "$kind" = exc ]; then key=exc_domains; out="$GEO_DIR/domains/custom_exc_p${id}.txt"; else key=custom_domains; out="$GEO_DIR/domains/custom_p${id}.txt"; fi
    cd=$(get_setting "$(geo_key "$id" "$key")")
    rm -f "$out"   # clear stale file when the field is emptied
    if [ -n "$cd" ]; then
        mkdir -p "$GEO_DIR/domains"
        echo "$cd" | tr ',' '\n' > "$out"
    fi
}

unregister_owned_set(){
    [ -f "$OWNED_SETS" ] || return 0
    grep -vxF "$1" "$OWNED_SETS" > "${OWNED_SETS}.tmp" 2>/dev/null
    mv "${OWNED_SETS}.tmp" "$OWNED_SETS"
}

ipset_replay_dynamic(){
    ipset save "$1" 2>/dev/null | awk -v o="$1" -v n="$2" '
        $1 == "add" && $2 == o {
            if ($0 ~ / timeout 0( |$)/) next
            $2 = n; print
        }' | ipset restore -! 2>/dev/null
    return 0
}

geo_cfg_sig(){
    local _s
    _s=$(grep -E 'awg_(geo|antifilter|ipset)' "$SETTINGS" 2>/dev/null | md5sum 2>/dev/null) || return 1
    _s=${_s%% *}
    case "$_s" in ''|*[!0-9a-f]*) return 1 ;; esac
    [ ${#_s} -eq 32 ] || return 1
    echo "$_s"
}

geodyn_stash_save(){
    local _s _t="${GEODYN_STASH}.$$" _sig _born="" _pass
    [ -s "$OWNED_SETS" ] || return 0
    _sig=$(geo_cfg_sig) || return 0
    { read -r _born < "$GEODYN_BORN"; } 2>/dev/null
    # Entries that lived through a geo edit (or whose origin is unknown) are not carried.
    [ "$_born" = "$_sig" ] || return 0
    # Exclusion sets first ("<set>_x": small, and a lost exclusion is a leak INTO the tunnel),
    # so the cap can only ever cut the tail of the big sets. A "<name>_t" whose "<name>" is
    # registered too is that set's staging twin — a crashed build's leftover, nothing live.
    # `timeout 0` lines (the statics: up to 150 K of them) are dropped by one literal regex
    # before anything else is looked at — busybox awk recompiles a STRING regex on every line.
    for _pass in x main; do
        while read -r _s; do
            [ -n "$_s" ] || continue
            case "$_s" in
                *_x) [ "$_pass" = x ] || continue ;;
                *)   [ "$_pass" = main ] || continue ;;
            esac
            case "$_s" in *_t) grep -qxF "${_s%_t}" "$OWNED_SETS" 2>/dev/null && continue ;; esac
            ipset save "$_s" 2>/dev/null | awk -v o="$_s" '
                / timeout 0( |$)/ { next }
                $1 == "add" && $2 == o && $3 ~ /^[0-9.]+(\/[0-9]+)?$/ {
                    for (i = 4; i < NF; i++) if ($i == "timeout") {
                        if ($(i + 1) ~ /^[0-9]+$/) print "add", o, $3, "timeout", $(i + 1)
                        break
                    }
                }'
        done < "$OWNED_SETS"
    done 2>/dev/null | head -n "$GEODYN_STASH_MAX" > "$_t.b" 2>/dev/null
    # Nothing dynamic in these sets (a start that never got as far as a build): whatever an
    # earlier stop parked is still the best there is — leave it.
    if [ -s "$_t.b" ]; then
        { echo "# sig $_sig"; cat "$_t.b"; } > "$_t" 2>/dev/null && mv -f "$_t" "$GEODYN_STASH" 2>/dev/null
    fi
    rm -f "$_t" "$_t.b" 2>/dev/null
    return 0
}

geodyn_stash_replay(){
    local _age _h1="" _h2="" _sig=""
    [ -s "$GEODYN_STASH" ] || return 0
    _age=$(file_age_s "$GEODYN_STASH") || return 0
    case "$_age" in ''|*[!0-9]*) return 0 ;; esac    # dated in the future (clock stepped) -> skip
    [ "$_age" -le "$GEODYN_STASH_TTL" ] || return 0
    { read -r _h1 _h2 _sig < "$GEODYN_STASH"; } 2>/dev/null
    [ "$_h1" = "#" ] && [ "$_h2" = sig ] && [ -n "$_sig" ] && [ "$_sig" = "$(geo_cfg_sig)" ] || return 0
    awk -v o="$1" -v n="$2" -v age="$_age" '
        NF == 5 && $1 == "add" && $2 == o && $4 == "timeout" && $3 ~ /^[0-9.]+(\/[0-9]+)?$/ && $5 ~ /^[0-9]+$/ {
            left = $5 - age
            if (left >= 60) print "add", n, $3, "timeout", left
        }' "$GEODYN_STASH" 2>/dev/null | ipset restore -! 2>/dev/null
    return 0
}

geodyn_stash_settle(){
    local _sig
    if [ "$1" = 1 ] && [ "$2" != 1 ]; then
        if _sig=$(geo_cfg_sig); then
            echo "$_sig" 2>/dev/null > "$GEODYN_BORN"
        else
            rm -f "$GEODYN_BORN" 2>/dev/null
        fi
    fi
    rm -f "$GEODYN_STASH" 2>/dev/null
    return 0
}

ipset_commit_staged(){
    local final="$1" tmp="$2"
    if ipset list "$final" -t >/dev/null 2>&1; then
        if ipset swap "$tmp" "$final" 2>/dev/null; then
            ipset destroy "$tmp" 2>/dev/null
            unregister_owned_set "$tmp"
            register_owned_set "$final"
            return 0
        fi
        return 1
    fi
    if ipset rename "$tmp" "$final" 2>/dev/null; then
        unregister_owned_set "$tmp"
        register_owned_set "$final"
        # A brand-new live set holds statics only: the next pre-resolve must feed it from line 1.
        geoset_gen_bump
        return 0
    fi
    return 1
}

file_age_s(){
    local _m _n
    _m=$(date -r "$1" +%s 2>/dev/null) || return 1
    _n=$(date +%s 2>/dev/null) || return 1
    case "$_m" in ''|*[!0-9]*) return 1 ;; esac
    case "$_n" in ''|*[!0-9]*) return 1 ;; esac
    echo $(( _n - _m ))
}

setup_policy_data(){
    b64d_init   # once here, so every $(geo_union_urls)/$(policy_url_keys) below inherits the probe
    # Keep active set members while building replacements and swap each set atomically.
    [ -n "$(get_setting awg_geo_policies)" ] || return 0

    # --- Create + populate one ipset PER geo policy ---
    # Old routers (e.g. RT-AC68U) don't autoload the ip_set kernel modules, and the
    # in-kernel auto-load needs modprobe — absent from the httpd/service-event PATH
    # context — so `ipset create` fails there. Load them explicitly (no-op if already
    # loaded or built-in). xt_set backs the `-m set --match-set` mangle rules below.
    local m
    for m in ip_set ip_set_hash_net xt_set; do
        modprobe "$m" 2>/dev/null
    done
    # Default timeout 24h: governs domain entries added by dnsmasq (GeoSite/custom domains).
    # They MUST expire — CDNs rotate IPs; dnsmasq re-adds the current IP on each resolution
    # (refreshing it), so active domains stay while stale IPs age out. Static GeoIP/custom-IP
    # entries are added with explicit "timeout 0" (permanent), overriding this default.
    # RAM-aware TOTAL budget: on low-memory routers (RT-AC68U etc., 256MB) the big lists
    # (antifilter ipresolve ~154K) can exhaust kernel memory and hang the router. With N geo
    # policies each owning a set, divide the budget by N (geo_maxelem) so they can't sum past
    # the box's ceiling. Adds past a set's cap fail harmlessly (ipset restore -!).
    local total_max="$IPSET_MAXELEM" memkb
    memkb=$(awk '/^MemTotal:/{print $2; exit}' /proc/meminfo 2>/dev/null)
    if [ -n "$memkb" ] && [ "$memkb" -lt 393216 ]; then
        total_max=98304
        log_msg "Low RAM (${memkb}KB total): geo ipset budget capped at $total_max (was $IPSET_MAXELEM) to avoid OOM"
    fi
    local maxelem; maxelem=$(geo_maxelem "$total_max")

    # Obsolete sets (deleted policies, an awg_ipset_name rename's old family, crashed staging
    # temps) are reaped by reconcile_owned_sets AFTER the chain reconcile below — here we only
    # GC per-policy content files for policies deleted in the UI.
    prune_orphan_policies

    # Sync the SHARED pool to the union of all policies' selections (drop de-selected files) and
    # extract the union of GeoSite categories once. Per-policy loading below picks each subset.
    migrate_geocustom_layout   # one-time: drop pre-shared-pool flat usercustom_*/custom.txt
    prune_geoip
    prune_antifilter
    prune_custom_urls
    build_geosite_domains

    # Staged build: load each policy's NEW content into a "_t" staging set while the live set
    # keeps routing, then ipset_commit_staged swaps it into place atomically. Dynamic (dnsmasq/
    # pre-resolve-fed) entries are replayed first with their remaining timeouts, so domain
    # routing survives the rebuild with no gap at all. Shared-base semantics preserved: a
    # pre-existing set we don't own is loaded IN PLACE for id 1 (documented shared behavior —
    # we must never destroy/swap another tool's set) and skipped for id>=2 (foreign collision).
    local gid gset tset _ldt _staged _prs_before _ssig
    # Did this run build a set from scratch / carry a live one over? geodyn_stash_settle
    # (after the loop) needs both to decide whether a new "born" epoch starts.
    local _gd_first=0 _gd_carried=0
    # The staged swap below keeps what an earlier pre-resolve fed (replay), so it keeps
    # GEOSET_GEN and the pre-resolve cursor stays valid — but only for feeds that happened
    # BEFORE the replay snapshot. Let a running pre-resolve reach its batch boundary and yield
    # first, remember the cursor, and let geo_swap_window_close judge the window afterwards.
    geo_preresolve_quiesce
    _prs_before="$(cat "$GEOSET_GEN" 2>/dev/null)|$(cat "$PRERSLV_STATE" 2>/dev/null)"
    _ssig=$(geo_static_sig)
    for gid in $(geo_ids); do
        gset=$(geo_ipset "$gid")
        local _cerr _crc
        _staged=1; _ldt=""
        if ipset list "$gset" -t >/dev/null 2>&1 && ! geo_set_ours 2 "$gset"; then
            echo "ipset $gset 已被占用"
            return 1
        else
            tset="${gset}_t"
            if ipset list "$tset" -t >/dev/null 2>&1; then
                geo_set_ours 2 "$tset" || return 1
                ipset destroy "$tset" 2>/dev/null || return 1
            fi
            _cerr=$(ipset create "$tset" hash:net family inet hashsize 4096 maxelem "$maxelem" timeout 86400 2>&1)
            _crc=$?
            if [ "$_crc" -ne 0 ] || ! ipset list "$tset" -t >/dev/null 2>&1; then
                log_msg "ERROR: ipset $tset creation failed, geo policy $gid disabled${_cerr:+: $_cerr}"
                continue
            fi
            register_owned_set "$tset"
            # Warm state first (empty set -> no -exist conflicts), statics after: their
            # `timeout 0` restore -! lines upgrade any replayed duplicate back to permanent.
            # A live set carries it over itself; on a FIRST build (after a stop destroyed
            # the sets) it comes from what that stop parked — see geodyn_stash_save.
            if ipset list "$gset" -t >/dev/null 2>&1; then
                _gd_carried=1
                ipset_replay_dynamic "$gset" "$tset"
            else
                _gd_first=1
                geodyn_stash_replay "$gset" "$tset"
            fi
            _ldt="$tset"
        fi

        # Load THIS policy's selected subset from the shared pool into the target set.
        local _svc _f _ak _uk
        for _svc in $(selected_geoip "$gid"); do
            _f="$GEO_DIR/geoip/v2fly_${_svc}.cidr"; [ -f "$_f" ] || continue
            ipset_load_file "$_f" "$_ldt"
        done
        for _ak in $(selected_antifilter "$gid"); do
            antifilter_is_domain "$_ak" && continue
            _f="$GEO_DIR/antifilter/af_${_ak}.cidr"; [ -f "$_f" ] || continue
            ipset_load_file "$_f" "$_ldt"
        done
        # Custom URL CIDRs this policy references (shared files keyed by URL hash).
        for _uk in $(policy_url_keys "$gid"); do
            _f="$GEO_DIR/geoip/userurl_${_uk}.cidr"; [ -f "$_f" ] || continue
            ipset_load_file "$_f" "$_ldt"
        done
        # Custom IPs (field) -> permanent entries, batched through ONE `ipset restore` (the old
        # per-IP `ipset add` loop forked a process per entry — 100+ execs on big fields).
        get_setting "$(geo_key "$gid" custom_ips)" | tr ',' '\n' | ipv4_restore_lines "$_ldt" \
            | ipset restore -! 2>/dev/null
        # GeoCustom pasted files (per-policy content): regenerate, then load this policy's CIDRs.
        apply_custom_geo "$gid"
        for _f in "$GEO_DIR"/geoip/usercustom_p${gid}_*.cidr; do
            [ -f "$_f" ] || continue
            ipset_load_file "$_f" "$_ldt"
        done
        # This policy's own custom-domains file (consumed by the dnsmasq builder below).
        build_custom_domains "$gid"

        if [ "$_staged" = 1 ]; then
            if ! ipset_commit_staged "$gset" "$tset"; then
                log_msg "ERROR: could not activate rebuilt ipset $gset (swap/rename failed) — geo policy $gid keeps its previous entries this round"
                ipset destroy "$tset" 2>/dev/null
                unregister_owned_set "$tset"
                # A previous live set (if any) keeps routing; fall through so exc/domains still build.
            fi
        fi

        # --- Exclusions channel (pointwise exceptions) ---
        # Always (re)generate this policy's exclusion content files (self-clean when empty), so a
        # cleared exclusions block leaves nothing behind. Only build the EXC ipset when used: it's
        # small (pointwise) and gets a fixed cap, so it never erodes the divided main budget.
        apply_custom_geo "$gid" exc
        build_custom_domains "$gid" exc
        if policy_has_exc "$gid"; then
            local _exset _etmp _exldt _exstaged
            _exset=$(geo_exc_ipset "$gid")
            _exstaged=1; _exldt=""
            if ipset list "$_exset" -t >/dev/null 2>&1 && ! geo_set_ours 2 "$_exset"; then
                echo "ipset $_exset 已被占用"
                return 1
            else
                _etmp="${_exset}_t"
                if ipset list "$_etmp" -t >/dev/null 2>&1; then
                    geo_set_ours 2 "$_etmp" || return 1
                    ipset destroy "$_etmp" 2>/dev/null || return 1
                fi
                if ipset create "$_etmp" hash:net family inet hashsize 1024 maxelem 8192 timeout 86400 2>/dev/null; then
                    register_owned_set "$_etmp"
                    if ipset list "$_exset" -t >/dev/null 2>&1; then
                        _gd_carried=1
                        ipset_replay_dynamic "$_exset" "$_etmp"
                    else
                        _gd_first=1
                        geodyn_stash_replay "$_exset" "$_etmp"
                    fi
                    _exldt="$_etmp"
                fi
            fi
            if [ -n "$_exldt" ]; then
                get_setting "$(geo_key "$gid" exc_ips)" | tr ',' '\n' | ipv4_restore_lines "$_exldt" \
                    | ipset restore -! 2>/dev/null
                for _f in "$GEO_DIR"/geoip/excustom_p${gid}_*.cidr; do
                    [ -f "$_f" ] && ipset_load_file "$_f" "$_exldt"
                done
                for _uk in $(policy_url_keys "$gid" exc); do
                    _f="$GEO_DIR/geoip/userurl_${_uk}.cidr"; [ -f "$_f" ] && ipset_load_file "$_f" "$_exldt"
                done
                if [ "$_exstaged" = 1 ]; then
                    if ! ipset_commit_staged "$_exset" "$_etmp"; then
                        log_msg "ERROR: could not activate rebuilt exclusion ipset $_exset — policy $gid keeps its previous exclusions this round"
                        ipset destroy "$_etmp" 2>/dev/null
                        unregister_owned_set "$_etmp"
                    fi
                fi
            fi
        fi

        # Fill-level warning (per set).
        local _ent
        _ent=$(ipset list "$gset" -t 2>/dev/null | awk '/Number of entries/{print $NF}')
        [ -n "$_ent" ] && [ "$_ent" -ge "$maxelem" ] 2>/dev/null && \
            log_msg "WARNING: ipset $gset full ($_ent/$maxelem) for geo policy $gid — raise RAM or trim its lists"
    done
    # The parked DNS-learned entries have been taken back (or failed their checks): consume
    # the stash and, when everything was built from scratch, start a new "born" epoch.
    geodyn_stash_settle "$_gd_first" "$_gd_carried"
    geo_swap_window_close "$_prs_before" "$_ssig"

    # --- Build dnsmasq config for domain-based routing ---
    local dns_next="$DNSMASQ_AWG_CONF.next"
    echo "# AmneziaWG domain routing" > "$dns_next"
    # Per policy: route ITS selected domains into ITS OWN ipset (INC -> main set, EXC -> exclusion
    # set). The exact files a policy uses are enumerated from its selection (NOT a dir glob), since
    # the pool is shared. Domain->ipset rules only work if the set exists, so re-check `ipset list`
    # per policy (mirrors the per-device mangle vpn_geo guard).
    #
    # CRITICAL (the multi-policy domain bug): dnsmasq honors only the FIRST `ipset=` directive that
    # matches a given domain — a second `ipset=/dom/otherset` line for the same domain is silently
    # ignored (verified on dnsmasq 2.93). So we must NOT emit one line per policy: a domain shared
    # by two policies (the common case — youtube/netflix/etc. in several tabs) would populate only
    # the first policy's set and starve every other policy's device of that destination. Instead we
    # collect (domain -> target set) pairs across ALL policies/channels and emit each domain ONCE
    # as `ipset=/dom/setA,setB,...` — a comma-set line fans the resolved IP to EVERY listed set.
    local dgid dgset f _cat _uk _dfiles _efiles _chan _cset _cfiles
    local _ds_tmp="$GEO_DIR/.dnsmasq_ds.$$"
    true 2>/dev/null > "$_ds_tmp"   # not `:` — a failed redirect on that special builtin exits the shell
    for dgid in $(geo_ids); do
        dgset=$(geo_ipset "$dgid")
        # INC domain files for this policy (route via its main set).
        _dfiles=""
        for _cat in $(get_setting "$(geo_key "$dgid" v2fly)" | tr ',' ' '); do
            _cat=$(echo "$_cat" | sed 's/[^A-Za-z0-9_.!-]//g'); [ -z "$_cat" ] && continue   # same charset as geo_union_geosite
            _dfiles="$_dfiles $GEO_DIR/domains/v2fly_${_cat}.txt"
        done
        _dfiles="$_dfiles $GEO_DIR/domains/custom_p${dgid}.txt"
        case " $(selected_antifilter "$dgid") " in *" community_domains "*) _dfiles="$_dfiles $GEO_DIR/domains/antifilter_community_domains.lst" ;; esac
        for _uk in $(policy_url_keys "$dgid"); do _dfiles="$_dfiles $GEO_DIR/domains/userurl_${_uk}.txt"; done
        for f in "$GEO_DIR"/domains/usercustom_p${dgid}_*.txt; do [ -f "$f" ] && _dfiles="$_dfiles $f"; done
        # EXC domain files for this policy (the exclusions block -> its EXC set).
        _efiles="$GEO_DIR/domains/custom_exc_p${dgid}.txt"
        for _uk in $(policy_url_keys "$dgid" exc); do _efiles="$_efiles $GEO_DIR/domains/userurl_${_uk}.txt"; done
        for f in "$GEO_DIR"/domains/excustom_p${dgid}_*.txt; do [ -f "$f" ] && _efiles="$_efiles $f"; done

        # Collect each channel's (domain -> target set) pairs into the shared stream.
        for _chan in inc exc; do
            if [ "$_chan" = exc ]; then _cset="$(geo_exc_ipset "$dgid")"; _cfiles="$_efiles"; else _cset="$dgset"; _cfiles="$_dfiles"; fi
            if ! ipset list "$_cset" >/dev/null 2>&1 || ! geo_set_ours "$dgid" "$_cset"; then
                for f in $_cfiles; do [ -f "$f" ] && { log_msg "domain-geo disabled for policy $dgid ($_chan): ipset $_cset unavailable (domains configured but not routable)"; break; }; done
                continue
            fi
            for f in $_cfiles; do
                [ -f "$f" ] || continue
                # Normalize in one awk pass per file (no per-domain shell fork): strip spaces/CR,
                # drop blanks/comments, strip a leading dot and any trailing ":@attr" v2fly tag,
                # reject domains with invalid chars. Emit "<domain>\t<set>".
                awk -v set="$_cset" '
                    { d=$0; gsub(/[ \r]/,"",d)
                      if (d=="" || substr(d,1,1)=="#") next
                      sub(/^\./,"",d); sub(/:@[^ ]*$/,"",d)
                      if (d=="" || d ~ /[^a-zA-Z0-9._-]/) next
                      print d "\t" set }' "$f" >> "$_ds_tmp"
            done
        done
    done

    # Aggregate domain -> unique set list across ALL policies/channels, then emit each domain once
    # as `ipset=/dom/setA,setB` (chunked 20 domains/line, grouped by identical set list so lines
    # stay compact). This collision-free form is what dnsmasq actually honors for shared domains.
    # DETERMINISTIC: the input is sorted (so each domain's set list is built in a stable order) and
    # the emitted lines are sorted, so an unchanged selection produces a byte-identical conf — that
    # lets reload_dnsmasq md5-compare and SKIP a pointless dnsmasq restart (see reload_dnsmasq).
    if [ -s "$_ds_tmp" ]; then
        sort "$_ds_tmp" | awk -F'\t' '
            { dom=$1; set=$2
              if (!(dom in S)) { S[dom]=set; next }
              cur=S[dom]; n=split(cur,a,","); found=0
              for(i=1;i<=n;i++) if(a[i]==set){found=1;break}
              if(!found) S[dom]=cur","set }
            END {
              for (dom in S) { sig=S[dom]; G[sig]=G[sig] " " dom }
              for (sig in G) {
                cnt=0; line="ipset=/"
                m=split(G[sig], dd, " ")
                for(i=1;i<=m;i++){
                  if(dd[i]=="") continue
                  line=line dd[i] "/"; cnt++
                  if(cnt>=20){ print line sig; line="ipset=/"; cnt=0 }
                }
                if(cnt>0) print line sig
              }
            }' | sort >> "$dns_next"
    fi
    rm -f "$_ds_tmp"

    # Validate the domain configuration before publishing it to dnsmasq.
    if ! dnsmasq --test --conf-file="$dns_next" >/dev/null 2>&1; then
        rm -f "$dns_next"
        echo "dnsmasq 不支持生成的域名分流配置"
        return 1
    fi
    for gid in $(geo_ids); do
        geo_set_ours "$gid" "$(geo_ipset "$gid")" || return 1
        ipset list "$(geo_ipset "$gid")" -t >/dev/null 2>&1 || return 1
        if policy_has_exc "$gid"; then
            geo_set_ours "$gid" "$(geo_exc_ipset "$gid")" || return 1
            ipset list "$(geo_exc_ipset "$gid")" -t >/dev/null 2>&1 || return 1
        fi
    done
    mv "$dns_next" "$DNSMASQ_AWG_CONF"
}

analyze_verdict(){
    case "$1" in
        vpn_all) echo "vpn" ;;
        vpn_geo|vpn_geo_*)
            local id incset excset
            id=$(geo_policy_of_ref "$1"); incset=$(geo_ipset "$id"); excset=$(geo_exc_ipset "$id")
            if [ "$(geo_mode "$id")" = direct ]; then
                if ipset test "$excset" "$2" >/dev/null 2>&1; then echo "vpn"
                elif ipset test "$incset" "$2" >/dev/null 2>&1; then echo "direct"
                else echo "vpn"; fi
            else
                if ipset test "$excset" "$2" >/dev/null 2>&1; then echo "direct"
                elif ipset test "$incset" "$2" >/dev/null 2>&1; then echo "geo"
                else echo "direct"; fi
            fi ;;
        *)       echo "direct" ;;
    esac
}

analyze_dns_log_on(){
    : > "$ANALYZE_DNS_LOG" || return 1
    printf 'log-queries=extra\nlog-facility=%s\n' "$ANALYZE_DNS_LOG" > "$ANALYZE_DNS_CONF" || return 1
    reload_dnsmasq
}

analyze_dns_log_off(){
    if [ -f "$ANALYZE_DNS_CONF" ]; then
        rm -f "$ANALYZE_DNS_CONF"
        reload_dnsmasq
    fi
    rm -f "$ANALYZE_DNS_LOG"
}

analyze_build_map(){
    if [ ! -f "$ANALYZE_DNS_LOG" ]; then : > "$ANALYZE_MAP" 2>/dev/null; return; fi
    awk '
        / is [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {
            ip=$NF; name=$(NF-2);
            gsub(/[^A-Za-z0-9._-]/,"",name);
            if(name!="") map[ip]=name;
        }
        END { for(k in map) print k"\t"map[k] }
    ' "$ANALYZE_DNS_LOG" > "$ANALYZE_MAP" 2>/dev/null
}

analyze_write(){
    local ip="$1" policy="$2" active="$3" started="${4:-0}" arr=""
    [ -f "$ANALYZE_ENTRIES" ] && arr=$(awk 'BEGIN{ORS=""} {if(NR>1)print ","; print}' "$ANALYZE_ENTRIES" 2>/dev/null)
    rm -f "${ANALYZE_FILE}.tmp" "${ANALYZE_FILE}".[0-9]* 2>/dev/null
    # '<' as its JSON unicode escape, like the status file: a queried domain name is LAN-client
    # text, and this .htm goes through the firmware's ASP evaluator (a stray tag opener livelocks
    # httpd).
    sed 's/</\\u003c/g' > "${ANALYZE_FILE}.$$" <<ANEOF
{"active":${active},"device":"${ip}","policy":"${policy}","started":${started},"entries":[${arr}]}
ANEOF
    mv "${ANALYZE_FILE}.$$" "$ANALYZE_FILE" 2>/dev/null
}

analyze_flows(){
    local ip="$1" src=""
    [ -r /proc/net/nf_conntrack ] && src=/proc/net/nf_conntrack
    [ -z "$src" ] && [ -r /proc/net/ip_conntrack ] && src=/proc/net/ip_conntrack
    [ -z "$src" ] && return 0
    awk -v source="src=$ip" '
        {
            proto=""; d=""; dp=""; first=""
            for(i=1;i<=NF;i++){
                if(proto==""&&($i=="tcp"||$i=="udp"||$i=="icmp"||$i=="icmpv6"||$i=="udplite"||$i=="sctp"||$i=="dccp")) proto=$i;
                if(first==""&&$i ~ /^src=/) first=$i;
                if(d==""&&$i ~ /^dst=/)    d=substr($i,5);
                if(dp==""&&$i ~ /^dport=/)  dp=substr($i,7);
            }
            if(proto=="") proto="ip";
            if(first==source && d!="") print proto" "d" "dp;
        }' "$src" 2>/dev/null
}

analyze_dns_queries(){
    local ip="$1"
    [ -r "$ANALYZE_DNS_LOG" ] || return 0
    awk -v ip="$ip" '
        {
            id="";
            for(i=1;i<=NF;i++){ if($i ~ /^dnsmasq\[/){ id=$(i+1); break } }
            if(id==""){ next }
            q=""; req="";
            for(i=1;i<=NF;i++){ if($i ~ /^query\[/) q=$(i+1); if($i=="from") req=$(i+1); }
            if(q!="" && req==ip){ d[id]=q; if(!(q in seen)){ seen[q]=1; ord[++n]=q } }
            for(i=1;i<NF;i++){
                if(($i=="reply"||$i=="cached") && $(i+2)=="is" && $(i+3) ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && (id in d))
                    ips[d[id]] = ips[d[id]] "," $(i+3);
            }
        }
        END{ for(k=1;k<=n;k++){ q=ord[k]; s=ips[q]; sub(/^,/,"",s); print q"\t"s } }
    ' "$ANALYZE_DNS_LOG"
}

analyze_loop(){
    local ip="$1" policy="$2" started="$3"
    local router_ip lan_pre deadline now sz
    router_ip=$(get_router_ip)
    lan_pre=$(printf '%s' "$router_ip" | sed 's/\.[0-9]*$/./')
    deadline=$((started + ANALYZE_MAX_SECONDS))
    while [ -f "$ANALYZE_FLAG" ]; do
        now=$(date +%s)
        [ "$now" -ge "$deadline" ] && break
        # Keep the query log from growing without bound on a busy LAN.
        if [ -f "$ANALYZE_DNS_LOG" ]; then
            sz=$(wc -c < "$ANALYZE_DNS_LOG" 2>/dev/null)
            [ -n "$sz" ] && [ "$sz" -gt 262144 ] 2>/dev/null && \
                { tail -c 131072 "$ANALYZE_DNS_LOG" > "${ANALYZE_DNS_LOG}.t" 2>/dev/null && mv "${ANALYZE_DNS_LOG}.t" "$ANALYZE_DNS_LOG"; }
        fi
        analyze_build_map
        # --- DNS-request rows: domains the device is TRYING to reach (the intent), captured at
        # query time. Verdict from the resolved IPv4(s): vpn_geo -> geo if any is in the set, else
        # direct; vpn_all -> vpn; direct -> direct. For vpn_geo we DEFER a domain (don't mark it
        # seen) until it has resolved, so its verdict is real rather than a transient "unknown". ---
        analyze_dns_queries "$ip" | while IFS="$(printf '\t')" read -r dom ipscsv; do
            dom=$(printf '%s' "$dom" | tr -cd 'A-Za-z0-9._-')
            [ -z "$dom" ] && continue
            dkey="dns:$dom"
            grep -qxF "$dkey" "$ANALYZE_SEEN" 2>/dev/null && continue
            firstip=$(printf '%s' "$ipscsv" | cut -d, -f1)
            verdict="direct"
            if [ "$policy" = vpn_all ]; then
                verdict="vpn"
            elif [ -n "$ipscsv" ]; then
                # Per resolved IP, the mode/exclusion/default-aware verdict; first non-direct wins.
                for one in $(printf '%s' "$ipscsv" | tr ',' ' '); do
                    [ -z "$one" ] && continue
                    verdict=$(analyze_verdict "$policy" "$one")
                    [ "$verdict" != direct ] && break
                done
            else
                case "$policy" in vpn_geo|vpn_geo_*) continue ;; esac   # geo: not resolved yet — retry
            fi
            echo "$dkey" >> "$ANALYZE_SEEN"
            echo "{\"t\":\"$(date '+%H:%M:%S')\",\"name\":\"$dom\",\"ip\":\"$firstip\",\"proto\":\"dns\",\"port\":\"\",\"verdict\":\"$verdict\"}" >> "$ANALYZE_ENTRIES"
        done
        analyze_flows "$ip" | while read -r proto dst dport; do
            # Skip LAN-local / router / loopback / multicast / broadcast destinations.
            case "$dst" in "$router_ip"|127.*|224.*|225.*|226.*|227.*|228.*|229.*|23[0-9].*|255.*|0.*) continue ;; esac
            [ -n "$lan_pre" ] && case "$dst" in "$lan_pre"*) continue ;; esac
            key="$proto:$dst:$dport"
            grep -qxF "$key" "$ANALYZE_SEEN" 2>/dev/null && continue
            echo "$key" >> "$ANALYZE_SEEN"
            name=$(awk -F'\t' -v ip="$dst" '$1==ip{print $2; exit}' "$ANALYZE_MAP" 2>/dev/null)
            [ -z "$name" ] && name="$dst"
            verdict=$(analyze_verdict "$policy" "$dst")
            echo "{\"t\":\"$(date '+%H:%M:%S')\",\"name\":\"$name\",\"ip\":\"$dst\",\"proto\":\"$proto\",\"port\":\"$dport\",\"verdict\":\"$verdict\"}" >> "$ANALYZE_ENTRIES"
        done
        if [ -f "$ANALYZE_ENTRIES" ]; then
            tail -n "$ANALYZE_MAX_ENTRIES" "$ANALYZE_ENTRIES" > "${ANALYZE_ENTRIES}.t" 2>/dev/null && mv "${ANALYZE_ENTRIES}.t" "$ANALYZE_ENTRIES"
        fi
        analyze_write "$ip" "$policy" true "$started"
        sleep 2
    done
    # Timeout / flag-cleared path: publish final inactive state and remove the DNS log snippet.
    rm -f "$ANALYZE_FLAG"
    analyze_write "$ip" "$policy" false "$started"
    analyze_dns_log_off
    rm -f "$ANALYZE_PID"
}

do_analyze_start(){
    local ip pol now
    ip=$(cat "$AWG_DIR/analyze-device" 2>/dev/null)
    ip=$(printf '%s' "$ip" | tr -cd '0-9.')
    if ! echo "$ip" | grep -qE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
        echo '{"active":false,"device":"","policy":"","started":0,"entries":[],"error":"bad_ip"}' > "$ANALYZE_FILE"
        return
    fi
    do_analyze_stop quiet          # clear any prior session first
    pol=$(cat "$AWG_DIR/analyze-policy" 2>/dev/null)
    now=$(date +%s)
    echo "$ip" > "$ANALYZE_FLAG"
    echo "$now" > "$ANALYZE_STARTED"
    : > "$ANALYZE_ENTRIES"; : > "$ANALYZE_SEEN"; : > "$ANALYZE_MAP"
    if ! analyze_dns_log_on; then
        do_analyze_stop quiet
        return 1
    fi
    analyze_write "$ip" "$pol" true "$now"
    analyze_loop "$ip" "$pol" "$now" </dev/null >/dev/null 2>&1 &
    echo $! > "$ANALYZE_PID"
    log_msg "Traffic analysis started for $ip ($pol)"
}

do_analyze_stop(){
    local ip pol was=0 pid
    [ -f "$ANALYZE_FLAG" ] && was=1
    rm -f "$ANALYZE_FLAG"
    pid=$(cat "$ANALYZE_PID" 2>/dev/null)
    case "$pid" in
        ''|*[!0-9]*) ;;
        *) if tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -qF "$root/run.sh analyze-start"; then kill "$pid" 2>/dev/null; fi ;;
    esac
    rm -f "$ANALYZE_PID" "$ANALYZE_SEEN" "$ANALYZE_MAP"
    analyze_dns_log_off
    ip=$(cat "$AWG_DIR/analyze-device" 2>/dev/null); ip=$(printf '%s' "$ip" | tr -cd '0-9.')
    pol=$(cat "$AWG_DIR/analyze-policy" 2>/dev/null)
    analyze_write "$ip" "$pol" false "$(cat "$ANALYZE_STARTED" 2>/dev/null || echo 0)"
    rm -f "$ANALYZE_STARTED"
    [ "$1" = quiet ] || [ "$was" = 0 ] || log_msg "Traffic analysis stopped"
}
