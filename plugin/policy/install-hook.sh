#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu
umask 077
hook=/jffs/scripts/dnsmasq.postconf
marker='# amneziawg-policy-postconf'
case "${1:-}" in
    install)
        if ! grep -qF "$marker" "$hook" 2>/dev/null; then
            mkdir -p /jffs/scripts
            [ -f "$hook" ] || printf '#!/bin/sh\n' > "$hook"
            {
                IFS= read -r first || :
                printf '%s\n' "${first:-#!/bin/sh}"
                printf '%s\n' '[ ! -r /koolshare/amneziawg/policy/dnsmasq-postconf.sh ] || /bin/sh /koolshare/amneziawg/policy/dnsmasq-postconf.sh "$1" # amneziawg-policy-postconf'
                cat
            } < "$hook" > "$hook.awg-new"
            chmod 755 "$hook.awg-new"
            mv "$hook.awg-new" "$hook"
        fi
        ;;
    uninstall)
        if grep -qF "$marker" "$hook" 2>/dev/null; then
            sed "\|$marker\$|d" "$hook" > "$hook.awg-new"
            chmod 755 "$hook.awg-new"
            mv "$hook.awg-new" "$hook"
        fi
        ;;
    *) exit 2 ;;
esac
