#!/bin/sh
export PATH=/koolshare/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Some ASUS firmware shells omit the command builtin.
has_tool() {
 for awg_tool_dir in /koolshare/bin /usr/sbin /usr/bin /sbin /bin; do
  [ -f "$awg_tool_dir/$1" ] && [ -x "$awg_tool_dir/$1" ] && return 0
 done
 return 1
}
umask 077
case "${1:-}" in
 start)
  # The known-good backup can recover even if the newly activated file will not run.
  if [ -f /koolshare/amneziawg/update-busy ] && [ -x /koolshare/bin/amneziawg-go.previous ]; then
   /koolshare/bin/amneziawg-go.previous ctl core-boot-recover >/dev/null 2>&1 || exit 1
  else
   /koolshare/bin/amneziawg-go ctl core-boot-recover >/dev/null 2>&1 || exit 1
  fi
  if has_tool cru; then cru a amneziawg_watch '*/1 * * * * /koolshare/bin/amneziawg-go ctl watch >/dev/null 2>&1'; fi
  /koolshare/bin/amneziawg-go ctl boot >/dev/null 2>&1
  /koolshare/bin/amneziawg-go ctl server-boot >/dev/null 2>&1
  ;;
 start_nat)
  /koolshare/bin/amneziawg-go ctl recover >/dev/null 2>&1
  /koolshare/bin/amneziawg-go ctl server-recover >/dev/null 2>&1
  ;;
 stop|kill)
  /koolshare/bin/amneziawg-go ctl down >/dev/null 2>&1
  /koolshare/bin/amneziawg-go ctl server-service-stop >/dev/null 2>&1
  ;;
esac
