#!/bin/sh
export PATH=/koolshare/bin:/usr/sbin:/usr/bin:/sbin:/bin
umask 077
. /koolshare/scripts/base.sh
case "${2:-}" in
 core-status|core-check|core-upgrade|core-rollback|logs|diagnose|status|up|down|server-status|server-up|server-down)
  result="$(/koolshare/bin/amneziawg-go web "$2")"
  ;;
 import|settings|switch|delete|server-save|server-add|server-delete|server-enable|server-disable|server-export|request-check)
  # The core reads and clears dbus itself; no shell printf/stdin dependency.
  result="$(/koolshare/bin/amneziawg-go web "$2")"
  ;;
 *) result='AWG64:eyJvayI6ZmFsc2UsIm1lc3NhZ2UiOiLmnKrnn6Xmk43kvZwifQ==' ;;
esac
[ -n "$result" ] || result='AWG64:eyJvayI6ZmFsc2UsIm1lc3NhZ2UiOiLmj5Lku7bov5vnqIvml6Dlk43lupTvvIzor7fmo4Dmn6Xlronoo4XlkozlhoXlrZgifQ=='
http_response "$result"
