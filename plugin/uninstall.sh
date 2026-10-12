#!/bin/sh
set -eu
export PATH=/koolshare/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Some ASUS firmware shells omit the command builtin.
has_tool() {
 for awg_tool_dir in /koolshare/bin /usr/sbin /usr/bin /sbin /bin; do
  [ -f "$awg_tool_dir/$1" ] && [ -x "$awg_tool_dir/$1" ] && return 0
 done
 return 1
}
if [ -x /koolshare/bin/amneziawg-go ]; then
 if [ -f /tmp/amneziawg-asus/server-state.json ]; then
  /koolshare/bin/amneziawg-go ctl server-down || { echo "服务端清理失败，保留旧程序"; exit 1; }
 fi
 /koolshare/bin/amneziawg-go ctl down || { echo '网络规则清理失败，保留插件以便恢复'; exit 1; }
fi
# Remove only the plugin-owned dnsmasq block.
DNS_ADD=/jffs/configs/dnsmasq.conf.add
if [ -f "$DNS_ADD" ] && grep -q '^# BEGIN AMNEZIAWG DNS$' "$DNS_ADD"; then
 sed '/^# BEGIN AMNEZIAWG DNS$/,/^# END AMNEZIAWG DNS$/d' "$DNS_ADD" > "$DNS_ADD.awg-new"
 mv "$DNS_ADD.awg-new" "$DNS_ADD"
 if has_tool service; then service restart_dnsmasq; fi
fi
if has_tool cru; then cru d amneziawg_watch; fi
rm -f /koolshare/init.d/S95amneziawg.sh /koolshare/init.d/N95amneziawg.sh
rm -f /koolshare/bin/amneziawg-go /koolshare/scripts/amneziawg_api.sh /koolshare/scripts/amneziawg_service.sh
rm -f /koolshare/webs/Module_amneziawg.asp /koolshare/res/amneziawg.js /koolshare/res/icon-amneziawg.png
rm -f /koolshare/res/amneziawg-qrcode.js /koolshare/res/amneziawg-config.js
rm -f /koolshare/res/amneziawg-server.js /koolshare/res/amneziawg-logs.js /koolshare/res/amneziawg-ui.js /koolshare/res/amneziawg.css /koolshare/res/amneziawg-0.4.0.css
rm -f /koolshare/res/amneziawg-icons/*.svg
rmdir /koolshare/res/amneziawg-icons 2>/dev/null || true
for key in version install name title description home_url; do dbus remove "softcenter_module_amneziawg_$key"; done
for key in version payload; do dbus remove "amneziawg_$key"; done
rm -f /koolshare/scripts/uninstall_amneziawg.sh
echo '程序已卸载；私密配置保留在 /koolshare/amneziawg/config，便于重新安装。'
