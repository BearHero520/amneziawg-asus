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
umask 077
DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
[ -f /koolshare/scripts/base.sh ] || { echo '需要 ASUSGO / KoolCenter 软件中心'; exit 1; }
package_arch="$(cat "$DIR/package-arch")"
case "$package_arch:$(uname -m)" in arm64:aarch64|armv7:armv7l) ;; *) echo '安装包架构不匹配，请选择 ARM64 或 ARMv7 对应包'; exit 1 ;; esac
kernel="$(uname -r)"
major="$(echo "$kernel" | cut -d. -f1)"; minor="$(echo "$kernel" | cut -d. -f2)"
case "$major:$minor" in *[!0-9:]*|:*) echo '无法识别 Linux 内核版本'; exit 1 ;; esac
[ "$major" -gt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -ge 2 ]; } || { echo '当前核心需要 Linux 3.2 或更新版本；不支持旧版 2.6 固件'; exit 1; }
[ ! -f /koolshare/amneziawg/update-busy ] || { echo '核心更新或恢复尚未结束，取消安装'; exit 1; }
for tool in dbus ip iptables; do has_tool "$tool" || { echo "缺少 $tool"; exit 1; }; done
chmod 755 "$DIR/bin/amneziawg-go"
"$DIR/bin/amneziawg-go" --version || { echo '核心无法在当前固件运行'; exit 1; }
need="$(du -sk "$DIR" | awk '{print $1}')"
free="$(df -k /koolshare | awk 'END {print $4}')"
[ "$free" -gt "$((need + 2048))" ] || { echo 'JFFS 可用空间不足（需要安装包解压大小加 2 MB 余量）'; exit 1; }
if [ -x /koolshare/bin/amneziawg-go ]; then
 if [ -f /tmp/amneziawg-asus/server-state.json ]; then
  /koolshare/bin/amneziawg-go ctl server-down || { echo "服务端清理失败，保留旧程序"; exit 1; }
 fi
 /koolshare/bin/amneziawg-go ctl down || { echo '旧版本清理失败，取消升级'; exit 1; }
fi
mkdir -p /koolshare/amneziawg/config /koolshare/amneziawg/licenses /koolshare/init.d
chmod 700 /koolshare/amneziawg /koolshare/amneziawg/config
cp "$DIR/bin/amneziawg-go" /koolshare/bin/amneziawg-go.new
chmod 755 /koolshare/bin/amneziawg-go.new
mv /koolshare/bin/amneziawg-go.new /koolshare/bin/amneziawg-go
printf '%s\n' '0.5.0' > /koolshare/amneziawg/plugin-version
rm -f /koolshare/bin/amneziawg-go.previous /koolshare/amneziawg/core-backup.json /koolshare/amneziawg/update-offer.json /koolshare/amneziawg/update-state.json
cp "$DIR/scripts/amneziawg_api.sh" /koolshare/scripts/amneziawg_api.sh
cp "$DIR/scripts/amneziawg_service.sh" /koolshare/scripts/amneziawg_service.sh
cp "$DIR/uninstall.sh" /koolshare/scripts/uninstall_amneziawg.sh
cp "$DIR/webs/Module_amneziawg.asp" /koolshare/webs/Module_amneziawg.asp
cp "$DIR/res/amneziawg.js" /koolshare/res/amneziawg.js
cp "$DIR/res/amneziawg-ui.js" /koolshare/res/amneziawg-ui.js
cp "$DIR/res/amneziawg-qrcode.js" /koolshare/res/amneziawg-qrcode.js
cp "$DIR/res/amneziawg-config.js" /koolshare/res/amneziawg-config.js
chmod 644 /koolshare/res/amneziawg-qrcode.js /koolshare/res/amneziawg-config.js
cp "$DIR/res/amneziawg-core.js" /koolshare/res/amneziawg-core.js
chmod 644 /koolshare/res/amneziawg-core.js
cp "$DIR/res/amneziawg-logs.js" /koolshare/res/amneziawg-logs.js
chmod 644 /koolshare/res/amneziawg-logs.js
cp "$DIR/res/amneziawg-server.js" /koolshare/res/amneziawg-server.js
chmod 644 /koolshare/res/amneziawg-server.js
cp "$DIR/res/amneziawg-0.5.0.css" /koolshare/res/amneziawg-0.5.0.css
mkdir -p /koolshare/res/amneziawg-icons
cp "$DIR/res/amneziawg-icons/"*.svg /koolshare/res/amneziawg-icons/
chmod 755 /koolshare/res/amneziawg-icons
chmod 644 /koolshare/res/amneziawg-ui.js /koolshare/res/amneziawg-0.5.0.css /koolshare/res/amneziawg-icons/*.svg
cp "$DIR/res/icon-amneziawg.png" /koolshare/res/icon-amneziawg.png
cp "$DIR/licenses/"* /koolshare/amneziawg/licenses/
chmod 755 /koolshare/scripts/amneziawg_*.sh /koolshare/scripts/uninstall_amneziawg.sh
chmod 644 /koolshare/webs/Module_amneziawg.asp /koolshare/res/amneziawg.js /koolshare/res/icon-amneziawg.png
ln -sf /koolshare/scripts/amneziawg_service.sh /koolshare/init.d/S95amneziawg.sh
ln -sf /koolshare/scripts/amneziawg_service.sh /koolshare/init.d/N95amneziawg.sh
if has_tool cru; then
 cru a amneziawg_watch '*/1 * * * * /koolshare/bin/amneziawg-go ctl watch >/dev/null 2>&1'
fi
if [ ! -f /koolshare/amneziawg/config/settings.json ]; then
 printf '%s\n' '{"mode":"tunnel","source":"","auto":false}' > /koolshare/amneziawg/config/settings.json
fi
# Register only our VPN interface with ASUS dnsmasq; preserve other additions.
DNS_ADD=/jffs/configs/dnsmasq.conf.add
mkdir -p /jffs/configs
if ! grep -q '^# BEGIN AMNEZIAWG DNS$' "$DNS_ADD" 2>/dev/null; then
 { [ ! -f "$DNS_ADD" ] || cat "$DNS_ADD"; printf '\n%s\n' '# BEGIN AMNEZIAWG DNS'; printf '%s\n' 'interface=awgs0' 'no-dhcp-interface=awgs0' '# END AMNEZIAWG DNS'; } > "$DNS_ADD.awg-new"
 if has_tool dnsmasq; then dnsmasq --test --conf-file="$DNS_ADD.awg-new" || { rm -f "$DNS_ADD.awg-new"; exit 1; }; fi
 mv "$DNS_ADD.awg-new" "$DNS_ADD"
 if has_tool service; then service restart_dnsmasq; fi
fi
dbus set amneziawg_version=0.5.0
dbus set softcenter_module_amneziawg_version=0.5.0
dbus set softcenter_module_amneziawg_install=1
dbus set softcenter_module_amneziawg_name=amneziawg
dbus set softcenter_module_amneziawg_title=AmneziaWG
dbus set softcenter_module_amneziawg_description='AmneziaWG 客户端与服务端 · ARM64 / ARMv7 测试版'
dbus set softcenter_module_amneziawg_home_url=Module_amneziawg.asp
echo 'AmneziaWG 安装完成。隧道尚未启动，请打开插件导入配置。'
