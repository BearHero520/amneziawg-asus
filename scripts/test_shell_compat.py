"""Run the actual shell lifecycle in an isolated mock router, without command builtin.

Git Bash on Windows is sufficient. No router or host network state is changed.
"""
import os
import base64
import json
import re
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
BASH = Path(os.environ.get('AWG_TEST_BASH', r'C:\Program Files\Git\bin\bash.exe'))


def shell_path(path):
    value = Path(path).resolve().as_posix()
    if len(value) > 1 and value[1] == ':':
        return '/' + value[0].lower() + value[2:]
    return value


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8', newline='\n')
    path.chmod(0o755)


def check_case(with_cru=True, missing_dbus=False, arch="arm64", machine="aarch64", kernel="5.4.0", rejected=""):
    with tempfile.TemporaryDirectory(prefix='awg-shell-') as temp:
        root = Path(temp)
        ks = root / 'koolshare'
        package = root / 'package'
        mock = root / 'mock'
        log = root / 'calls.log'
        for directory in ('bin', 'scripts', 'webs', 'res'):
            (ks / directory).mkdir(parents=True)
        mock.mkdir()
        dns_add = root / 'jffs/configs/dnsmasq.conf.add'
        write(dns_add, '# existing user DNS config\nserver=/example.test/192.168.50.9\n')
        shutil.copytree(ROOT / 'plugin', package)
        write(package / 'package-arch', arch+'\n')
        write(ks / 'scripts/base.sh', '# mock softcenter\n')
        # Rewrite ONLY filesystem roots and executable search directories.
        # All lifecycle logic is the real shipped script.
        for script in package.rglob('*.sh'):
            text = script.read_text(encoding='utf-8')
            assert 'command -v' not in text, script
            text = text.replace('/koolshare', shell_path(ks)).replace('/jffs/configs', shell_path(root / 'jffs/configs'))
            text = text.replace('/jffs/scripts', shell_path(root / 'jffs/scripts'))
            text = text.replace('/tmp/amneziawg-asus/policy', shell_path(root / 'policy-runtime'))
            text = text.replace('export PATH=/bin:/usr/bin:/sbin:/usr/sbin:' + shell_path(ks) + '/bin',
                                'export PATH="' + shell_path(mock) + ':' + shell_path(ks) + '/bin:/usr/bin:/bin"')
            text = text.replace('export PATH=' + shell_path(ks) + '/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                                'export PATH="' + shell_path(mock) + ':' + shell_path(ks) + '/bin:/usr/bin:/bin"')
            text = text.replace(shell_path(ks) + '/bin /usr/sbin /usr/bin /sbin /bin',
                                '"' + shell_path(mock) + '" "' + shell_path(ks) + '/bin"')
            write(script, text)
        def fake(name, body):
            write(mock / name, '#!/bin/sh\n' + body + '\n')
        fake('uname', f'[ \"$1\" = -r ] && echo {kernel} || echo {machine}')
        fake('nvram', 'echo RT-BE88U')
        fake('df', "printf 'Filesystem 1K-blocks Used Available Use%% Mounted\\nmock 99999 0 99999 0 /\\n'")
        for name in ('ip', 'iptables'):
            fake(name, 'exit 0')
        logger = 'printf "%s\\n" "$0 $*" >> "$AWG_TEST_LOG"'
        if not missing_dbus:
            fake('dbus', logger)
        if with_cru:
            fake('cru', logger)
        write(package / 'bin/amneziawg-go', '#!/bin/sh\n' + logger + '\n')
        legacy = ks / 'awgmerlin/settings'
        write(legacy, 'awg_autostart 1\nawgs_autostart 1\nawgs_port 51821\n')
        advanced_settings = ks / 'amneziawg/config/advanced/settings'
        write(advanced_settings, 'awgs_port 51821\n')
        write(ks / 'amneziawg/advanced/manage.sh', '#!/bin/sh\n' + logger + '\n[ "$1" = uninstall ]\n')
        postconf = root / 'jffs/scripts/dnsmasq.postconf'
        write(postconf, '#!/bin/sh\n# user postconf line\n')
        init = root / 'bash-env'
        write(init, 'enable -n command\n')
        env = dict(os.environ, BASH_ENV=shell_path(init), AWG_TEST_LOG=shell_path(log))
        def run(script, *args):
            return subprocess.run([str(BASH), shell_path(script), *args], env=env,
                                  capture_output=True, encoding='utf-8', errors='replace', timeout=30)
        disabled = subprocess.run([str(BASH), '-c', 'command -v dbus'], env=env, capture_output=True)
        assert disabled.returncode == 127, 'command builtin must be unavailable'
        result = run(package / 'install.sh')
        if rejected:
            assert result.returncode != 0 and rejected in result.stdout, result
            assert not (ks / "bin/amneziawg-go").exists()
            print("PASS rejected " + rejected)
            return
        if missing_dbus:
            assert result.returncode != 0 and '缺少 dbus' in result.stdout, result
            assert not (ks / 'bin/amneziawg-go').exists()
            assert 'command: not found' not in result.stderr
            print('PASS missing dependency rejected before copying')
            return
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert 'command: not found' not in result.stderr
        assert (ks / 'bin/amneziawg-go').is_file()
        html = (ks / 'webs/Module_amneziawg.asp').read_text(encoding='utf-8')
        for url in re.findall(r'(?:href|src)="(/res/[^\"]+)"', html):
            if url=='/res/softcenter.css': continue # firmware-owned stylesheet
            if '.css' in url:
                assert '?' not in url, 'ASUS httpd returns 404 for CSS query strings'
            path = ks / url.split('?')[0].lstrip('/')
            assert path.is_file(), 'installed asset missing: ' + url

        dns_text = dns_add.read_text()
        assert 'interface=awgs0' in dns_text and 'no-dhcp-interface=awgs0' in dns_text
        assert 'server=/example.test/192.168.50.9' in dns_text
        for license_file in (ks / 'amneziawg/licenses').glob('*'):
            license_file.chmod(0o644) # Windows read-only bit from upstream licenses
        result = run(package / 'install.sh')
        assert result.returncode == 0, (result.stdout,result.stderr)
        assert dns_add.read_text() == dns_text, 'DNS installation must be idempotent'
        assert (ks / 'config').exists() is False
        settings = ks / 'amneziawg/config/settings.json'
        assert settings.is_file()
        assert advanced_settings.read_text() == 'awgs_port 51821\n'
        assert legacy.read_text() == 'awg_autostart 1\nawgs_autostart 1\nawgs_port 51821\n'
        assert postconf.read_text().count('# amneziawg-policy-postconf') == 1
        assert '# user postconf line' in postconf.read_text()
        assert (ks / 'amneziawg/policy/run.sh').is_file()
        assert (ks / 'res/amneziawg-routing.js').is_file()
        assert not list((ks / 'webs').glob('*_advanced_*'))
        # A reboot clears /tmp; the postconf hook may only refer to files which exist.
        conf = root / 'dnsmasq.conf'
        conf.write_text('servers-file=/tmp/resolv.dnsmasq\nserver=9.9.9.9\n')
        result = run(ks / 'amneziawg/policy/dnsmasq-postconf.sh', shell_path(conf))
        assert result.returncode == 0 and 'policy-runtime' not in conf.read_text(), result
        policy_runtime = root / 'policy-runtime'
        write(policy_runtime / 'dns-active', '')
        write(policy_runtime / 'dnsmasq_awg.conf', 'ipset=/example.com/awgp_dst\n')
        result = run(ks / 'amneziawg/policy/dnsmasq-postconf.sh', shell_path(conf))
        assert result.returncode == 0 and 'dnsmasq_awg.conf' in conf.read_text(), result
        assert 'server=9.9.9.9' in conf.read_text()
        assert 'servers-file=' in conf.read_text()
        write(policy_runtime / 'dnsmasq_tunnel.conf', 'no-resolv\nserver=10.1.0.1@awg0\n')
        result = run(ks / 'amneziawg/policy/dnsmasq-postconf.sh', shell_path(conf))
        assert result.returncode == 0 and 'servers-file=' not in conf.read_text(), result
        assert conf.read_text().count('dnsmasq_awg.conf') == 1
        assert 'dnsmasq_tunnel.conf' in conf.read_text()
        service = ks / 'scripts/amneziawg_service.sh'
        for action in ('start', 'start_nat', 'stop'):
            result = run(service, action)
            assert result.returncode == 0, (action, result.stdout, result.stderr)
        # Exercise the shipped API script with the firmware's observed wrapper.
        write(ks / "scripts/base.sh", "http_response() { printf '{\"result\": \"%s\"}\\n' \"$1\"; }\n")
        core = ks / 'bin/amneziawg-go'
        original_core = core.read_text(encoding='utf-8')
        encoded = base64.b64encode(json.dumps({'ok': True, 'message': '状态已刷新'}, ensure_ascii=False).encode()).decode()
        write(core, '#!/bin/sh\n[ "$1" = web ] || exit 1\nprintf \'%s\\n\' \'AWG64:' + encoded + '\'\n')
        def api_response(action):
            response = run(ks / 'scripts/amneziawg_api.sh', '123', action)
            assert response.returncode == 0, response.stderr
            value = json.loads(response.stdout)['result']
            assert value.startswith('AWG64:')
            return json.loads(base64.b64decode(value[6:]))
        for action in ('status','server-enable','server-disable','server-route','traffic-status','traffic-start','traffic-stop','routing-refresh','logs','diagnose','core-status','core-check','core-upgrade','core-rollback'):
            assert api_response(action) == {'ok': True, 'message': '状态已刷新'}, action
        assert api_response('unknown')['ok'] is False
        write(core, '#!/bin/sh\nexit 1\n')
        assert api_response('status')['ok'] is False
        write(core, original_core)
        calls = log.read_text(encoding='utf-8')
        for call in ('ctl boot', 'ctl recover', 'ctl down', 'ctl server-boot', 'ctl server-recover', 'ctl server-service-stop', 'softcenter_module_amneziawg_version=0.5.5', '/advanced/manage.sh uninstall'):
            assert call in calls, call
        assert ('cru a amneziawg_watch' in calls) == with_cru
        result = run(ks / 'scripts/uninstall_amneziawg.sh')
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert not (ks / 'bin/amneziawg-go').exists()
        assert settings.is_file(), 'uninstall must preserve private configuration'
        assert advanced_settings.is_file(), 'uninstall must preserve private advanced configuration'
        assert '# amneziawg-policy-postconf' not in postconf.read_text()
        assert '# user postconf line' in postconf.read_text()
        assert not (ks / 'webs/Module_amneziawg_advanced_client.asp').exists()
        assert not (ks / 'webs/Module_amneziawg_advanced_server.asp').exists()
        assert not (ks / 'scripts/amneziawg_advanced_api.sh').exists()
        assert not (ks / 'amneziawg/policy/run.sh').exists()
        assert 'awgs0' not in dns_add.read_text()
        assert 'server=/example.test/192.168.50.9' in dns_add.read_text()
        assert ('cru d amneziawg_watch' in log.read_text(encoding='utf-8')) == with_cru
        print('PASS install/start/recover/stop/uninstall without command; cru=' + str(with_cru))


def check_policy_sets():
    with tempfile.TemporaryDirectory(prefix='awg-policy-') as temp:
        root = Path(temp)
        tools = root / 'tools'
        runtime = root / 'runtime'
        sets = root / 'sets'
        sets.mkdir()
        write(tools / 'ipset', """#!/bin/sh
case "$1" in
    version) exit 0 ;;
    list|save) cat "$SETS/$2" ;;
    create) [ ! -f "$SETS/$2" ] && touch "$SETS/$2" ;;
    rename) mv "$SETS/$2" "$SETS/$3" ;;
    swap) mv "$SETS/$2" "$SETS/.swap" && mv "$SETS/$3" "$SETS/$2" && mv "$SETS/.swap" "$SETS/$3" ;;
    destroy) rm -f "$SETS/$2" ;;
    restore) while read -r op name value rest; do
        [ -f "$SETS/$name" ] || exit 1
        printf '%s %s %s %s\n' "$op" "$name" "$value" "$rest" >> "$SETS/$name"
    done ;;
    *) exit 1 ;;
esac
""")
        for utility in ('dnsmasq', 'logger', 'modprobe'):
            write(tools / utility, '#!/bin/sh\nexit 0\n')
        for script in ('merlin.sh', 'run.sh'):
            text = (ROOT / 'plugin/policy' / script).read_text(encoding='utf-8')
            text = text.replace('/usr/sbin/ipset', shell_path(tools / 'ipset'))
            text = text.replace('/tmp/amneziawg-asus/policy', shell_path(runtime))
            text = text.replace('/koolshare/amneziawg/policy', shell_path(root))
            text = text.replace('/bin:/usr/bin:/sbin:/usr/sbin:/koolshare/bin', shell_path(tools) + ':/bin:/usr/bin')
            write(root / script, text)
        write(runtime / 'settings',
              'awg_geo_policies 1:a;2:b\n'
              'awg_geo_custom_domains common.example,www.one.example\n'
              'awg_geo_2_custom_domains common.example\n'
              'awg_geo_exc_domains blocked.example\n'
              'awg_geo_2_custom_ips 203.0.113.0/24\n')
        env = dict(os.environ, SETS=shell_path(sets))

        def run(action):
            return subprocess.run([str(BASH), shell_path(root / 'run.sh'), action], env=env,
                                  capture_output=True, encoding='utf-8', errors='replace', timeout=30)

        result = run('prepare')
        assert result.returncode == 0, (result.stdout, result.stderr)
        dns = (runtime / 'dnsmasq_awg.conf').read_text()
        assert 'ipset=/common.example/awgp_dst,awgp_dst2' in dns, dns
        assert 'ipset=/blocked.example/awgp_dst_x' in dns, dns
        assert '203.0.113.0/24' in (sets / 'awgp_dst2').read_text()
        result = run('prepare')
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert (runtime / 'dnsmasq_awg.conf').read_text() == dns
        result = run('clear')
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert not list(sets.iterdir())
        # A conflicting foreign set must survive the aborted startup.
        write(sets / 'awgp_dst', 'foreign\n')
        result = run('prepare')
        assert result.returncode != 0
        result = run('clear')
        assert result.returncode == 0 and (sets / 'awgp_dst').read_text() == 'foreign\n'
        print('PASS shared Geo domains, list membership, idempotent rebuild and owned set cleanup')


if __name__ == '__main__':
    check_case()
    check_case(with_cru=False)
    check_case(missing_dbus=True)

    check_case(arch="armv7", machine="armv7l")
    check_case(arch="armv7", rejected="架构不匹配")
    check_case(kernel="2.6.36", rejected="Linux 3.2")
    check_policy_sets()
