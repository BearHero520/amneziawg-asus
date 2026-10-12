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


def check_case(with_cru=True, missing_dbus=False):
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
        write(ks / 'scripts/base.sh', '# mock softcenter\n')
        # Rewrite ONLY filesystem roots and executable search directories.
        # All lifecycle logic is the real shipped script.
        for script in package.rglob('*.sh'):
            text = script.read_text(encoding='utf-8')
            assert 'command -v' not in text, script
            text = text.replace('/koolshare', shell_path(ks)).replace('/jffs/configs', shell_path(root / 'jffs/configs'))
            text = text.replace('export PATH=' + shell_path(ks) + '/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                                'export PATH="' + shell_path(mock) + ':' + shell_path(ks) + '/bin:/usr/bin:/bin"')
            text = text.replace(shell_path(ks) + '/bin /usr/sbin /usr/bin /sbin /bin',
                                '"' + shell_path(mock) + '" "' + shell_path(ks) + '/bin"')
            write(script, text)
        def fake(name, body):
            write(mock / name, '#!/bin/sh\n' + body + '\n')
        fake('uname', 'echo aarch64')
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
        init = root / 'bash-env'
        write(init, 'enable -n command\n')
        env = dict(os.environ, BASH_ENV=shell_path(init), AWG_TEST_LOG=shell_path(log))
        def run(script, *args):
            return subprocess.run([str(BASH), shell_path(script), *args], env=env,
                                  capture_output=True, encoding='utf-8', errors='replace', timeout=30)
        disabled = subprocess.run([str(BASH), '-c', 'command -v dbus'], env=env, capture_output=True)
        assert disabled.returncode == 127, 'command builtin must be unavailable'
        result = run(package / 'install.sh')
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
        for action in ('status','server-enable','server-disable','logs','diagnose'):
            assert api_response(action) == {'ok': True, 'message': '状态已刷新'}, action
        assert api_response('unknown')['ok'] is False
        write(core, '#!/bin/sh\nexit 1\n')
        assert api_response('status')['ok'] is False
        write(core, original_core)
        calls = log.read_text(encoding='utf-8')
        for call in ('ctl boot', 'ctl recover', 'ctl down', 'ctl server-boot', 'ctl server-recover', 'ctl server-down', 'softcenter_module_amneziawg_version=0.4.0'):
            assert call in calls, call
        assert ('cru a amneziawg_watch' in calls) == with_cru
        result = run(ks / 'scripts/uninstall_amneziawg.sh')
        assert result.returncode == 0, (result.stdout, result.stderr)
        assert not (ks / 'bin/amneziawg-go').exists()
        assert settings.is_file(), 'uninstall must preserve private configuration'
        assert 'awgs0' not in dns_add.read_text()
        assert 'server=/example.test/192.168.50.9' in dns_add.read_text()
        assert ('cru d amneziawg_watch' in log.read_text(encoding='utf-8')) == with_cru
        print('PASS install/start/recover/stop/uninstall without command; cru=' + str(with_cru))


if __name__ == '__main__':
    check_case()
    check_case(with_cru=False)
    check_case(missing_dbus=True)
