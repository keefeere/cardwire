"""Disposable-VM acceptance driver for the integrated `service-roles` cardwired.

Replaces the guest package's cardwired binary with the exact native candidate
via explicit loader paths (no ELF patching). CARDWIRE_INTEGRATED_MODE selects:
  probe  - service-roles enabled; run integrated-daemon-probe.py (default)
  suite  - NO service-roles.toml; the unchanged 2-GPU suite must still pass
Never a host deployment tool. Environment: CARDWIRE_ROLE_ARTIFACT_DIR,
CARDWIRE_ROLE_PYTHON, CARDWIRE_ROLE_ELF_LOADER, CARDWIRE_ROLE_LIBRARY_PATH,
CARDWIRE_DAEMON_LIBRARY_PATH, CARDWIRE_DAEMON_SUITE (suite mode only).
"""
import os
from pathlib import Path
import shlex
from datetime import timedelta

assert 'machine' in globals(), 'Use the isolated NixOS test driver'
artifact_dir = Path(os.environ['CARDWIRE_ROLE_ARTIFACT_DIR'])
python = os.environ['CARDWIRE_ROLE_PYTHON']
loader = os.environ['CARDWIRE_ROLE_ELF_LOADER']
libraries = os.environ['CARDWIRE_ROLE_LIBRARY_PATH']
daemon_libraries = os.environ['CARDWIRE_DAEMON_LIBRARY_PATH']
mode = os.environ.get('CARDWIRE_INTEGRATED_MODE', 'probe')
assert mode in ('probe', 'suite') and artifact_dir.is_absolute()
assert all(c not in loader + daemon_libraries for c in '\n\r"%\\ ')

machine.start()
machine.wait_for_unit('default.target')
machine.wait_for_unit('cardwired.service')
machine.succeed('cardwire set hybrid')
machine.succeed('systemctl stop cardwired.service')
for name in ('cardwired-service-roles', 'cardwire-service-guard.bpf.o',
             'cardwire-role-worker', 'integrated-daemon-probe.py',
             'task-storage-probe.py'):
    machine.copy_from_host(str(artifact_dir / name), '/root/' + name)
machine.succeed('chmod 755 /root/cardwired-service-roles /root/cardwire-role-worker')
machine.succeed('mkdir -p /usr/share/hwdata /usr/share/libdrm /run/systemd/system/cardwired.service.d')
machine.succeed('cp /nix/store/71437l93dh58b1r4z1kai3337if73i8x-hwdata-0.410/share/hwdata/pci.ids /usr/share/hwdata/pci.ids')
machine.succeed('cp /nix/store/5qg70j0rzbxqlxlzrq87k4ksgzdwrwr6-libdrm-2.4.134/share/libdrm/amdgpu.ids /usr/share/libdrm/amdgpu.ids')
dropin = (
    '[Service]\nExecStart=\n'
    f'ExecStart={loader} /root/cardwired-service-roles\n'
    f'Environment="LD_LIBRARY_PATH={daemon_libraries}"\n'
    'NotifyAccess=main\nFileDescriptorStoreMax=64\nFileDescriptorStorePreserve=yes\n'
    'ReadWritePaths=/sys/fs/bpf\nRestart=on-failure\nRestartSec=2s\n')
machine.succeed('cat > /run/systemd/system/cardwired.service.d/99-integrated.conf <<"EOF"\n' + dropin + 'EOF')
machine.succeed('test ! -e /run/cardwire-lifecycle-vm-only && touch /run/cardwire-lifecycle-vm-only')
try:
    if mode == 'suite':
        machine.succeed('test ! -e /etc/cardwire/service-roles.toml')
        machine.succeed('systemctl daemon-reload && systemctl start cardwired.service')
        pid = machine.succeed('systemctl show cardwired.service -p MainPID --value').strip()
        machine.succeed('grep -F /root/cardwired-service-roles /proc/' + pid + '/maps')
        suite = os.environ['CARDWIRE_DAEMON_SUITE']
        exec(compile(Path(suite).read_text(), suite, 'exec'), globals())
        print('INTEGRATED_DAEMON_DISABLED_SUITE_PASSED')
    else:
        machine.succeed('systemctl daemon-reload')
        command = shlex.join([
            'env', 'CARDWIRE_VM_ELF_LOADER=' + loader, 'LD_LIBRARY_PATH=' + libraries,
            python, '/root/integrated-daemon-probe.py', '--vm-only',
        ])
        print(machine.succeed(command, timeout=timedelta(seconds=180)))
finally:
    machine.execute('rm -f /run/cardwire-lifecycle-vm-only')
