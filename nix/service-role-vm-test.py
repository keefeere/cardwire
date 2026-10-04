"""Custom test script for the disposable two-virtio-GPU NixOS test driver.

Build artifacts separately; this script is not a host deployment tool and does
not replace the existing guest Cardwire package. See docs/development/smart.md.
"""
import os
from pathlib import Path
import shlex
from datetime import timedelta

assert 'machine' in globals(), 'Use the isolated NixOS test driver'
artifact_dir = Path(os.environ['CARDWIRE_ROLE_ARTIFACT_DIR'])
assert artifact_dir.is_absolute() and artifact_dir.is_dir()
python = os.environ['CARDWIRE_ROLE_PYTHON']
loader = os.environ['CARDWIRE_ROLE_ELF_LOADER']
libraries = os.environ['CARDWIRE_ROLE_LIBRARY_PATH']
assert Path(python).is_absolute() and Path(loader).is_absolute()
probe = os.environ.get('CARDWIRE_ROLE_PROBE', 'service-role-probe.py')
assert probe in ('service-role-probe.py', 'service-role-owner-probe.py',
                 'service-snapshots-probe.py', 'persistent-snapshots-probe.py')

machine.start()
machine.wait_for_unit('default.target')
machine.wait_for_unit('cardwired.service')
machine.succeed('cardwire set hybrid')
machine.succeed('test ! -e /run/cardwire-lifecycle-vm-only')
machine.succeed('touch /run/cardwire-lifecycle-vm-only')
try:
    artifacts = ['cardwire-role-loader', 'cardwire-role-worker',
                 'cardwire-role-guard.bpf.o', probe, 'task-storage-probe.py']
    if probe == 'service-role-owner-probe.py':
        artifacts.append('cardwire-role-owner')
    if probe == 'service-snapshots-probe.py':
        artifacts.extend(['cardwire-service-snapshots', 'cardwire-service-guard.bpf.o'])
    if probe == 'persistent-snapshots-probe.py':
        artifacts.extend(['cardwire-persistent-snapshots', 'cardwire-service-guard.bpf.o'])
    for name in artifacts:
        machine.copy_from_host(str(artifact_dir / name), '/tmp/' + name)
    machine.succeed('chmod 755 /tmp/cardwire-role-loader /tmp/cardwire-role-worker')
    if probe == 'service-role-owner-probe.py':
        machine.succeed('chmod 755 /tmp/cardwire-role-owner')
    if probe == 'service-snapshots-probe.py':
        machine.succeed('chmod 755 /tmp/cardwire-service-snapshots')
    if probe == 'persistent-snapshots-probe.py':
        machine.succeed('chmod 755 /tmp/cardwire-persistent-snapshots')
    command = shlex.join([
        'env', 'CARDWIRE_VM_ELF_LOADER=' + loader, 'LD_LIBRARY_PATH=' + libraries,
        python, '/tmp/' + probe, '--vm-only',
    ])
    print(machine.succeed(command, timeout=timedelta(seconds=120)))
finally:
    machine.succeed('rm /run/cardwire-lifecycle-vm-only')
