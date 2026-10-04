"""Crash-safe permission commits over retained roles; disposable virtio VM only.

The controller owns no role/object FDs. The actual root-owned test service dies;
PID1 plus the pinned maps/links must preserve both positive and negative access.
No installed Cardwire daemon or host GPU is restarted or modified.
"""
import importlib.util
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import time


def main():
    spec = importlib.util.spec_from_file_location(
        'task_probe', Path(__file__).with_name('task-storage-probe.py'))
    primitives = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(primitives)
    primitives.vm_guard()
    unit = 'cardwire-snapshot-owner-vm.service'
    unit_path = Path('/run/systemd/system') / unit
    pins = Path('/sys/fs/bpf/cardwire_snapshots_vm')
    endpoint = Path('/run/cardwire-snapshot-owner-vm.sock')
    groups = [Path('/sys/fs/cgroup/cardwire-persistent-' + part)
              for part in ('a', 'b', 'outside')]
    a, b, outside = groups
    assert not any(path.exists() for path in [unit_path, pins, endpoint, *groups])
    worker = '/tmp/cardwire-role-worker'
    children = []
    saved_map = replacement_map = None

    def control(*args, check=True):
        result = subprocess.run(['systemctl', *args], capture_output=True, text=True, timeout=25)
        if check and result.returncode:
            raise RuntimeError(f'{args}: {result.stderr}')
        return result

    def prop(name):
        return control('show', unit, '-p', name, '--value').stdout.strip()

    def request(message, generation=None, rejected=False, crash=False):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(10)
            client.connect(str(endpoint))
            client.sendall((message + '\n').encode())
            result = b''
            while not result.endswith(b'\n'):
                chunk = client.recv(4096)
                if not chunk:
                    break
                result += chunk
            result = result.decode().strip()
        if crash:
            assert not result, result
        elif rejected:
            assert result.startswith(f'REJECTED {generation} '), result
        else:
            assert result == f'OK {generation}', result

    def ready(generation):
        assert prop('ActiveState') == 'active'
        assert prop('NFileDescriptorStore') == '6'
        request('status', generation)
        return prop('MainPID')

    def dead():
        deadline = time.monotonic() + 10
        while prop('MainPID') != '0':
            assert time.monotonic() < deadline, 'owner still alive'
            time.sleep(0.05)
        assert prop('ActiveState') == 'failed'
        assert prop('NFileDescriptorStore') == '6'

    def receive(process, expected, kind):
        assert select.select([process.stdout], [], [], 10)[0], 'worker timeout'
        fields = process.stdout.readline().split()
        assert len(fields) == 3 and fields[0] == kind and int(fields[2]) == expected, fields
        return int(fields[1])

    def spawn(group, expected=0):
        def setup():
            (group / 'cgroup.procs').write_text(str(os.getpid()))
        process = subprocess.Popen([worker], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   text=True, bufsize=1, preexec_fn=setup)
        children.append(process)
        assert receive(process, expected, 'constructor') == process.pid
        return process

    def command(process, text='open', expected=0, kind='open'):
        process.stdin.write(text + '\n')
        process.stdin.flush()
        return receive(process, expected, kind)

    def finish(process):
        process.stdin.close()
        assert process.wait(timeout=5) == 0
        children.remove(process)

    def access(render, inference, allowed=True):
        command(render, expected=0 if allowed else -13)
        assert command(inference) == inference.pid
        finish(spawn(outside, -13))

    try:
        for group in groups:
            group.mkdir()
        finish(spawn(outside))
        loader, libs = os.environ['CARDWIRE_VM_ELF_LOADER'], os.environ['LD_LIBRARY_PATH']
        assert all(c not in loader + libs for c in '\n\r"%\\ ')
        unit_path.write_text(
            '[Unit]\nDescription=Disposable persistent snapshot regression\nStartLimitBurst=20\n'
            '[Service]\nType=notify\nNotifyAccess=main\nRestart=no\n'
            'FileDescriptorStoreMax=64\nFileDescriptorStorePreserve=yes\n'
            'TimeoutStartSec=20\nTimeoutStopSec=5\n'
            f'Environment="CARDWIRE_VM_ELF_LOADER={loader}" "LD_LIBRARY_PATH={libs}"\n'
            f'ExecStart={loader} /tmp/cardwire-persistent-snapshots\n')
        control('daemon-reload')
        control('start', unit)
        first_pid = ready(1)
        finish(spawn(a, -13))
        request('apply 3 1', 2)
        render, inference = spawn(a), spawn(b)
        render_pid, inference_pid = render.pid, inference.pid
        access(render, inference)
        command(render, 'open /dev/dri/card1')
        command(inference, 'open /dev/dri/card1', -13)
        command(render, 'fork', -13, 'fork')
        print('PASS: persisted fixed catalog, distinct render/service permissions', flush=True)

        request('crash-before 0 1', crash=True)
        dead()
        access(render, inference)
        finish(spawn(b))
        control('start', unit)
        assert ready(2) != first_pid
        access(render, inference)
        print('PASS: SIGKILL before commit retains old policy and admits new allowed workers', flush=True)

        request('crash-after 0 1', crash=True)
        dead()
        access(render, inference, False)
        finish(spawn(a, -13))
        control('start', unit)
        ready(3)
        access(render, inference, False)
        request('apply 3 1', 4)
        access(render, inference)
        assert (render.pid, inference.pid) == (render_pid, inference_pid)
        print('PASS: SIGKILL after commit adopts new policy; inference never restarts', flush=True)

        request('prepare 0 1', 4)
        request('apply 1 1', 5)
        request('commit', 5, rejected=True)
        request('apply 4 1', 5, rejected=True)
        access(render, inference)
        command(render, 'open /dev/dri/card1', -13)
        pid = ready(5)
        descriptor_count = len(list(Path(f'/proc/{pid}/fd').iterdir()))
        for generation in range(6, 306):
            mask = 3 if generation % 2 else 0
            request(f'apply {mask} 1', generation)
            command(render, expected=0 if mask else -13)
            assert command(inference) == inference_pid
        assert len(list(Path(f'/proc/{pid}/fd').iterdir())) <= descriptor_count + 2
        ready(305)
        print('PASS: stale/invalid commits rejected; 300 swaps keep FD store and local handles bounded', flush=True)

        control('stop', unit)
        assert prop('ActiveState') == 'inactive' and prop('NFileDescriptorStore') == '6'
        access(render, inference)
        control('start', unit)
        ready(305)
        access(render, inference)
        print('PASS: ordinary stop/start adopts current permissions without an unguarded interval', flush=True)

        control('stop', unit)
        original_pin = pins / 'CW_DEVICES_MAP'
        saved_map = primitives.object_operation(7, original_pin)
        # Same ARRAY ABI, different map ID: adoption must not accept it.
        replacement_map = primitives.bpf(0, struct.pack('<7I16s5I',
            2, 4, 72, 1, 128, 0, 0, b'cw_wrong_inv', 0, 0, 0, 0, 0))
        original_pin.unlink()
        primitives.object_operation(6, original_pin, replacement_map)
        assert control('start', unit, check=False).returncode != 0
        assert prop('ActiveState') == 'failed'
        access(render, inference)
        original_pin.unlink()
        primitives.object_operation(6, original_pin, saved_map)
        control('start', unit)
        ready(305)
        print('PASS: foreign same-ABI pinned map rejected; attached enforcement remains unchanged', flush=True)

        finish(render)
        control('stop', unit)
        old_id = a.stat().st_ino
        a.rmdir()
        a.mkdir()
        assert a.stat().st_ino != old_id
        control('start', unit)
        ready(305)
        finish(spawn(a, -13))
        assert command(inference) == inference_pid
        finish(inference)
        print('PASS: recreated cgroup is not silently registered on owner restart', flush=True)
        print('PERSISTENT_SNAPSHOTS_VM_PASSED (fixed registrations; no host deployment)', flush=True)
    except BaseException:
        journal = subprocess.run(['journalctl', '-b', '-u', unit, '--no-pager', '-n', '100'],
                                 capture_output=True, text=True, timeout=10)
        print(journal.stdout, flush=True)
        raise
    finally:
        for process in children:
            process.stdin.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if unit_path.exists():
            control('stop', unit, check=False)
        # Explicit deactivation is test-fixture teardown, not a desktop API.
        for name in ('exec_link', 'open_link', 'CW_ACTIVE', 'CW_DEVICES_MAP', 'CW_ROLE_TASKS'):
            path = pins / name
            if path.exists():
                path.unlink()
        for fd in (saved_map, replacement_map):
            if fd is not None:
                os.close(fd)
        if unit_path.exists():
            control('reset-failed', unit, check=False)
            control('clean', '--what=fdstore', unit)
            unit_path.unlink()
            control('daemon-reload')
        if endpoint.exists():
            endpoint.unlink()
        if pins.exists():
            pins.rmdir()
        for group in reversed(groups):
            group.rmdir()


if __name__ == '__main__':
    if sys.argv[1:] != ['--vm-only']:
        raise SystemExit('Only --vm-only in the explicit disposable test guest')
    main()
