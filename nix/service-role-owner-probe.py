"""VM-only persistent-owner failure/adoption regression, never a host installer.

The probe holds no executable/cgroup FDs: systemd must retain them for the owner.
The existing Cardwire daemon/mode is left untouched (Hybrid fixture baseline).
"""
import importlib.util
import os
from pathlib import Path
import select
import shutil
import stat
import subprocess
import sys
import time


def main():
    spec = importlib.util.spec_from_file_location(
        'task_probe', Path(__file__).with_name('task-storage-probe.py'))
    primitives = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(primitives)
    primitives.vm_guard()
    unit = 'cardwire-role-owner-vm.service'
    unit_path = Path('/run/systemd/system') / unit
    pins = Path('/sys/fs/bpf/cardwire_role_vm')
    cg = Path('/sys/fs/cgroup/cardwire-role-vm')
    outside = Path('/sys/fs/cgroup/cardwire-owner-outside')
    exe = Path('/tmp/cardwire-role-worker')
    old_exe = Path('/tmp/cardwire-role-worker-original')
    node = Path('/dev/dri/renderD129')
    assert not any(p.exists() for p in (unit_path, pins, cg, outside, old_exe))
    original_mode = stat.S_IMODE(node.stat().st_mode)
    children = []
    saved_map_fd = None
    replacement_fd = None

    def control(*args, check=True):
        result = subprocess.run(['systemctl', *args], text=True, capture_output=True,
                                timeout=25, check=False)
        if check and result.returncode:
            raise RuntimeError(f'systemctl {args}: {result.stderr.strip()}')
        return result

    def prop(name):
        return control('show', unit, '-p', name, '--value').stdout.strip()

    def receive(p, expected, kind='open'):
        assert select.select([p.stdout], [], [], 10)[0], 'worker timeout'
        words = p.stdout.readline().split()
        assert len(words) == 3 and words[0] == kind, words
        assert int(words[2]) == expected, words

    def spawn(group, expected):
        def setup():
            (group / 'cgroup.procs').write_text(str(os.getpid()))
        p = subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             text=True, bufsize=1, preexec_fn=setup)
        children.append(p)
        receive(p, expected, 'constructor')
        return p

    def command(p, value='open', expected=0, kind='open'):
        p.stdin.write(value + '\n')
        p.stdin.flush()
        receive(p, expected, kind)

    def finish(p):
        p.stdin.close()
        assert p.wait(timeout=10) == 0
        children.remove(p)

    def check_access(p):
        command(p)
        command(p, 'fork', -13, 'fork')
        finish(spawn(outside, -13))

    def owner_ready():
        assert prop('ActiveState') == 'active'
        assert prop('NFileDescriptorStore') == '3'
        return prop('MainPID'), prop('InvocationID')

    try:
        cg.mkdir()
        outside.mkdir()
        os.chmod(node, 0o666)
        finish(spawn(outside, 0))  # Baseline proves the node is otherwise openable.
        loader = os.environ['CARDWIRE_VM_ELF_LOADER']
        libraries = os.environ['LD_LIBRARY_PATH']
        assert all(c not in loader + libraries for c in '\n\r"%\\ ')
        unit_path.write_text(
            '[Unit]\nDescription=Disposable Cardwire role-owner test\n'
            '[Service]\nType=notify\nNotifyAccess=main\n'
            'FileDescriptorStoreMax=3\nFileDescriptorStorePreserve=yes\n'
            'TimeoutStartSec=20\nTimeoutStopSec=5\nRestart=no\n'
            f'Environment="CARDWIRE_VM_ELF_LOADER={loader}" "LD_LIBRARY_PATH={libraries}"\n'
            f'ExecStart={loader} /tmp/cardwire-role-owner\n')
        control('daemon-reload')
        control('start', unit)
        first_pid, first_invocation = owner_ready()
        p = spawn(cg, 0)
        check_access(p)
        print('PASS: service owner created guard and stored three verified references', flush=True)

        # The actual owner dies, not just unrelated guest Cardwire. No controller
        # copy of the executable/cgroup FD can hide a broken retention protocol.
        control('kill', '--kill-whom=main', '--signal=KILL', unit)
        deadline = time.monotonic() + 10
        while prop('MainPID') != '0':
            assert time.monotonic() < deadline, 'owner did not terminate'
            time.sleep(0.05)
        assert prop('ActiveState') == 'failed'
        assert prop('NFileDescriptorStore') == '3'
        check_access(p)
        finish(spawn(cg, 0))
        print('PASS: owner SIGKILL leaves exact denial and synchronous new admission intact', flush=True)

        control('start', unit)
        next_pid, next_invocation = owner_ready()
        assert (next_pid, next_invocation) != (first_pid, first_invocation)
        check_access(p)
        journal = subprocess.run(['journalctl', '-b', '-u', unit, '--no-pager'],
                                 check=True, capture_output=True, text=True, timeout=10).stdout
        assert 'ADOPTED: verified stored objects' in journal, journal
        print('PASS: new owner adopted original policy, links and retained identities', flush=True)

        control('stop', unit)
        assert prop('ActiveState') == 'inactive' and prop('NFileDescriptorStore') == '3'
        check_access(p)
        control('start', unit)
        owner_ready()
        print('PASS: explicit stop/start retains policy without an open interval', flush=True)

        # Same path, different inode: adoption must retain the original role,
        # not silently authorize replacement bytes by reopening the pathname.
        control('stop', unit)
        exe.rename(old_exe)
        shutil.copyfile(old_exe, exe)
        os.chmod(exe, 0o755)
        assert exe.stat().st_ino != old_exe.stat().st_ino
        control('start', unit)
        owner_ready()
        check_access(p)
        finish(spawn(cg, -13))
        exe.unlink()
        old_exe.rename(exe)
        finish(spawn(cg, 0))
        print('PASS: executable-path replacement does not acquire the stored role', flush=True)

        # A foreign map with identical type/size is still the wrong object.
        control('stop', unit)
        task_pin = pins / 'VM_ROLE_TASKS'
        saved_map_fd = primitives.object_operation(7, task_pin)
        replacement_fd = primitives.create_map()
        task_pin.unlink()
        primitives.object_operation(6, task_pin, replacement_fd)
        rejected = control('start', unit, check=False)
        assert rejected.returncode != 0, 'owner accepted a substituted policy map'
        assert prop('ActiveState') == 'failed'
        check_access(p)  # Original attached program still references its map.
        task_pin.unlink()
        primitives.object_operation(6, task_pin, saved_map_fd)
        control('reset-failed', unit)  # Six bounded starts otherwise hit the VM's default rate limit.
        assert prop('NFileDescriptorStore') == '3'
        control('start', unit)
        owner_ready()
        check_access(p)
        print('PASS: substituted pinned map rejected; original enforcement never replaced', flush=True)
        finish(p)

        control('stop', unit)
        old_cgroup_id = cg.stat().st_ino
        cg.rmdir()
        cg.mkdir()
        assert cg.stat().st_ino != old_cgroup_id
        control('start', unit)
        owner_ready()
        finish(spawn(cg, -13))
        print('PASS: recreated cgroup path is not silently reauthorized on owner adoption', flush=True)
        print('SERVICE_ROLE_OWNER_VM_PASSED (not installed desktop profiles)', flush=True)
    finally:
        for p in children:
            if not p.stdin.closed:
                p.stdin.close()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=5)
        if unit_path.exists():
            control('stop', unit, check=False)
        # Fixture-only teardown, not a production profile deactivation protocol.
        for name in ('open_link', 'exec_link', 'VM_ROLE_CONFIG', 'VM_ROLE_CGROUP', 'VM_ROLE_TASKS'):
            path = pins / name
            if path.exists():
                path.unlink()
        for fd in (replacement_fd, saved_map_fd):
            if fd is not None:
                os.close(fd)
        if unit_path.exists():
            control('reset-failed', unit, check=False)
            control('clean', '--what=fdstore', unit)
            unit_path.unlink()
            control('daemon-reload')
            control('reset-failed', unit, check=False)
        if old_exe.exists():
            if exe.exists():
                exe.unlink()
            old_exe.rename(exe)
        for path in (pins, cg, outside):
            if path.exists():
                path.rmdir()
        os.chmod(node, original_mode)


if __name__ == '__main__':
    if sys.argv[1:] != ['--vm-only']:
        raise SystemExit('Only --vm-only in the explicit disposable test guest')
    main()
