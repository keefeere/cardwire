"""VM-only real-open test for the synchronous service-role candidate.

Runs only in the disposable two-virtio-GPU fixture. Cardwire stays Hybrid;
the candidate is a separate, last-attached guard, not a released profile.
The controller owns executable/cgroup FDs for the entire test. Guest Cardwire
is stopped/started while the separately pinned guard remains. This does NOT
test daemon ownership/adoption, durable fdstore/reboot policy, or a hostile-user
sandbox.
"""
import ctypes
import importlib.util
import os
from pathlib import Path
import select
import shutil
import stat
import struct
import subprocess
import sys


def main():
    spec = importlib.util.spec_from_file_location(
        'task_probe', Path(__file__).with_name('task-storage-probe.py'))
    primitives = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(primitives)
    primitives.vm_guard()
    loader = [os.environ['CARDWIRE_VM_ELF_LOADER'], '/tmp/cardwire-role-loader']
    worker = '/tmp/cardwire-role-worker'
    wrong_worker = '/tmp/cardwire-role-wrong-worker'
    obj = '/tmp/cardwire-role-guard.bpf.o'
    cg = Path('/sys/fs/cgroup/cardwire-role-vm')
    outside = Path('/sys/fs/cgroup/cardwire-role-vm-outside')
    nested = cg / 'nested'
    pins = Path('/sys/fs/bpf/cardwire_role_vm')
    alias = Path('/tmp/cardwire-role-device')
    node = Path('/dev/dri/renderD129')
    assert not pins.exists() and not cg.exists() and not outside.exists()
    assert not Path(wrong_worker).exists() and not alias.exists()
    children = []
    held = []
    original_mode = stat.S_IMODE(node.stat().st_mode)

    def receive(p, expected, kind=None):
        assert select.select([p.stdout], [], [], 10)[0], 'worker timeout'
        line = p.stdout.readline().split()
        assert len(line) == 3, line
        if kind:
            assert line[0] == kind, line
        assert int(line[2]) == expected, line
        return int(line[1])

    def spawn(path=worker, cgroup=cg, uid=0, expected=0):
        def setup():
            (cgroup / 'cgroup.procs').write_text(str(os.getpid()))
            if uid:
                os.setgroups([])
                os.setgid(uid)
                os.setuid(uid)
        p = subprocess.Popen([path], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             text=True, bufsize=1, preexec_fn=setup)
        children.append(p)
        assert receive(p, expected, 'constructor') == p.pid
        return p

    def command(p, message, expected=0, kind=None):
        p.stdin.write(message + '\n')
        p.stdin.flush()
        return receive(p, expected, kind)

    def finish(p):
        p.stdin.close()
        assert p.wait(timeout=10) == 0
        children.remove(p)

    def map_fd(name):
        fd = primitives.object_operation(7, pins / name)
        held.append(fd)
        return fd

    def update(fd, value):
        key = ctypes.c_uint32(0)
        payload = ctypes.create_string_buffer(value)
        primitives.bpf(2, struct.pack('<I4xQQQ', fd, ctypes.addressof(key),
                                      ctypes.addressof(payload), 0))

    try:
        cg.mkdir()
        outside.mkdir()
        nested.mkdir()
        held.append(os.open(cg, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC))
        held.append(os.open(worker, os.O_PATH | os.O_CLOEXEC))
        shutil.copyfile(worker, wrong_worker)
        os.chmod(wrong_worker, 0o755)
        os.chmod(node, 0o666)
        # Prove DAC/root/nonroot behavior before attaching the candidate.
        finish(spawn())
        finish(spawn(path=wrong_worker))
        finish(spawn(cgroup=outside))
        finish(spawn(uid=65534))
        subprocess.run(loader + [obj, str(cg), worker, str(pins)], check=True, timeout=20)
        assert pins.is_dir()
        # The loader has exited: both links and maps must actually remain.
        print('PASS: loader exited with guard pinned', flush=True)
        p = spawn()
        print('PASS: registered ELF constructor opens GPU immediately', flush=True)
        assert command(p, 'thread', kind='thread') == p.pid
        child_pid = command(p, 'fork', expected=-13, kind='fork')
        assert child_pid != p.pid
        assert command(p, 'exec', kind='constructor') == p.pid
        assert command(p, 'thread-exec', kind='constructor') == p.pid
        print('PASS: threads allowed; fork denied; leader/nonleader exec admitted', flush=True)

        for settings in ({'path': wrong_worker}, {'cgroup': outside},
                         {'cgroup': nested}, {'uid': 65534}):
            finish(spawn(expected=-13, **settings))
        adopted = spawn(cgroup=outside, expected=-13)
        (cg / 'cgroup.procs').write_text(str(adopted.pid))
        command(adopted, 'open', -13, 'open')
        pidfd = os.pidfd_open(adopted.pid)
        held.append(pidfd)
        primitives.element(2, map_fd('VM_ROLE_TASKS'), pidfd, 1)
        command(adopted, 'open', 0, 'open')
        command(adopted, 'thread', 0, 'thread')
        command(adopted, 'fork', -13, 'fork')
        finish(adopted)
        print('PASS: existing-process pidfd adoption remains exact and thread-aware', flush=True)
        assert command(p, 'exec ' + wrong_worker, -13, 'constructor') == p.pid
        command(p, 'open', -13, 'open')
        command(p, 'exec ' + worker, 0, 'constructor')
        print('PASS: wrong executable/UID/cgroup/descendant denied, exec cannot keep old role', flush=True)

        (outside / 'cgroup.procs').write_text(str(p.pid))
        command(p, 'open', -13, 'open')
        (cg / 'cgroup.procs').write_text(str(p.pid))
        command(p, 'open', 0, 'open')
        print('PASS: access rechecks live cgroup membership', flush=True)

        os.mknod(alias, stat.S_IFCHR | 0o600, node.stat().st_rdev)
        command(p, 'open ' + str(alias), 0, 'open')
        denied = spawn(cgroup=outside, expected=-13)
        command(denied, 'open ' + str(alias), -13, 'open')
        command(denied, 'open /dev/null', 0, 'open')
        finish(denied)
        subprocess.run(loader + ['--inspect-pinned', str(pins)], check=True, timeout=20)
        command(p, 'open', 0, 'open')
        print('PASS: device alias covered; unrelated device unaffected; fresh loader inspects pins', flush=True)

        # Probe the stopped interval explicitly, not just before/after restart.
        # The existing daemon must not own the separate candidate's links.
        subprocess.run(['systemctl', 'stop', 'cardwired.service'], check=True, timeout=20)
        try:
            state = subprocess.run(['systemctl', 'show', 'cardwired.service',
                                    '-p', 'ActiveState', '--value'], check=True,
                                   capture_output=True, text=True, timeout=10)
            assert state.stdout.strip() == 'inactive', state.stdout
            command(p, 'open', 0, 'open')
            finish(spawn(cgroup=outside, expected=-13))
            print('PASS: stopped Cardwire does not remove the pinned guard', flush=True)
        finally:
            subprocess.run(['systemctl', 'start', 'cardwired.service'], check=True, timeout=20)
        command(p, 'open', 0, 'open')
        finish(spawn(cgroup=outside, expected=-13))
        print('PASS: restarted Cardwire preserves pinned guard denial and allowed access', flush=True)

        # Revoking the generation must remove existing grants immediately.
        cfg_fd = map_fd('VM_ROLE_CONFIG')
        exe = os.stat(worker)
        def kdev(dev):
            return (os.major(dev) << 20) | os.minor(dev)
        def config(generation):
            return struct.pack('<QQQIIII', generation, cg.stat().st_ino, exe.st_ino,
                               kdev(exe.st_dev), 0, kdev(node.stat().st_rdev), 1)
        update(cfg_fd, config(2))
        command(p, 'open', -13, 'open')
        command(p, 'exec', 0, 'constructor')
        finish(p)
        print('PASS: generation change revokes existing grant until verified exec', flush=True)

        previous_cgroup = cg.stat().st_ino
        nested.rmdir()
        cg.rmdir()
        cg.mkdir()
        assert cg.stat().st_ino != previous_cgroup
        finish(spawn(expected=-13))
        new_cg_fd = os.open(cg, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        held.append(new_cg_fd)
        update(map_fd('VM_ROLE_CGROUP'), struct.pack('<I', new_cg_fd))
        update(cfg_fd, config(3))
        finish(spawn())
        print('PASS: recreated cgroup denied until explicit new registration', flush=True)
        print('SERVICE_ROLE_EXEC_OPEN_VM_PASSED (candidate, not installed Cardwire profiles)')
    finally:
        for p in children:
            if not p.stdin.closed:
                p.stdin.close()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=5)
        # Only fixture-owned pins; never unlink an arbitrary BPF directory.
        for name in ('open_link', 'exec_link', 'VM_ROLE_CONFIG', 'VM_ROLE_CGROUP', 'VM_ROLE_TASKS'):
            path = pins / name
            if path.exists():
                path.unlink()
        for fd in reversed(held):
            os.close(fd)
        if pins.exists():
            pins.rmdir()
        for path in (nested, cg, outside):
            if path.exists():
                path.rmdir()
        if alias.exists():
            alias.unlink()
        if Path(wrong_worker).exists():
            Path(wrong_worker).unlink()
        os.chmod(node, original_mode)


if __name__ == '__main__':
    if sys.argv[1:] != ['--vm-only']:
        raise SystemExit('Only --vm-only in the explicit disposable test guest')
    main()
