"""VM-only acceptance of the integrated `service-roles` cardwired (never a host tool).

Run by integrated-daemon-vm-test.py with the guest cardwired replaced by the
native candidate. Initial policy is deny-all by design; the root-only D-Bus SetPermissions then
admits only the registered role. The
guard must survive daemon SIGKILL/stop, be adopted from systemd's FD store, and
failed adoption must never replace attached enforcement nor stop legacy Cardwire.
"""
import importlib.util
import os
from pathlib import Path
import select
import socket
import stat
import subprocess
import time


def main():
    spec = importlib.util.spec_from_file_location(
        'task_probe', Path(__file__).with_name('task-storage-probe.py'))
    primitives = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(primitives)
    primitives.vm_guard()
    unit = 'cardwired.service'
    config = Path('/etc/cardwire/service-roles.toml')
    pins = Path('/sys/fs/bpf/cardwire-service-roles')
    cg = Path('/sys/fs/cgroup/cardwire-integrated-vm')
    outside = Path('/sys/fs/cgroup/cardwire-integrated-outside')
    cg2 = Path('/sys/fs/cgroup/cardwire-integrated-vm-2')
    node = Path('/dev/dri/renderD129')
    exe = '/root/cardwire-role-worker'
    assert not any(p.exists() for p in (config, pins, cg, outside, cg2))
    original_mode = stat.S_IMODE(node.stat().st_mode)
    children = []
    fds = []

    def control(*args, check=True):
        if args[0] == 'start':  # VM default StartLimitBurst; harness issue only
            subprocess.run(['systemctl', 'reset-failed', unit], capture_output=True, timeout=30)
        r = subprocess.run(['systemctl', *args], text=True, capture_output=True, timeout=30)
        if check and r.returncode:
            raise RuntimeError(f'systemctl {args}: {r.stderr.strip()}')
        return r

    def prop(name):
        return control('show', unit, '-p', name, '--value').stdout.strip()

    def journal():
        return subprocess.run(['journalctl', '-b', '-u', unit, '--no-pager'], text=True,
                              capture_output=True, timeout=15, check=True).stdout

    def spawn(group, expected):
        def setup():
            (group / 'cgroup.procs').write_text(str(os.getpid()))
        p = subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             text=True, bufsize=1, preexec_fn=setup)
        children.append(p)
        assert select.select([p.stdout], [], [], 10)[0], 'worker timeout'
        words = p.stdout.readline().split()
        assert words[0] == 'constructor' and int(words[2]) == expected, (words, expected)
        p.stdin.close()
        assert p.wait(timeout=10) == 0
        children.remove(p)

    active = [cg]  # cgroup of the currently enrolled role

    def denied():
        spawn(active[0], -13)  # registered role: deny-all until a permission commit
        spawn(outside, -13)  # outsider

    def wait_active(previous_pid=None):
        deadline = time.monotonic() + 30
        while True:
            if prop('ActiveState') == 'active' and prop('MainPID') not in ('0', previous_pid):
                return prop('MainPID')
            assert time.monotonic() < deadline, 'daemon did not become active'
            time.sleep(0.1)

    def busctl(*args, user=None):
        cmd = ['busctl', '--system', *args]
        if user:
            cmd = ['runuser', '-u', user, '--', *cmd]
        env = {k: v for k, v in os.environ.items() if k != 'LD_LIBRARY_PATH'}
        return subprocess.run(cmd, env=env, text=True, capture_output=True, timeout=30)

    def set_permissions(mask, user=None):
        return busctl('call', 'org.opengamingcollective.cardwire',
                      '/org/opengamingcollective/cardwire',
                      'org.opengamingcollective.cardwire.ServiceRoles',
                      'SetPermissions', 'au', '1', str(mask), user=user)

    def allowed():
        spawn(active[0], 0)  # registered role now admitted by verified exec
        spawn(outside, -13)  # outsider still denied

    def legacy_works():
        env = {k: v for k, v in os.environ.items() if k != 'LD_LIBRARY_PATH'}
        r = subprocess.run(['cardwire', 'set', 'hybrid'], env=env, text=True,
                           capture_output=True, timeout=30)
        assert r.returncode == 0, r.stderr

    try:
        cg.mkdir()
        outside.mkdir()
        os.chmod(node, 0o666)
        spawn(outside, 0)  # baseline: node openable before the guard exists
        config.write_text(
            'enabled = true\nbpf_object = "/root/cardwire-service-guard.bpf.o"\n'
            f'devices = ["{node}"]\n[[role]]\nexecutable = "{exe}"\n'
            f'cgroup = "{cg}"\nuid = 0\n'
            '[[profile]]\nname = "open"\npermissions = [1]\n'
            '[[profile]]\nname = "closed"\npermissions = [0]\n'
            '[[profile]]\nname = "everyone"\npermissions = [0]\ndefault_mask = 1\n')
        os.chmod(config, 0o600)
        control('start', unit)
        pid = wait_active()
        count = int(prop('NFileDescriptorStore'))
        assert count >= 3, count
        assert 'service-roles: created generation 1' in journal(), journal()
        denied()
        legacy_works()
        print('PASS: integrated daemon created guard, FD store populated, legacy API alive', flush=True)

        # Root permission API: unprivileged callers rejected, root commit atomic.
        r = set_permissions(1, user='nobody')
        assert r.returncode != 0, 'non-root changed permissions'
        denied()
        r = set_permissions(2)  # bit for a device outside the 1-device catalog
        assert r.returncode != 0, 'invalid mask accepted'
        denied()
        r = set_permissions(1)
        assert r.returncode == 0 and r.stdout.split() == ['t', '2'], r
        allowed()
        print('PASS: root SetPermissions admits registered role only; non-root/invalid rejected', flush=True)

        def profile(name, user=None):
            return busctl('call', 'org.opengamingcollective.cardwire',
                          '/org/opengamingcollective/cardwire',
                          'org.opengamingcollective.cardwire.ServiceRoles',
                          'ApplyProfile', 's', name, user=user)

        def current():
            r = busctl('get-property', 'org.opengamingcollective.cardwire',
                       '/org/opengamingcollective/cardwire',
                       'org.opengamingcollective.cardwire.ServiceRoles', 'CurrentProfile')
            assert r.returncode == 0, r.stderr
            return r.stdout.split(None, 1)[1].strip().strip('"')

        assert current() == 'open'
        assert profile('closed', user='nobody').returncode != 0
        assert profile('missing').returncode != 0
        allowed()
        r = profile('closed')
        assert r.returncode == 0 and r.stdout.split() == ['t', '3'], r
        assert current() == 'closed'
        denied()
        r = profile('open')
        assert r.returncode == 0 and r.stdout.split() == ['t', '4'], r
        assert current() == 'open'
        allowed()
        print('PASS: named profiles apply atomically; unknown/non-root rejected; CurrentProfile derived', flush=True)

        # Default (non-role) mask: Gaming-style profile admits every process.
        r = profile('everyone')
        assert r.returncode == 0 and r.stdout.split() == ['t', '5'], r
        assert current() == 'everyone'
        spawn(outside, 0)
        spawn(cg, 0)
        r = profile('open')
        assert r.returncode == 0 and r.stdout.split() == ['t', '6'], r
        spawn(outside, -13)  # roles-only again
        allowed()
        print('PASS: default mask admits non-role processes only while the profile says so', flush=True)

        control('kill', '--kill-whom=main', '--signal=KILL', unit)
        allowed()  # during the dead/restart window
        pid = wait_active(pid)
        assert int(prop('NFileDescriptorStore')) == count
        assert 'service-roles: adopted generation 6' in journal(), journal()
        allowed()
        legacy_works()
        print('PASS: SIGKILL: committed permissions persisted and restarted daemon adopted stored guard', flush=True)

        control('stop', unit)
        allowed()
        assert int(prop('NFileDescriptorStore')) == count
        control('start', unit)
        pid = wait_active()
        allowed()
        print('PASS: stop/start keeps guard with no open interval', flush=True)

        # Service restart recreated its cgroup: re-enroll the SAME role index.
        cg2.mkdir()
        spawn(cg2, -13)  # not enrolled yet
        allowed()
        reenroll = ['call', 'org.opengamingcollective.cardwire',
                    '/org/opengamingcollective/cardwire',
                    'org.opengamingcollective.cardwire.ServiceRoles', 'ReEnrollRole', 'uss']
        assert busctl(*reenroll, '0', exe, str(cg2), user='nobody').returncode != 0
        assert busctl(*reenroll, '7', exe, str(cg2)).returncode != 0   # unknown role
        assert busctl(*reenroll, '0', exe, str(cg)).returncode != 0    # unchanged identity
        assert busctl(*reenroll, '0', '../x', str(cg2)).returncode != 0
        r = busctl(*reenroll, '0', exe, str(cg2))
        assert r.returncode == 0 and r.stdout.split() == ['t', '7'], r
        assert int(prop('NFileDescriptorStore')) == count  # stale references removed
        assert current() == 'open'                          # permission mask kept
        spawn(cg, -13)       # old cgroup identity no longer admitted
        spawn(outside, -13)
        spawn(cg2, 0)        # new identity admitted at verified exec
        active[0] = cg2
        print('PASS: re-enrollment swaps the role identity atomically, keeps mask and FD count', flush=True)

        control('kill', '--kill-whom=main', '--signal=KILL', unit)
        spawn(cg2, 0)
        spawn(cg, -13)
        pid = wait_active(pid)
        assert int(prop('NFileDescriptorStore')) == count
        assert 'service-roles: adopted generation 7' in journal(), journal()
        spawn(cg2, 0)
        spawn(cg, -13)
        print('PASS: SIGKILL after re-enrollment adopts the new catalog epoch', flush=True)

        # Interrupted re-enrollment leftovers: inject stray store entries from inside the
        # unit cgroup (VM only, NotifyAccess=all), as a crash between store/cleanup would.
        def inject(name, path):
            fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
            unit_cgroup = Path('/sys/fs/cgroup/system.slice') / unit
            try:
                (unit_cgroup / 'cgroup.procs').write_text(str(os.getpid()))
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                sock.connect('/run/systemd/notify')
                socket.send_fds(sock, [f'FDSTORE=1\nFDPOLL=0\nFDNAME={name}'.encode()], [fd])
                sock.close()
            finally:
                Path('/sys/fs/cgroup/cgroup.procs').write_text(str(os.getpid()))
                os.close(fd)
            time.sleep(0.5)

        inject('cw-cg-0-8', cg)  # plausible uncommitted new reference (generation 7 + 1)
        assert int(prop('NFileDescriptorStore')) == count + 1
        control('stop', unit)
        control('start', unit)
        pid = wait_active()
        assert int(prop('NFileDescriptorStore')) == count, 'stale reference not removed'
        assert 'service-roles: adopted generation 7' in journal()
        spawn(cg2, 0)
        spawn(cg, -13)
        print('PASS: leftovers of an interrupted re-enrollment are garbage-collected at adoption', flush=True)

        inject('cw-bogus', cg)  # foreign descriptor: adoption must refuse, enforcement stays
        control('stop', unit)
        control('start', unit)
        wait_active()
        assert 'foreign owner descriptor cw-bogus' in journal(), journal()
        assert int(prop('NFileDescriptorStore')) == count + 1  # nothing guessed or removed
        spawn(cg2, 0)
        spawn(cg, -13)
        print('PASS: foreign stored descriptor refuses adoption; enforcement untouched', flush=True)

        # Pins present but FD store emptied: refuse to recreate, keep legacy running.
        control('stop', unit)
        control('clean', '--what=fdstore', unit)
        assert prop('NFileDescriptorStore') == '0'
        control('start', unit)
        wait_active()
        assert 'owner pins exist but no stored descriptors' in journal(), journal()
        allowed()  # old attached links still enforce
        legacy_works()
        print('PASS: missing FD store is refused without repair; enforcement and legacy kept', flush=True)

        # Foreign same-ABI map: adoption must fail, original enforcement stays.
        control('stop', unit)
        task_pin = pins / 'CW_ROLE_TASKS'
        saved = primitives.object_operation(7, task_pin)
        replacement = primitives.create_map()
        fds += [saved, replacement]
        task_pin.unlink()
        primitives.object_operation(6, task_pin, replacement)
        control('start', unit)
        wait_active()
        allowed()
        task_pin.unlink()
        primitives.object_operation(6, task_pin, saved)
        print('PASS: substituted pinned map not adopted; enforcement unchanged', flush=True)
        print('INTEGRATED_DAEMON_VM_PASSED (root permission API, crash adoption)', flush=True)
    finally:
        for p in children:
            p.kill()
            p.wait(timeout=5)
        control('stop', unit, check=False)
        for name in ('open_link', 'exec_link', 'CW_ACTIVE', 'CW_DEVICES_MAP', 'CW_ROLE_TASKS'):
            if (pins / name).exists():
                (pins / name).unlink()
        control('clean', '--what=fdstore', unit, check=False)
        config.unlink(missing_ok=True)
        for fd in fds:
            os.close(fd)
        for group in (cg2,):
            try:
                group.rmdir()
            except OSError:
                pass
        os.chmod(node, original_mode)


main()
