"""Immutable multi-role publication regression, disposable two-virtio-GPU VM only.

Uses the actual feature-gated Rust backend. No host Cardwire/profile is changed.
The bounded unpinned owner intentionally drops enforcement on normal exit;
persistent ownership is a separate, not-yet-integrated acceptance gate.
"""
import importlib.util
import os
from pathlib import Path
import select
import stat
import subprocess
import sys
import tempfile


def main():
    spec = importlib.util.spec_from_file_location(
        'task_probe', Path(__file__).with_name('task-storage-probe.py'))
    primitives = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(primitives)
    primitives.vm_guard()
    groups = [Path('/sys/fs/cgroup/cardwire-snapshot-' + suffix)
              for suffix in ('a', 'b', 'outside')]
    a, b, outside = groups
    assert all(not group.exists() for group in groups)
    worker = '/tmp/cardwire-role-worker'
    render = Path('/dev/dri/renderD129')
    primary = Path('/dev/dri/card1')
    alias = Path('/tmp/cardwire-snapshot-device')
    assert not alias.exists()
    children = []
    owner = None
    owner_log = tempfile.TemporaryFile(mode='w+t')

    def line(process):
        assert select.select([process.stdout], [], [], 15)[0], 'response timeout'
        result = process.stdout.readline().strip()
        assert result, f'unexpected EOF, exit={process.poll()}'
        return result

    def receive(process, expected, kind):
        fields = line(process).split()
        assert len(fields) == 3 and fields[0] == kind, fields
        assert int(fields[2]) == expected, fields
        return int(fields[1])

    def spawn(group=a, expected=0):
        def setup():
            (group / 'cgroup.procs').write_text(str(os.getpid()))
        process = subprocess.Popen([worker], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   text=True, bufsize=1, preexec_fn=setup)
        children.append(process)
        assert receive(process, expected, 'constructor') == process.pid
        return process

    def command(process, request='open', expected=0, kind='open'):
        process.stdin.write(request + '\n')
        process.stdin.flush()
        return receive(process, expected, kind)

    def finish(process):
        process.stdin.close()
        assert process.wait(timeout=5) == 0
        children.remove(process)

    def policy(request, generation, rejected=False):
        owner.stdin.write(request + '\n')
        owner.stdin.flush()
        response = line(owner)
        if rejected:
            assert response.startswith(f'REJECTED {generation} '), response
        else:
            assert response == f'OK {generation}', response

    try:
        for group in groups:
            group.mkdir()
        baseline = spawn(outside)
        command(baseline, 'open ' + str(primary))
        finish(baseline)
        owner = subprocess.Popen(
            [os.environ['CARDWIRE_VM_ELF_LOADER'], '/tmp/cardwire-service-snapshots'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=owner_log,
            text=True, bufsize=1)
        assert line(owner) == 'ATTACHED deny-all'
        denied = spawn(expected=-13)
        command(denied, 'open ' + str(primary), -13)
        command(denied, 'open /dev/dri/renderD128')
        command(denied, 'open /dev/null')
        finish(denied)
        print('PASS: initial deny-all; both protected nodes denied, AMD/null unaffected', flush=True)

        policy('publish 1 3 1', 1)
        p = spawn(a)
        inference = spawn(b)
        inference_pid = inference.pid
        command(p, 'open ' + str(primary))
        command(inference, 'open ' + str(primary), -13)
        assert command(p, 'thread', kind='thread') == p.pid
        assert command(p, 'fork', -13, 'fork') != p.pid
        finish(spawn(outside, -13))
        print('PASS: two independent roles; thread allowed, fork/outsider denied', flush=True)

        policy('publish 2 0 1', 2)
        command(p, expected=-13)
        command(p, 'open ' + str(primary), -13)
        assert command(inference) == inference_pid
        policy('publish 3 3 1', 3)
        command(p)
        command(p, 'open ' + str(primary))
        assert command(inference) == inference_pid
        print('PASS: permissions change live; inference PID/admission survives without exec', flush=True)

        for request in ('duplicate 4 3 1', 'publish 4 4 1', 'publish 3 3 1',
                        'publish 0 3 1', 'publish 4 3'):
            policy(request, 3, rejected=True)
            command(p)
            assert command(inference) == inference_pid
        policy('frozen', 3)
        print('PASS: malformed/stale/duplicate updates preserve policy; active snapshot is frozen', flush=True)

        # Repeated whole-snapshot swaps while workers retain the same task tickets.
        # This is deterministic regression coverage, not an exhaustive race proof.
        for generation in range(4, 28):
            mask = 3 if generation % 2 else 0
            policy(f'publish {generation} {mask} 1', generation)
            command(p, expected=0 if mask else -13)
            assert command(inference) == inference_pid
            finish(spawn(outside, -13))
        print('PASS: 24 further swaps preserve inference and outsider denial', flush=True)

        policy('clear 28', 28)
        command(p, expected=-13)
        command(inference, expected=-13)
        policy('publish 29 3 1', 28, rejected=True)
        policy('rebind-all 29 3 1', 29)
        command(p, expected=-13)
        command(inference, expected=-13)
        assert command(p, 'exec', kind='constructor') == p.pid
        assert command(inference, 'exec', kind='constructor') == inference_pid
        print('PASS: removed/reintroduced roles cannot revive old admission tickets', flush=True)

        old_id = a.stat().st_ino
        finish(p)
        a.rmdir()
        a.mkdir()
        assert a.stat().st_ino != old_id
        replacement = spawn(a, -13)
        policy('rebind-a 30 3 1', 30)
        command(replacement, expected=-13)
        assert command(inference) == inference_pid
        command(replacement, 'exec', kind='constructor')
        command(replacement, 'open ' + str(primary))
        print('PASS: recreated cgroup needs explicit registration+exec; other role stays live', flush=True)

        os.mknod(alias, stat.S_IFCHR | 0o600, render.stat().st_rdev)
        command(replacement, 'open ' + str(alias))
        denied = spawn(outside, -13)
        command(denied, 'open ' + str(alias), -13)
        finish(denied)
        policy('frozen', 30)
        finish(replacement)
        finish(inference)
        owner.stdin.write('stop\n')
        owner.stdin.flush()
        assert owner.wait(timeout=5) == 0
        owner = None
        finish(spawn(outside))
        print('PASS: aliases covered; bounded owner teardown releases only its guard', flush=True)
        print('SERVICE_SNAPSHOTS_VM_PASSED (candidate; no desktop deployment)', flush=True)
    except BaseException:
        owner_log.seek(0)
        print('OWNER DIAGNOSTIC:\n' + owner_log.read()[-24000:], flush=True)
        raise
    finally:
        for process in children:
            process.stdin.close()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        if owner is not None and owner.poll() is None:
            owner.stdin.close()
            try:
                owner.wait(timeout=5)
            except subprocess.TimeoutExpired:
                owner.kill()
                owner.wait(timeout=5)
        owner_log.close()
        if alias.exists():
            alias.unlink()
        for group in reversed(groups):
            if group.exists():
                group.rmdir()


if __name__ == '__main__':
    if sys.argv[1:] != ['--vm-only']:
        raise SystemExit('Only --vm-only in the explicit disposable test guest')
    main()
