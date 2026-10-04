"""Known-gap reproducer. ONLY disposable Cardwire two-virtio-GPU VM.

This records current lifecycle shortcomings, not acceptance of a persistent
profile. It intentionally fails when these shortcomings are fixed; replace
the matching expectation with a positive lifecycle regression at that point.
Never run on the desktop: it stops/restarts the guest Cardwire and changes mode.
"""
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import time

DEVICE = '/dev/dri/renderD129'
SERVICE = 'org.opengamingcollective.cardwire'
OBJECT = '/org/opengamingcollective/cardwire'
API = ['busctl', '--system', '--timeout=3', '--json=short', 'call', SERVICE, OBJECT,
       SERVICE + '.SmartPolicy']


def opened():
    try:
        fd = os.open(DEVICE, os.O_RDONLY | os.O_CLOEXEC)
        os.close(fd)
        return True
    except OSError:
        return False


def worker():
    print(json.dumps({'pid': os.getpid(), 'open': opened()}), flush=True)
    for line in sys.stdin:
        if line.strip() == 'exec':
            env = {k: v for k, v in os.environ.items() if not k.startswith('CARDWIRE_')}
            os.execve(sys.executable, [sys.executable, __file__, '--worker'], env)
        print(json.dumps({'pid': os.getpid(), 'open': opened()}), flush=True)


def run(args):
    return subprocess.check_output(args, text=True, timeout=20).strip()


def status(pid):
    return json.loads(run(API + ['GetProcessStatus', 'u', str(pid)]))['data']


def grant(pid):
    run(API + ['RequestProcessAccess', 'usu', str(pid), 'Allow_dGPU_Exact', '1'])
    assert status(pid) == ['AllowedExact', [0]]


def receive(process):
    assert select.select([process.stdout], [], [], 10)[0], 'probe timed out'
    line = process.stdout.readline()
    assert line, 'probe terminated'
    return json.loads(line)


def request(process, value='open'):
    process.stdin.write(value + '\n')
    process.stdin.flush()
    return receive(process)


def main():
    if sys.flags.optimize or os.geteuid() != 0:
        raise SystemExit('Requires unoptimized Python and root in the test VM')
    assert Path('/run/cardwire-lifecycle-vm-only').is_file(), 'VM fixture marker missing'
    assert run(['cat', '/sys/class/dmi/id/product_name']).startswith('Standard PC'), 'Not test QEMU'
    for node in ('card0', 'card1'):
        device = Path('/sys/class/drm/' + node + '/device')
        assert (device / 'driver').resolve().name == 'virtio-pci'
        assert (device / 'vendor').read_text().strip() == '0x1af4'
        assert (device / 'device').read_text().strip() == '0x1050'
    env = {k: v for k, v in os.environ.items() if not k.startswith('CARDWIRE_')}
    children = []
    stopped_pid = None
    def spawn(environment):
        p = subprocess.Popen([sys.executable, __file__, '--worker'], env=environment,
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        children.append(p)
        return p
    try:
        run(['cardwire', 'set', 'smart'])
        # Hold only the disposable guest daemon. BPF hooks stay attached but
        # its userspace analyzer cannot service the new exec notification.
        stopped_pid = int(run(['systemctl', 'show', 'cardwired.service', '-p', 'MainPID', '--value']))
        assert stopped_pid > 1
        os.kill(stopped_pid, signal.SIGSTOP)
        p = spawn({**env, 'CARDWIRE_ALLOW': '1'})
        first = receive(p)
        assert first['open'] is False, first
        os.kill(stopped_pid, signal.SIGCONT)
        stopped_pid = None
        deadline = time.monotonic() + 5
        while status(first['pid']) != ['Allowed', [0]]:
            assert time.monotonic() < deadline, 'environment analyzer did not catch up'
            time.sleep(0.02)
        assert request(p)['open'] is True
        print('REPRODUCED: allowed exec needs async analyzer before first GPU open', flush=True)
        p.stdin.close()
        p.wait(timeout=5)
        children.remove(p)

        p = spawn(env)
        initial = receive(p)
        assert not initial['open']
        grant(initial['pid'])
        assert request(p)['open']
        after_exec = request(p, 'exec')
        assert after_exec == {'pid': initial['pid'], 'open': False}, after_exec
        assert status(initial['pid']) == ['', []]
        print('REPRODUCED: Exact grant does not survive same-PID exec', flush=True)

        grant(initial['pid'])
        assert request(p)['open']
        run(['systemctl', 'restart', 'cardwired.service'])
        mode = run(['busctl', 'get-property', SERVICE, OBJECT, SERVICE + '.Mode', 'Mode'])
        assert mode == 'u 3', mode
        assert status(initial['pid']) == ['', []]
        assert not request(p)['open']
        print('REPRODUCED: daemon restart loses existing-process Exact grants', flush=True)

        run(['systemctl', 'stop', 'cardwired.service'])
        assert request(p)['open'] is True
        run(['systemctl', 'start', 'cardwired.service'])
        assert not request(p)['open']
        print('REPRODUCED: no daemon means no GPU-open enforcement', flush=True)
    finally:
        if stopped_pid:
            os.kill(stopped_pid, signal.SIGCONT)
        run(['systemctl', 'start', 'cardwired.service'])
        run(['cardwire', 'set', 'hybrid'])
        for p in children:
            if not p.stdin.closed:
                p.stdin.close()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=5)


if __name__ == '__main__':
    if sys.argv[1:] == ['--worker']:
        worker()
    elif sys.argv[1:] == ['--vm-only']:
        main()
    else:
        raise SystemExit('Only --vm-only in the isolated two-GPU test guest')
