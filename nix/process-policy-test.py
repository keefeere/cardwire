"""Destructive-to-Cardwire-state integration test: run ONLY inside the test VM.

Uses the real system bus, daemon, eBPF maps and two virtio GPU device nodes.
The probe stays in one process (no exec between policy writes and GPU opens).
"""

import concurrent.futures
import json
import os
import select
import subprocess
import sys

API = [
    "busctl", "--system", "--timeout=10", "--json=short", "call",
    "org.opengamingcollective.cardwire", "/org/opengamingcollective/cardwire",
    "org.opengamingcollective.cardwire.SmartPolicy",
]


def call(method, *args, user=None, denied=False):
    command = API + [method] + [str(arg) for arg in args]
    if user:
        command = ["runuser", "-u", user, "--"] + command
    result = subprocess.run(command, capture_output=True, text=True, timeout=15,
                            env={**os.environ, "LC_ALL": "C"})
    if denied:
        assert result.returncode != 0, result
        # zbus/busctl expose the standard AccessDenied description, not the
        # explanatory string carried inside the Rust fdo::Error variant.
        assert result.stderr.strip() == "Call failed: Access denied", result.stderr
        return
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["data"] if result.stdout.strip() else None


def status(pid):
    return call("GetProcessStatus", "u", pid)


def request(pid, policy, value, **kwargs):
    return call("RequestProcessAccess", "usu", pid, policy, value, **kwargs)


def read_line(process):
    ready, _, _ = select.select([process.stdout], [], [], 15)
    assert ready, "probe timed out"
    line = process.stdout.readline()
    assert line, "probe exited unexpectedly"
    return json.loads(line)


def probe():
    print(json.dumps(os.getpid()), flush=True)
    for _ in sys.stdin:
        accessible = []
        for device in ["/dev/dri/renderD128", "/dev/dri/renderD129"]:
            try:
                fd = os.open(device, os.O_RDONLY | os.O_CLOEXEC)
                os.close(fd)
                accessible.append(True)
            except OSError:
                accessible.append(False)
        print(json.dumps(accessible), flush=True)


def main():
    # Neither the parent nor the worker may inherit an Allow environment hint.
    env = {key: value for key, value in os.environ.items() if not key.startswith("CARDWIRE_")}
    subprocess.run(["cardwire", "set", "hybrid"], check=True)
    workers = []
    try:
        for user in [None, "john", "alice"]:
            command = [sys.executable, __file__, "--probe"]
            if user:
                command = ["runuser", "-u", user, "--"] + command
            worker = subprocess.Popen(command, env=env, stdin=subprocess.PIPE,
                                      stdout=subprocess.PIPE, text=True, bufsize=1)
            workers.append((worker, read_line(worker)))

        # A normal user cannot mutate root, another user, or even their own PID.
        # Read-only status still works; Default must not bypass authorization.
        for _, pid in workers:
            before = status(pid)
            for policy, value in [("Allow_dGPU", 1), ("Force_GPU", 0), ("Default", 0)]:
                request(pid, policy, value, user="john", denied=True)
                assert call("GetProcessStatus", "u", pid, user="john") == before
            request(pid, "Force_GPU", 0)
            assert status(pid) == ["Forced", [0]]

        # Root targets must still exist, while an unprivileged caller cannot
        # use this method to distinguish nonexistent PIDs via its error text.
        request(0, "Allow_dGPU", 1, user="john", denied=True)

        subprocess.run(["cardwire", "set", "smart"], check=True)
        worker, pid = workers[0]
        assert status(os.getpid()) == ["", []], "parent must not grant inherited access"
        expected_access = {"Allowed": [True, True], 0: [True, False], 1: [False, True]}

        def assert_enforcement():
            policy, gpu = status(pid)
            assert policy in ("Allowed", "Forced"), (policy, gpu)
            expected = expected_access["Allowed" if policy == "Allowed" else gpu[0]]
            worker.stdin.write("probe\n")
            worker.stdin.flush()
            assert read_line(worker) == expected, (policy, gpu, expected)

        # Verify both directions deterministically before racing writers.
        for policy, value in [("Allow_dGPU", 1), ("Force_GPU", 0), ("Force_GPU", 1)]:
            request(pid, policy, value)
            assert_enforcement()

        # The last writer need not be predictable; status and enforcement must
        # agree once the batch finishes. Two independently locked maps cannot
        # guarantee that, even though each individual map operation is atomic.
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            for _ in range(20):
                futures = [pool.submit(request, pid, policy, value)
                           for policy, value in [("Allow_dGPU", 1), ("Force_GPU", 0),
                                                 ("Force_GPU", 1)] * 4]
                for future in futures:
                    future.result(timeout=20)
                assert_enforcement()

        print("PASS: authenticated root-only requests and 240 concurrent policy writes")
    finally:
        for worker, _ in workers:
            worker.stdin.close()
            worker.wait(timeout=15)
        subprocess.run(["cardwire", "set", "hybrid"], check=True)


if __name__ == "__main__":
    if sys.argv[1:] == ["--probe"]:
        probe()
    elif sys.argv[1:] == ["--test-vm-only"]:
        main()
    else:
        sys.exit("Run only in the two-GPU NixOS test VM, with --test-vm-only")
