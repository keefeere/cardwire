"""VM-only kernel primitive probe, NOT Cardwire enforcement or a host installer.

Creates one BPF task-storage map; attaches no programs and touches no GPU policy.
Uses raw UAPI because pinned Aya 0.14 exposes TASK_STORAGE as Unsupported.
The x86_64 disposable two-virtio-GPU fixture must create the explicit marker.
"""

import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import select
import struct
import subprocess
import sys
import tempfile


def vm_guard():
    if (sys.flags.optimize or os.geteuid() != 0 or platform.machine() != "x86_64"
            or not Path("/run/cardwire-lifecycle-vm-only").is_file()
            or not Path("/sys/class/dmi/id/product_name").read_text().startswith("Standard PC")):
        raise SystemExit("Requires the explicit disposable x86_64 test VM")
    for node in ("card0", "card1"):
        device = Path("/sys/class/drm") / node / "device"
        if ((device / "driver").resolve().name != "virtio-pci"
                or (device / "vendor").read_text().strip() != "0x1af4"
                or (device / "device").read_text().strip() != "0x1050"):
            raise SystemExit("Requires two QEMU virtio GPUs, never host hardware")


LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.syscall.restype = ctypes.c_long


def bpf(command, fields):
    attr = ctypes.create_string_buffer(fields)
    result = LIBC.syscall(ctypes.c_long(321), ctypes.c_uint(command),
                          ctypes.byref(attr), ctypes.c_uint(len(fields)))
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def create_map():
    # BTF int key and unsigned 64-bit test token. No kernel struct layout reads.
    strings = b"\x00int\x00token\x00"
    types = (struct.pack("<4I", 1, 1 << 24, 4, (1 << 24) | 32)
             + struct.pack("<4I", 5, 1 << 24, 8, 64))
    blob = (struct.pack("<HBB5I", 0xEB9F, 1, 0, 24, 0, len(types),
                        len(types), len(strings)) + types + strings)
    data = ctypes.create_string_buffer(blob)
    log = ctypes.create_string_buffer(16384)
    try:
        btf = bpf(18, struct.pack("<QQIII", ctypes.addressof(data), ctypes.addressof(log),
                                  len(blob), len(log), 1))
    except OSError as error:
        raise RuntimeError(log.value.decode(errors="replace")) from error
    try:
        # BPF_MAP_TYPE_TASK_STORAGE=29, BPF_F_NO_PREALLOC=1; pidfd key.
        return bpf(0, struct.pack("<7I16s5I", 29, 4, 8, 0, 1, 0, 0,
                                   b"cw_vm_task", 0, btf, 1, 2, 0))
    finally:
        os.close(btf)


def element(command, map_fd, pid_fd, token=0):
    key = ctypes.c_int(pid_fd)
    value = ctypes.c_uint64(token)
    bpf(command, struct.pack("<I4xQQQ", map_fd, ctypes.addressof(key),
                             0 if command == 3 else ctypes.addressof(value), 0))
    return value.value


def missing(map_fd, pid_fd, expected=errno.ENOENT):
    try:
        element(1, map_fd, pid_fd)
    except OSError as error:
        assert error.errno == expected, error
    else:
        raise AssertionError("unexpected task-storage entry")


def object_operation(command, path, fd=0):
    name = ctypes.create_string_buffer(os.fsencode(path))
    return bpf(command, struct.pack("<QII", ctypes.addressof(name), fd, 0))


def receive(process):
    assert select.select([process.stdout], [], [], 10)[0], "worker timed out"
    line = process.stdout.readline()
    assert line, "worker terminated"
    return json.loads(line)


def worker():
    print(json.dumps(os.getpid()), flush=True)
    for line in sys.stdin:
        if line.strip() == "exec":
            os.execv(sys.executable, [sys.executable, __file__, "--worker"])


def main():
    vm_guard()
    owned = []
    map_fd = create_map()
    owned.append(map_fd)
    own_pidfd = os.pidfd_open(os.getpid())
    owned.append(own_pidfd)
    child = None
    pin_dir = None
    pin = None
    try:
        missing(map_fd, own_pidfd)
        element(2, map_fd, own_pidfd, 0xC0FFEE)
        assert element(1, map_fd, own_pidfd) == 0xC0FFEE
        print("PASS: pidfd-addressed task-storage grant/readback", flush=True)

        # A fork inherits this map FD but not the parent's task storage.
        reader, writer = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(reader)
            try:
                fd = os.pidfd_open(os.getpid())
                missing(map_fd, fd)
                os.close(fd)
                os.write(writer, b"not-inherited")
                os._exit(0)
            except BaseException:
                os._exit(1)
        os.close(writer)
        try:
            assert select.select([reader], [], [], 10)[0], "fork test timed out"
            assert os.read(reader, 64) == b"not-inherited"
        finally:
            os.close(reader)
            fork_pidfd = os.pidfd_open(pid)
            try:
                ready = select.select([fork_pidfd], [], [], 10)[0]
                if not ready:
                    os.kill(pid, 9)  # This diagnostic's own child only.
                _, result = os.waitpid(pid, 0)
            finally:
                os.close(fork_pidfd)
            assert result == 0, result
        print("PASS: fork-before-exec does not inherit task storage", flush=True)

        child = subprocess.Popen([sys.executable, __file__, "--worker"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 text=True, bufsize=1)
        assert receive(child) == child.pid
        child_pidfd = os.pidfd_open(child.pid)
        owned.append(child_pidfd)
        missing(map_fd, child_pidfd)
        element(2, map_fd, child_pidfd, 0xBEEF)
        child.stdin.write("exec\n")
        child.stdin.flush()
        assert receive(child) == child.pid
        assert element(1, map_fd, child_pidfd) == 0xBEEF
        print("OBSERVED: same-process exec retains storage; exec hook must revalidate", flush=True)

        pin_dir = Path(tempfile.mkdtemp(prefix="cw_task_vm_", dir="/sys/fs/bpf"))
        pin = pin_dir / "task_map"
        object_operation(6, pin, map_fd)
        owned.remove(map_fd)
        os.close(map_fd)
        map_fd = object_operation(7, pin)
        owned.append(map_fd)
        assert element(1, map_fd, own_pidfd) == 0xC0FFEE
        assert element(1, map_fd, child_pidfd) == 0xBEEF
        print("PASS: pinned map preserves entries after all userspace map FDs close", flush=True)

        child.stdin.close()
        assert child.wait(timeout=10) == 0
        missing(map_fd, child_pidfd, errno.ENOENT)
        try:
            element(2, map_fd, child_pidfd, 0xBAD)
        except OSError as error:
            assert error.errno == errno.ENOENT, error
        else:
            raise AssertionError("dead pidfd accepted a new grant")
        print("PASS: dead/reaped pidfd cannot receive a new grant", flush=True)
        element(3, map_fd, own_pidfd)
        missing(map_fd, own_pidfd)
        print("TASK_STORAGE_PRIMITIVE_PASSED (not an enforcement/persistent-profile test)")
    finally:
        if child is not None:
            if child.stdin and not child.stdin.closed:
                child.stdin.close()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)
        if pin and pin.exists():
            pin.unlink()
        if pin_dir:
            pin_dir.rmdir()
        for fd in reversed(owned):
            os.close(fd)


if __name__ == "__main__":
    if sys.argv[1:] == ["--vm-only"]:
        main()
    elif sys.argv[1:] == ["--worker"]:
        worker()
    else:
        raise SystemExit("Only --vm-only inside the explicit disposable VM fixture")
