# Maintained Cardwire fork

This is [keefeere/cardwire](https://github.com/keefeere/cardwire), a downstream
fork of [OpenGamingCollective/Cardwire](https://github.com/OpenGamingCollective/cardwire).
Original authorship and GPL-3.0 licensing are preserved. It is not an official
upstream release. Changes in this fork were developed with OpenAI Codex assistance.

## Process-policy changes

- `RequestProcessAccess` requires an authenticated system-bus caller with UID 0.
  The daemon resolves the unique message sender's UID through the bus, not a
  client-provided PID or UID. Missing/unresolvable credentials are denied.
  Ordinary users cannot change even their own PID through this administrative
  API. `cardwire launch` and the existing environment-hint mechanism are unchanged.
- Each PID has one `CW_PID_POLICY` entry shared by API, analyzer and eBPF readers.
  An Allow/Force transition replaces one complete value atomically. Failed writes
  leave the previous policy intact. A concurrent analyzer inserts only when no
  policy exists, so it cannot overwrite a newer administrative request.
- The wire signature (`usu`), fresh/repeated requests, read-only status and
  `Default` as a no-op are retained. Status describes the PID's own entry, not
  all inherited effects: Smart mode still gives a direct parent's Allow priority
  over a child's Force; Manual mode still honors only Force entries.

This is **not a general security sandbox**. Other existing global configuration
APIs, environment hints, inherited grants and built-in service exemptions are
outside this patch. PID identity is still a numeric PID, not a pidfd/generation:
the administrator must coordinate process lifetime and reapply after exec.
Old asynchronous exec events/PID reuse are not claimed to be solved here.

## Build and tests

The `Fork build and tests` workflow runs on pushes, pull requests and manual
dispatch. It uses read-only repository permissions, no upstream secrets or
cache publishing, a committed Cargo lockfile, pinned Rust/eBPF toolchains and
pinned action revisions. Inherited upstream publishing workflows are gated off
in this fork. There is no auto-install step.

The workflow builds `cardwired`, `cardwire` and `cardwire-gui` for x86_64 Linux,
and uploads a 30-day artifact with SHA-256 checksums, build metadata and a source
archive of the exact commit. Only use artifacts from a run whose **entire test
matrix passed**; an artifact can exist while a separate VM job is still running
or has failed. Pinned inputs improve repeatability; this does not promise
bit-for-bit reproducible binaries or independence from public build dependencies.

Local equivalent (with the workflow's build dependencies installed):

```sh
cargo +nightly-2026-08-12 fmt --all --check
cargo +1.95.0 test --locked
cargo +1.95.0 clippy --locked --all-targets --all-features -- -D warnings
cargo +1.95.0 build --locked --release --config profile.release.lto=false
bash scripts/fork-bundle.sh
nix build --no-link --print-build-logs .#checks.x86_64-linux.vm-ci-2gpu
nix build --no-link --print-build-logs .#checks.x86_64-linux.vm-ci-3gpu
nix build --no-link --print-build-logs .#checks.x86_64-linux.vm-ci-15gpu
```

The two-GPU VM exercises actual D-Bus authorization (own/foreign/root targets),
fresh and repeated requests, and 240 concurrent Allow/Force writes, comparing
the final status with actual device opens by the same still-running process.
These are isolated virtual-GPU tests, not proof of NVIDIA/USB4 hardware behavior.

## Deployment boundary

The main development line is currently **0.13.0-alpha.1**. Do not silently replace
a Bazzite 0.12.3 installation with this bundle. The `backport/v0.12.3-process-access`
branch originally contains only the earlier idempotence fix, not this security
patch. Check its history before using it.

The bundle is not an RPM or a self-contained static distribution: it needs the
usual host graphics libraries, system-bus policy and service configuration.
Daemon and embedded eBPF must be updated together; this map layout cannot be
hot-swapped into a running daemon. Any deployment needs a separately approved
Cardwire restart and rollback plan. Building or downloading it changes neither
the installed RPM nor GPU mode, desktop session, kernel, or eGPU configuration.
