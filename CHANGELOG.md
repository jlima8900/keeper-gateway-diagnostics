# Changelog

## v1.1.0
- **Windows companion** `keeper-gateway-collect.ps1` (native-Windows gateway: service, Event Log, network, time sync, health endpoint, target reachability, redaction + secret-scan, `-Minimal`). Parse-validated; not yet live-validated on Windows.
- **Time-skew WARN** (Linux): flags an unsynchronized clock (`timedatectl`/chrony/ntpq) — clock drift silently breaks TLS to the router/relay.
- **Rotation/discovery log analysis** (Linux): parses gateway logs for `rotate-action`/`discover-action`/`kdnrm` activity + errors → `gateway/rotation.txt` (vault-side status still needs Commander `pam action job-info`).
- Podman code path validated end-to-end (shim over the real engine).

## v1.0.0
Initial release — read-only KeeperPAM Gateway diagnostic collector.

- **Runtime-agnostic:** Docker or Podman (auto-shim when only podman is present).
- **Distro-aware LSM audit:** SELinux (`getenforce`/AVC) on RHEL/Rocky/CentOS/Fedora, AppArmor (`aa-status`/denials) on Debian/Ubuntu, seccomp on both — black-screen WARN scoped to container/CEF-relevant denials only.
- **Issue coverage:** control plane (reachability, TLS, time, gateway HTTP health endpoint incl. `under_pressure`/`can_accept_rbi`), WebRTC media path (conntrack timeout, INPUT policy, relay-vs-direct candidates, IPv6 STUN noise), RBI/DB (shm vs RAM, CEF lifecycle), rotation/target DNS+TCP (`--target`), performance (CPU steal, entropy), local network (interfaces/routes/DNS/NAT/sockets, `docker network inspect`).
- **Privacy:** broad secret redaction (`*_KEY`/`*_SEED`/PASSWORD/SECRET/TOKEN/bearer/basic-auth/AWS/long-blobs) + post-collection secret-scan; `--minimal` mode to scope down infrastructure exposure; `COLLECTION-NOTICE.txt` in every bundle.
- **Debug toggle:** `--enable-debug`/`--disable-debug` via a Compose override (never edits the real compose).
- **Robust:** runs to completion under `set -u` on bash 3.2+ and degrades gracefully when diagnostic tools are absent.
