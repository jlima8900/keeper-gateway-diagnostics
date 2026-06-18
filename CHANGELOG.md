# Changelog

## v1.1.1
Hardening from a multi-agent review pass.
- **Redaction airtightness:** multi-line PEM private-key blocks now masked; values containing spaces (quoted or unquoted) masked in full (previously leaked after the first space); JWTs redacted; log path now masks very long (>=64 char) blobs while keeping conversation/tube IDs readable. PowerShell redaction brought to parity.
- **Secret-scan parity:** scan key list now mirrors the full redaction key set (incl. `GATEWAY_CONFIG`/`KCM_LICENSE`/`CREDENTIAL`/`_KEY`/`_SEED`) and JWTs, on both bash and PowerShell.
- **Bug fixes:** debug toggle no longer aborts under `set -u` on bash 3.2/4.3 when the compose `-f` list is empty (`${FARGS[@]+...}`); PowerShell reachability/target tests use a portable TCP probe instead of `Test-NetConnection` (which is absent on PS Core / Server Core and would mis-report BLOCKED); fixed a doubled secret-scan count; `--help` no longer truncates; PowerShell NTP check made best-effort (locale-tolerant).
- **Docs:** README redaction section corrected (`KCM_LICENSE`, JWT/PEM, spaces) and `.env` wording clarified (container env values are captured redacted).

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
