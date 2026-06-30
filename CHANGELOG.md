# Changelog

## v1.3.0
- **Active STUN binding probe (new):** sends a real RFC 5389 binding request to the relay and waits for the binding *response*, then decodes XOR-MAPPED-ADDRESS to recover the server-reflexive (`srflx`) address. This is the **definitive** UDP/3478 test — it supersedes the best-effort `nc -u -z` / `/dev/udp` checks, which can't distinguish an open path from a silently-filtered one (a STUN server ignores non-STUN bytes, so "sent OK / 0 received" looks identical either way). A returned `srflx` proves a direct (non-relay) media path is reachable; no response means UDP/3478 egress is blocked — the usual cause of relay-only "slow RBI".
- **Container-namespace probe (new):** runs the STUN probe inside the container's network namespace via `nsenter` using the *host's* python3, so the real container egress is tested even on minimal images that ship no python3; falls back to `docker exec` then to a clear skip note.
- **`KEEPER_GATEWAY_TUNNEL_ONLY_USE_TURN` detection (new):** when set, relay-only media is *intentional config*, not a NAT/firewall fault — flagged up front and cross-referenced in the candidate-type note so it isn't misdiagnosed.
- **`KRELAY_SERVER` override honored (new):** reads the gateway env and points the STUN probe + conntrack grep at the relay actually in use rather than the region default.
- **DEBUG-HOWTO:** documents `KEEPER_GATEWAY_INCLUDE_WEBRTC_LOGS=1`, required for the ICE candidate-type lines the WebRTC analysis parses to appear.
- Bash collector only; PowerShell parity for these checks is a follow-up (the STUN binding probe + netns entry need a Windows-side design and live validation).

## v1.2.0
- **WebRTC/ICE media-path analysis (new):** scans the collected gateway logs and reports why a session fails, separating look-alike causes — ICE never reached `connected` + "no candidate pairs" (never paired), `srflx` gathered but **no relay (TURN) candidate** (relay path never established), **relay candidates on both sides yet no pair** (TURN allocates but a proxy/SWG strips the UDP media), and `could not listen udp fe80::` (host link-local-only IPv6). Writes `network/webrtc-ice-analysis.txt` + targeted WARN notes. Treats `failed to resolve stun host … No available ipv6` as expected noise (the relay has no native IPv6), not a host defect.
- **Relay path probes (new):** UDP/STUN probe to `krelay…:3478` (STUN/TURN is UDP — a TCP-open does not prove the media path) + an AAAA (IPv6) resolution check for the relay.
- **Host IPv6 health (new):** flags IPv6 enabled with **no global address (link-local only — typical of Hyper-V VMs)**.
- **Bash + PowerShell parity:** all three checks are in both collectors; the PowerShell additions are live-validated on **Windows Server 2022 (PowerShell 5.1)** against the live relay.

## v1.1.2
- **Windows collector live-validated** on Windows Server 2022 (runs to completion, redacts, produces a `.zip` bundle).
- **Fix:** gateway-service detection no longer false-matches non-gateway Keeper services (EPM / KeeperWatchdog) — now matches gateway-named services only. Found by the live run.

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
