# keeper-gateway-diagnostics

A read-only diagnostic data collector for a **KeeperPAM Gateway** host. It gathers host, container, gateway/guacd, network, WebRTC media-path (with **ICE candidate-type root-cause analysis**), and RBI/CEF state into a single **redacted** `.tar.gz` bundle you can attach to a support case.

It is **runtime-agnostic** (Docker **or** Podman), **distro-aware** (RHEL/Rocky/CentOS/Fedora *and* Debian/Ubuntu), and degrades gracefully when diagnostic tools are missing — so it runs and produces a useful bundle almost anywhere.

A **Windows** companion, [`keeper-gateway-collect.ps1`](keeper-gateway-collect.ps1), covers native-Windows gateway installs (service status, Event Log, network, time sync, health endpoint, target reachability) and is at **feature parity** with the bash collector — including the UDP/STUN relay probe, AAAA + host link-local-IPv6 checks, and the WebRTC/ICE candidate-type analysis below. It is **live-validated on Windows Server 2022 (PowerShell 5.1)** (runs to completion, redacts, and produces a `.zip` bundle); the new probes were validated against the live relay. _(The v1.3.0 bash additions — the active RFC 5389 STUN binding probe, the `nsenter` container-namespace probe, and `KEEPER_GATEWAY_TUNNEL_ONLY_USE_TURN` / `KRELAY_SERVER` env detection — are not yet ported to PowerShell; parity for those is a tracked follow-up.)_

> Collection is **read-only**. The only state-changing actions are the explicit, opt-in `--enable-debug` / `--disable-debug` toggles, which write/remove a Compose **override** file (your real `docker-compose.yml` is never edited) and recreate only the gateway service.

## Quick start

```bash
chmod +x keeper-gateway-collect.sh

# full collection (auto-detects the gateway container; region defaults to eu)
./keeper-gateway-collect.sh --region us --container keeper-gateway

# scope down to gateway-relevant data only (recommended when sharing externally)
./keeper-gateway-collect.sh --minimal

# test connectivity to a rotation/RBI target from INSIDE the gateway container
./keeper-gateway-collect.sh --target db.internal:5432
```

The result is a directory plus a `.tar.gz` next to it. **Review it before sharing.**

On **Windows** (PowerShell, run as Administrator):

```powershell
.\keeper-gateway-collect.ps1 -Region us
.\keeper-gateway-collect.ps1 -Target dc01.corp.local:5986 -Minimal   # WinRM rotation target
```

## Issue classes it covers

| Class | What it captures |
|---|---|
| Control plane | router/relay/cloud reachability, TLS issuer+expiry, time sync, gateway HTTP health endpoint (websocket latency, `under_pressure`, `can_accept_rbi`) |
| WebRTC "drops" | host INPUT policy + RELATED,ESTABLISHED rule, `nf_conntrack_udp_timeout`, live conntrack-to-relay, ICE connected/disconnected/failed ratio |
| WebRTC "never connects" | **ICE candidate-type root-cause analysis** (see below): no-relay-candidate vs relay-on-both-sides-but-blocked, never-paired detection, host link-local-IPv6 |
| WebRTC reachability | TCP **and UDP/STUN** probe to the relay (STUN/TURN is UDP — a TCP "open" doesn't prove it), AAAA lookup, host IPv6 health |
| RBI/DB black screen or slow | `/dev/shm` size vs RAM, Chromium/CEF lifecycle, distro-aware LSM audit — **SELinux** (`getenforce`, AVC) or **AppArmor** (`aa-status`, denials) + seccomp |
| Rotation/target | DNS + TCP from inside the gateway container (`--target`) |
| Performance | CPU steal, load, per-container stats, kernel entropy |
| Local network | host interfaces/routes/DNS, NAT table, listening sockets, `docker network inspect` (subnet/MTU) |

## WebRTC / ICE media-path analysis

When the gateway logs are at `debug`, the collector scans them and writes `network/webrtc-ice-analysis.txt` — a **candidate-type breakdown** that turns the same user-visible symptom ("can't connect" / "drops after ~30s") into a *specific* root cause. It classifies ICE candidates as **local** (the gateway) vs **remote** (the client) and raises targeted findings:

| Signature in the log | What it means | Where to look |
|---|---|---|
| Never reaches `connected` + `pingAllCandidates ... no candidate pairs` | ICE never paired — it **never connected**, not a mid-session drop | candidate/relay/NAT — *not* a conntrack timeout |
| Gateway gathered `srflx` but **no relay (TURN) candidate** | the relay path was never established | gateway can't allocate TURN — check **outbound UDP 3478 + 49152–65535**, and host IPv6 below |
| Relay candidates on **both** sides yet no pair connects | TURN allocates but the relayed **UDP media** is dropped | a cloud proxy / **SWG** (e.g. Zscaler) stripping WebRTC UDP — a TCP "open" on 3478 does *not* prove the path |
| `could not listen udp fe80::` (bind failure) | host has **link-local-only IPv6** (typical of Hyper-V VMs) | disable IPv6 on the host or force IPv4, then retry |
| `failed to resolve stun host … No available ipv6` | **expected noise** — `krelay` publishes no native IPv6 (AAAA is IPv4-mapped) | ignore — it appears on healthy gateways too; not a host defect |

These map two common-but-different failures apart: a host that **never builds a relay path** (no TURN candidate — usually blocked UDP or broken host IPv6) versus a path where **TURN allocates but a middlebox strips the UDP media** (relay on both sides, still no pair). The reachability section adds matching active probes: a **UDP/STUN** check to `krelay:3478`, an **AAAA** lookup, and a **host link-local-IPv6** check.

## Options

```
--region eu|us|au|jp|ca|gov   region for cloud reachability (default eu)
--container NAME              gateway container name (else auto-detect)
--target HOST:PORT            test DNS+TCP to a target from inside the container
--lines N                     log tail length (default 2000)
--out DIR                     output directory (default ./)
--no-network                  skip outbound reachability tests
--minimal                     scope down to gateway-relevant data only
--enable-debug                turn on gateway+guacd debug logging (Compose override)
--disable-debug               remove the override, restore the prior level
--compose-file PATH           override compose-file auto-detection
-h | --help
```

### Debug workflow

```
./keeper-gateway-collect.sh --enable-debug      # raise to debug, recreate service
# ... reproduce the failing connection / rotation / RBI session ...
./keeper-gateway-collect.sh                     # collect the debug logs
./keeper-gateway-collect.sh --disable-debug     # restore info logging
```

## Privacy & redaction

This bundle is built to be shareable, but **you are the last line of review.**

- **Secrets are redacted** to `[REDACTED]`: `GATEWAY_CONFIG`, `KCM_LICENSE`, and any key name ending in `PASSWORD/PASSWD/PWD/SECRET/TOKEN/API_KEY/PRIVATE_KEY/PASSPHRASE/CREDENTIAL/_KEY/_SEED`, plus Bearer tokens, basic-auth in URLs, AWS keys, JWTs, multi-line PEM private-key blocks, and long base64/hex blobs. Values with spaces (quoted or not) are masked in full. Over-redaction is the intended failure mode.
- A final **secret-scan** greps the whole bundle for residual secret patterns and writes `REDACTION-SCAN.txt` (and warns if anything survives).
- **Not captured:** the gateway config file / `GATEWAY_CONFIG` payload and `keeper get --unmask` output are never collected. Raw `.env` files are not read either — but environment values that reach the container *are* captured (redacted) in `container_env.txt`/`inspect.json`, so review those if a secret uses an unusual variable name.
- **Full mode captures broad host context** (every container, all interfaces, the complete firewall ruleset, all listening ports, `/etc/hosts`). None of it is secret, but together it reveals your infrastructure topology. Use **`--minimal`** to scope this down when the recipient is a third party. Each bundle includes a `COLLECTION-NOTICE.txt` describing exactly what it contains.

## Requirements

- `bash` (works on 3.2+), and `docker` or `podman` for the container-level checks.
- Diagnostic tools (`nft`/`iptables`, `conntrack`, `ss`, `getenforce`/`aa-status`, `ausearch`, `openssl`, …) are used when present and skipped cleanly when not.
- Run as root (or a user that can `docker`/`podman` and read host firewall/audit state) for complete output.

## License

MIT — see [LICENSE](LICENSE).
