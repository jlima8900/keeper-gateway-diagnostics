#!/usr/bin/env bash
#
# keeper-gateway-collect.sh
#
# General-purpose diagnostic data collector for a Keeper Gateway host
# (KeeperPAM). Runtime-agnostic: works with Docker OR Podman. Gathers host,
# container, Gateway/guacd, network, WebRTC media-path, and RBI/CEF state into
# a single redacted bundle for sharing with Keeper support or a ticket.
#
# Covers the common gateway issue classes:
#   - control plane:  router/relay/cloud reachability, TLS, time sync
#   - WebRTC media:    ICE drops, conntrack timeout, relay-vs-direct, IPv6 noise
#   - RBI/DB "black screen" or slow: CEF lifecycle, shm, seccomp/apparmor audit
#   - rotation/target: DNS + TCP from inside the container (--target)
#   - performance:     CPU steal, load, per-container stats
#
# Collection is READ-ONLY: it never edits the compose file, never restarts the
# Gateway, and redacts secrets (GATEWAY_CONFIG, the gateway-config.json
# contents, passwords, tokens, keys, licenses).
#
# The ONLY mutating actions are the explicit, opt-in debug toggles below. They
# do NOT edit your compose file either -- they write/remove a separate
# keeper-debug.override.yml and recreate only the gateway service, so reverting
# is just removing one file.
#
# Usage:
#   ./keeper-gateway-collect.sh [options]
#     --region eu|us|au|jp|ca|gov   region for cloud reachability (default eu)
#     --container NAME              Gateway container name (else auto-detect)
#     --target HOST:PORT            test DNS+TCP to a rotation/RBI target
#                                   from INSIDE the Gateway container. Common
#                                   rotation ports: SSH 22, WinRM 5986, plus the
#                                   DB port (e.g. 3306/5432/1433) for DB targets.
#     --lines N                     log tail length (default 2000)
#     --out DIR                     output directory (default ./)
#     --no-network                  skip outbound reachability tests
#     --minimal                     SCOPE DOWN to gateway-relevant data only:
#                                   filters container list to keeper/guac, trims
#                                   the firewall dump to gateway rules, skips the
#                                   full interface/socket inventory and host
#                                   /etc/hosts. Use when sharing with third
#                                   parties to limit infrastructure exposure.
#     --enable-debug                turn on Gateway+guacd debug logging via a
#                                   compose override, recreate the service, exit
#     --disable-debug               remove the override, restore prior level
#     --compose-file PATH           override compose-file auto-detection
#                                   (only needed if labels are missing)
#     -h | --help
#
# Output (collection runs): a directory and a .tar.gz next to it. Review first.
#
# Debug workflow: --enable-debug -> reproduce the failing connection ->
# run the collector normally to capture the debug logs -> --disable-debug.

set -uo pipefail

# Ensure sbin dirs are on PATH: nft, iptables, conntrack, dmesg, ausearch,
# aa-status all live in /sbin or /usr/sbin and are missing from the minimal
# PATH of a non-login shell (e.g. when piped via `ssh host bash -s`).
export PATH="/usr/local/sbin:/usr/sbin:/sbin:${PATH:-/usr/local/bin:/usr/bin:/bin}"

# ---- options --------------------------------------------------------------
REGION="eu"; CONTAINER=""; TARGET=""; LINES=2000; OUTBASE="."; DO_NET="yes"; TIMEOUT=6
DEBUG_ACTION=""; COMPOSE_FILE=""; MINIMAL="no"
while [ $# -gt 0 ]; do
  case "$1" in
    --region) REGION="${2:-}"; shift 2 ;;
    --container) CONTAINER="${2:-}"; shift 2 ;;
    --target) TARGET="${2:-}"; shift 2 ;;
    --lines) LINES="${2:-2000}"; shift 2 ;;
    --out) OUTBASE="${2:-.}"; shift 2 ;;
    --no-network) DO_NET="no"; shift ;;
    --minimal) MINIMAL="yes"; shift ;;
    --enable-debug) DEBUG_ACTION="enable"; shift ;;
    --disable-debug) DEBUG_ACTION="disable"; shift ;;
    --compose-file) COMPOSE_FILE="${2:-}"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//' | head -n 60; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

# Container-runtime shim: customers run Docker OR Podman. If docker is absent
# but podman is present, define a 'docker' shell function that dispatches to
# podman so the ENTIRE script (ps/inspect/logs/exec/stats/compose + the debug
# toggle) works unchanged. 'command -v docker' resolves to this function, so
# detection keeps working. Defined before the debug toggle so it covers both.
if command -v docker >/dev/null 2>&1; then
  RUNTIME="docker"
elif command -v podman >/dev/null 2>&1; then
  docker() { podman "$@"; }   # shim so the rest of the script is runtime-agnostic
  RUNTIME="podman"
else
  RUNTIME="none"              # no container runtime; host/native checks still run
fi

case "$REGION" in
  us) TLD="com" ;; eu) TLD="eu" ;; au) TLD="com.au" ;;
  jp) TLD="jp" ;; ca) TLD="ca" ;; gov|us_gov) TLD="us" ;;
  *) echo "Invalid --region '$REGION'" >&2; exit 2 ;;
esac
ROUTER="connect.keepersecurity.${TLD}"
RELAY="krelay.keepersecurity.${TLD}"
CLOUD="keepersecurity.${TLD}"

# ---- debug toggle (the ONLY mutating action; opt-in, reversible) ----------
# Runs and exits before any collection happens. Uses a compose OVERRIDE file so
# the real docker-compose.yml is never edited; revert = remove that file.
if [ -n "$DEBUG_ACTION" ]; then
  command -v docker >/dev/null 2>&1 || { echo "debug toggle requires docker" >&2; exit 2; }
  if [ -z "$CONTAINER" ]; then
    CONTAINER=$(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null \
      | awk '/keeper\/gateway|keepersecurityinc\/gateway/{print $1; exit}')
  fi
  [ -n "$CONTAINER" ] || { echo "no gateway container found; pass --container NAME" >&2; exit 2; }
  PROJ=$(docker inspect "$CONTAINER" --format '{{ index .Config.Labels "com.docker.compose.project" }}' 2>/dev/null)
  SVC=$(docker inspect "$CONTAINER"  --format '{{ index .Config.Labels "com.docker.compose.service" }}' 2>/dev/null)
  WDIR=$(docker inspect "$CONTAINER" --format '{{ index .Config.Labels "com.docker.compose.project.working_dir" }}' 2>/dev/null)
  CFGS=$(docker inspect "$CONTAINER" --format '{{ index .Config.Labels "com.docker.compose.project.config_files" }}' 2>/dev/null)
  [ -n "$COMPOSE_FILE" ] && CFGS="$COMPOSE_FILE"
  if [ -z "$SVC" ] || [ -z "$CFGS" ]; then
    echo "Gateway container is not compose-managed (no project labels found)." >&2
    echo "Pass --compose-file PATH, or enable debug manually (see DEBUG-HOWTO in a collection bundle)." >&2
    exit 2
  fi
  OVR="${WDIR:-.}/keeper-debug.override.yml"
  # Build the base -f list, EXCLUDING our override. After --enable-debug, Compose
  # stamps the container's config_files label to include the override; if we
  # didn't drop it here, --disable-debug would reference the (now-deleted)
  # override file and Compose would fail with "no such file or directory".
  FARGS=(); OIFS="$IFS"; IFS=','; for f in $CFGS; do [ "$f" = "$OVR" ] && continue; FARGS+=( -f "$f" ); done; IFS="$OIFS"
  # compose flavor: v2 plugin ('docker compose') or v1 standalone ('docker-compose')
  if docker compose version >/dev/null 2>&1; then DC=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then DC=(docker-compose)
  else echo "neither 'docker compose' nor 'docker-compose' is available; cannot toggle debug" >&2; exit 2; fi
  if [ "$DEBUG_ACTION" = "enable" ]; then
    cat > "$OVR" <<YAML
# Written by keeper-gateway-collect.sh --enable-debug on $(date).
# TEMPORARY: raises Gateway + guacd logging to debug for support capture.
# Revert with: keeper-gateway-collect.sh --disable-debug
# NOTE: assumes the service's environment: is map style (KEY: value), which
# merges cleanly. If yours is list style (- KEY=value), set the two vars there
# instead and delete this file.
services:
  ${SVC}:
    environment:
      KEEPER_GATEWAY_LOG_LEVEL: "debug"
      LOG_LEVEL: "debug"
YAML
    echo "[debug] wrote override: $OVR"
    echo "[debug] recreating service '$SVC' (brief gateway restart)..."
    "${DC[@]}" -p "$PROJ" ${FARGS[@]+"${FARGS[@]}"} -f "$OVR" up -d "$SVC" || { echo "compose up failed" >&2; exit 1; }
  else
    if [ -f "$OVR" ]; then rm -f "$OVR"; echo "[debug] removed override: $OVR"; else echo "[debug] no override file at $OVR (already reverted?)"; fi
    echo "[debug] recreating service '$SVC' to restore the prior log level..."
    "${DC[@]}" -p "$PROJ" ${FARGS[@]+"${FARGS[@]}"} up -d "$SVC" || { echo "compose up failed" >&2; exit 1; }
  fi
  echo "[debug] waiting for the container to settle..."
  for _ in 1 2 3 4 5; do command -v sleep >/dev/null && sleep 1; done
  echo "[debug] effective log levels now:"
  docker inspect "$CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep -iE 'LOG_LEVEL' | sed 's/^/    /'
  echo "[debug] health:"; docker inspect "$CONTAINER" --format '    {{.State.Status}} (health: {{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}})' 2>/dev/null
  echo "[debug] Done. Reproduce the failing connection, then run the collector normally to capture the debug logs."
  exit 0
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${OUTBASE%/}/keeper-gw-diag-$(hostname 2>/dev/null || echo host)-${STAMP}"
mkdir -p "$OUT"/{host,docker,gateway,network,rbi} || { echo "cannot create $OUT" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# ---- redaction ------------------------------------------------------------
# Over-redaction is the SAFE failure mode here -- err toward masking. Key-name
# fragments are matched case-insensitively (so a benign FOO_KEY may also get
# masked; that's fine). Also masks bearer tokens, basic-auth in URLs, and AWS
# access keys. 'strict' additionally masks any long base64/hex blob.
SECRET_KEYS='GATEWAY_CONFIG|[A-Za-z0-9_]*(PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|PASSPHRASE|CREDENTIALS?|_KEY|_SEED|SEED)|KCM_LICENSE'
# multi-line PEM private-key blocks: blank every body line between the markers
# (the long-blob rule alone misses the short final base64 line).
redact_pem() { sed -E '/-----BEGIN [A-Z ]*PRIVATE KEY-----/,/-----END [A-Z ]*PRIVATE KEY-----/{/-----(BEGIN|END) /!s/.+/[REDACTED_PRIVATE_KEY_LINE]/}'; }
redact_common() {
  redact_pem | sed -E \
    -e "s/((\"?)($SECRET_KEYS)(\"?)[[:space:]]*[:=][[:space:]]*)\"[^\"]*\"/\1\"[REDACTED]\"/Ig" \
    -e "s/((\"?)($SECRET_KEYS)(\"?)[[:space:]]*[:=][[:space:]]*)[^\"[:space:]].*/\1[REDACTED]/Ig" \
    -e 's/([Bb]earer )[A-Za-z0-9._~+/=-]{8,}/\1[REDACTED]/g' \
    -e 's#(://[^:/@[:space:]]+:)[^@/[:space:]]+@#\1[REDACTED]@#g' \
    -e 's/AKIA[0-9A-Z]{16}/[REDACTED_AWS_KEY]/g' \
    -e 's/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/[REDACTED_JWT]/g'
}
# strict: config/env/inspect/compose/network-inspect -- also mask long base64/hex
# blobs (GATEWAY_CONFIG payload, keys, certs run hundreds of chars).
redact_strict() { redact_common | sed -E -e 's#[A-Za-z0-9+/_-]{40,}={0,2}#[REDACTED_LONG_TOKEN]#g'; }
# logs: mask only VERY long blobs (>=64) so base64 conversation/tube IDs
# (~24-44 chars) stay readable, but a dumped config/key/cert still gets masked.
redact_logs() { redact_common | sed -E -e 's#[A-Za-z0-9+/_-]{64,}={0,2}#[REDACTED_LONG_TOKEN]#g'; }

# run CMD..., capture stdout+stderr to a file, never abort the script
cap() { local f="$1"; shift; { echo "\$ $*"; "$@"; } >>"$f" 2>&1 || echo "(command failed, continuing)" >>"$f"; }

# console summary collectors
declare -a NOTES
note() { NOTES+=("$1"); printf '  %s\n' "$1"; }

echo "Keeper Gateway diagnostic collector"
echo "Region=$REGION  Output=$OUT"
echo
if [ "$MINIMAL" = "yes" ]; then
  echo ">>> Mode: MINIMAL -- scoped to gateway-relevant data (reduced infra exposure)."
else
  cat <<'NOTICE'
============================ DATA-EXPOSURE NOTICE ============================
 Full collection captures BROAD host context: EVERY container, ALL network
 interfaces/routes, the COMPLETE firewall ruleset (incl. rule comments that may
 name other projects), ALL listening ports, and DNS/hosts config.

 Secrets ARE redacted + scanned -- but the rest still reveals your
 infrastructure topology and unrelated services to whoever receives the bundle.

 The more you gather, the more you expose. Before sharing externally:
   * review the bundle contents, OR
   * re-run with  --minimal  to scope collection to gateway-relevant data.
=============================================================================
NOTICE
fi
echo

# ---- host -----------------------------------------------------------------
echo "[*] Host"
{ echo "collected: $(date)"; echo "hostname: $(hostname 2>/dev/null)"; } > "$OUT/host/info.txt"
cap "$OUT/host/info.txt" uname -a
[ -r /etc/os-release ] && cap "$OUT/host/info.txt" cat /etc/os-release
# distro family drives which LSM matters (SELinux on RHEL/Rocky, AppArmor on
# Debian/Ubuntu) and which firewall front-end is likely (firewalld vs ufw).
DISTRO_ID="$(. /etc/os-release 2>/dev/null; echo "${ID:-unknown}")"
DISTRO_LIKE="$(. /etc/os-release 2>/dev/null; echo "${ID_LIKE:-}")"
note "distro: ${DISTRO_ID}${DISTRO_LIKE:+ (like: $DISTRO_LIKE)}"
cap "$OUT/host/info.txt" uptime
have nproc && cap "$OUT/host/resources.txt" nproc
have free && cap "$OUT/host/resources.txt" free -h
have df && cap "$OUT/host/resources.txt" df -h
have df && cap "$OUT/host/resources.txt" df -h /dev/shm
# kernel entropy: low values stall TLS/crypto handshakes (Keeper suggests haveged).
if [ -r /proc/sys/kernel/random/entropy_avail ]; then
  EA=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null)
  echo "entropy_avail: ${EA:-unknown}" >> "$OUT/host/resources.txt"
  [ -n "${EA:-}" ] && [ "$EA" -lt 256 ] 2>/dev/null \
    && note "WARN: low kernel entropy ($EA); can stall TLS/crypto handshakes -- consider haveged or rng-tools"
fi
# performance: load + VPS CPU steal (a slow session is often the host, not the
# network). 'st' in vmstat is steal % -- non-zero = noisy-neighbour on a VPS.
cap "$OUT/host/performance.txt" uptime
have vmstat && cap "$OUT/host/performance.txt" vmstat 1 3
if have vmstat; then
  ST="$(vmstat 1 2 2>/dev/null | tail -1 | awk '{print $NF}')"
  [ -n "$ST" ] && [ "$ST" -gt 5 ] 2>/dev/null && note "WARN: CPU steal ~${ST}% (VPS noisy-neighbour) -- can cause slow/laggy sessions independent of the network"
fi
have timedatectl && cap "$OUT/host/time.txt" timedatectl
cap "$OUT/host/time.txt" date
# clock skew silently breaks the TLS handshake to the router/relay -- WARN on it.
SYNCED=""
if have timedatectl; then
  cap "$OUT/host/time.txt" sh -c 'timedatectl timesync-status 2>/dev/null'
  SYNCED=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
fi
have chronyc && cap "$OUT/host/time.txt" sh -c 'chronyc tracking 2>/dev/null'
have ntpq && cap "$OUT/host/time.txt" sh -c 'ntpq -pn 2>/dev/null'
[ "$SYNCED" = "no" ] && note "WARN: system clock is NOT NTP-synchronized -- clock skew breaks TLS to the router/relay; sync time (chronyd / systemd-timesyncd) before deeper debugging"

# firewall snapshot (relevant to BOTH the VLAN/rotation routing class of issue
# AND the WebRTC media-path class: a default-deny INPUT policy drops relayed
# UDP media once its conntrack entry expires).
FW="$OUT/host/firewall.txt"
if [ "$MINIMAL" = "yes" ]; then
  # scoped: policies + ESTABLISHED + DOCKER/conntrack rules only -- enough for the
  # WebRTC/conntrack diagnosis without dumping every other project's rules.
  if have iptables; then cap "$FW" sh -c '{ sudo -n iptables -S 2>/dev/null || iptables -S 2>/dev/null; } | grep -iE "^-P|RELATED,ESTABLISHED|DOCKER|MASQUERADE|conntrack"'; fi
else
  if have nft; then cap "$FW" sudo -n nft list ruleset; fi
  if have iptables; then cap "$FW" sudo -n iptables -S; fi
fi

# Analyse the inbound policy + return path that WebRTC media depends on.
IPT="$(sudo -n iptables -S 2>/dev/null || iptables -S 2>/dev/null)"
if [ -n "$IPT" ]; then
  INPUT_POLICY="$(printf '%s\n' "$IPT" | awk '/^-P INPUT/{print $3}')"
  note "iptables INPUT policy: ${INPUT_POLICY:-unknown}"
  if [ "$INPUT_POLICY" = "DROP" ]; then
    if printf '%s\n' "$IPT" | grep -qiE -- '-m (state --state|conntrack --ctstate).*(RELATED,ESTABLISHED|ESTABLISHED,RELATED)'; then
      note "INPUT is default-deny but RELATED,ESTABLISHED accept is present (return traffic OK while conntrack lives)"
    else
      note "WARN: INPUT DROP and NO RELATED,ESTABLISHED accept found -- inbound return traffic (incl. WebRTC media) will be blocked"
    fi
  fi
  printf '%s\n' "$IPT" | grep -qE -- '-A INPUT -j ts-input' \
    && note "Tailscale detected (ts-input chain runs before other INPUT rules) -- account for it when reasoning about drops"
fi

# conntrack UDP timeouts: too-short values drop relayed WebRTC media on idle.
for k in nf_conntrack_udp_timeout nf_conntrack_udp_timeout_stream; do
  v="$(sysctl -n "net.netfilter.$k" 2>/dev/null || cat "/proc/sys/net/netfilter/$k" 2>/dev/null)"
  echo "net.netfilter.$k = ${v:-unavailable}" >> "$OUT/host/conntrack.txt"
  [ "$k" = "nf_conntrack_udp_timeout" ] && [ -n "$v" ] && [ "$v" -lt 60 ] 2>/dev/null \
    && note "WARN: nf_conntrack_udp_timeout=${v}s is low; WebRTC relay media can drop on idle behind a default-deny INPUT policy (recommend >=120)"
done
have conntrack && { echo "count=$(cat /proc/sys/net/netfilter/nf_conntrack_count 2>/dev/null) max=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)" >> "$OUT/host/conntrack.txt"; }

# dual-stack note: an IPv6 default route alongside IPv4-only relay candidates
# can cause ICE asymmetry worth flagging.
have ip && ip -6 route show default 2>/dev/null | grep -q . \
  && note "host has an IPv6 default route (dual-stack); Keeper relay candidates are IPv4 -- watch for ICE asymmetry"

# IPv6 enabled but with NO usable GLOBAL address (link-local only) -- common on
# Hyper-V VMs -- makes the ICE agent try STUN/TURN over IPv6 and fail to resolve/bind
# ("No available ipv6 IP address" / "could not listen udp fe80::"), starving relay
# gathering so NO relay (TURN) candidate is produced. It looks like a firewall
# problem but is host-side. (Seen live: Hyper-V gateway, sessions never connected.)
if have ip; then
  V6GLOBAL=$(ip -6 addr show scope global 2>/dev/null | grep -c 'inet6')
  V6ANY=$(ip -6 addr show 2>/dev/null | grep -c 'inet6')
  if [ "${V6GLOBAL:-0}" -eq 0 ] && [ "${V6ANY:-0}" -gt 0 ]; then
    note "WARN: host has IPv6 enabled but NO global IPv6 address (link-local only -- typical of Hyper-V VMs). The gateway will fail STUN/TURN over IPv6 to $RELAY and may gather no relay candidate. Disable IPv6 on the host (or force IPv4 for $RELAY), then retry a session."
  fi
fi

# ---- host local network config (network-class troubleshooting; runs even
# with --no-network since it is all local state, no egress) -----------------
HN="$OUT/network/host-network.txt"
if have ip; then
  cap "$HN" ip -br addr      # interfaces + IPs at a glance
  cap "$HN" ip route         # IPv4 routing table
  cap "$HN" ip -6 route
  if [ "$MINIMAL" != "yes" ]; then
    cap "$HN" ip addr        # full, incl. MTU + every docker bridge
    cap "$HN" ip -br link
  fi
else
  have ifconfig && cap "$HN" ifconfig -a
  have netstat && cap "$HN" netstat -rn
fi
# listening sockets reveal EVERY service on the host -- skip in minimal mode.
if [ "$MINIMAL" != "yes" ]; then
  if have ss; then cap "$HN" ss -tulpn
  elif have netstat; then cap "$HN" netstat -tulpn; fi
else
  echo "(listening-socket inventory skipped: --minimal)" >> "$HN"
fi
# NAT table: Docker DNAT/MASQUERADE for published ports. 'iptables -S' shows the
# filter table only; on legacy-iptables hosts the nat table is captured here.
have iptables && cap "$OUT/host/firewall.txt" sh -c 'sudo -n iptables -t nat -S 2>/dev/null || iptables -t nat -S 2>/dev/null'
# host DNS resolver (needed for DNS diagnosis). /etc/hosts can carry internal /
# customer mappings -- skip it in minimal mode.
[ -r /etc/resolv.conf ] && cap "$OUT/network/host-resolv.conf.txt" cat /etc/resolv.conf
have resolvectl && cap "$OUT/network/host-resolv.conf.txt" sh -c 'resolvectl status 2>/dev/null'
if [ "$MINIMAL" != "yes" ] && [ -r /etc/hosts ]; then cap "$OUT/network/host-hosts.txt" cat /etc/hosts
elif [ "$MINIMAL" = "yes" ]; then echo "(host /etc/hosts skipped: --minimal)" > "$OUT/network/host-hosts.txt"; fi

# ---- deployment detection -------------------------------------------------
echo "[*] Detecting deployment"
MODE="unknown"
if have docker; then
  if [ -z "$CONTAINER" ]; then
    CONTAINER=$(docker ps --format '{{.Names}} {{.Image}}' 2>/dev/null \
      | awk '/keeper\/gateway|keepersecurityinc\/gateway/{print $1; exit}')
  fi
  [ -n "$CONTAINER" ] && MODE="docker"
fi
if [ "$MODE" = "unknown" ] && have systemctl; then
  systemctl list-unit-files 2>/dev/null | grep -q '^keeper-gateway' && MODE="native"
fi
note "deployment mode: $MODE (runtime: $RUNTIME)${CONTAINER:+ (container: $CONTAINER)}"

# ---- docker ---------------------------------------------------------------
if have docker; then
  echo "[*] Docker"
  cap "$OUT/docker/version.txt" docker version
  if [ "$MINIMAL" = "yes" ]; then
    # only the gateway + KCM/guac stack -- not the operator's unrelated containers
    { echo "\$ docker ps -a (filtered: keeper/gateway/guac -- --minimal)"; docker ps -a 2>/dev/null | grep -iE 'keeper|gateway|guac|NAMES'; } > "$OUT/docker/ps.txt" 2>&1
  else
    cap "$OUT/docker/ps.txt" docker ps -a
  fi
  cap "$OUT/docker/networks.txt" docker network ls
  if [ -n "$CONTAINER" ]; then
    docker inspect "$CONTAINER" 2>/dev/null | redact_strict > "$OUT/docker/inspect.json"
    # key facts pulled out for the summary
    SHM=$(docker inspect "$CONTAINER" --format '{{.HostConfig.ShmSize}}' 2>/dev/null)
    docker inspect "$CONTAINER" --format '{{json .HostConfig.SecurityOpt}}' 2>/dev/null > "$OUT/docker/security_opt.txt"
    docker inspect "$CONTAINER" --format '{{json .NetworkSettings.Networks}}' 2>/dev/null > "$OUT/docker/container_networks.txt"
    # full inspect of the gateway's network(s): subnet, gateway IP, driver, MTU --
    # for spotting subnet overlaps with target VLANs and MTU mismatches
    for net in $(docker inspect "$CONTAINER" --format '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' 2>/dev/null); do
      { echo "== network: $net =="; docker network inspect "$net" 2>/dev/null; } | redact_strict >> "$OUT/docker/network-inspect.txt"
    done
    docker inspect "$CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | redact_strict > "$OUT/docker/container_env.txt"
    # compose file, if labelled
    CF=$(docker inspect "$CONTAINER" --format '{{ index .Config.Labels "com.docker.compose.project.config_files" }}' 2>/dev/null)
    if [ -n "${CF:-}" ] && [ -r "$CF" ]; then
      redact_strict < "$CF" > "$OUT/docker/docker-compose.redacted.yml"
      note "compose file captured (redacted): $CF"
    fi
    # log level currently in effect
    GLL=$(docker inspect "$CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep -i 'KEEPER_GATEWAY_LOG_LEVEL=' | cut -d= -f2)
    QLL=$(docker inspect "$CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep -i '^LOG_LEVEL=' | cut -d= -f2)
    note "gateway log level: ${GLL:-info(default)}   guacd log level: ${QLL:-info(default)}"
    [ "${GLL:-info}" != "debug" ] && note "TIP: gateway not at debug; see DEBUG-HOWTO.txt and reproduce before relying on logs"
    # live resource usage of the gateway container (slow sessions: CPU-bound?)
    cap "$OUT/docker/stats.txt" docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}' "$CONTAINER"
  else
    note "no Keeper Gateway container detected; pass --container NAME if it is named differently"
  fi
fi

# ---- gateway + guacd logs -------------------------------------------------
echo "[*] Gateway / guacd logs"
if [ "$MODE" = "docker" ] && [ -n "$CONTAINER" ]; then
  { echo "\$ docker logs --tail $LINES $CONTAINER"; docker logs --tail "$LINES" "$CONTAINER"; } 2>&1 \
    | redact_logs > "$OUT/gateway/container-logs.txt"
  # health check + version from inside the container (tolerant of image variations)
  cap "$OUT/gateway/health-check.txt" docker exec "$CONTAINER" keeper-gateway health-check
  cap "$OUT/gateway/version.txt" docker exec "$CONTAINER" keeper-gateway --version
  cap "$OUT/gateway/version.txt" docker exec "$CONTAINER" guacd -v
  # structured health: connection_status + websocket latency/ping age. Prefer the
  # CLI --json; if the HTTP health endpoint is enabled, capture its richer JSON.
  docker exec "$CONTAINER" sh -c 'gateway health-check --json 2>/dev/null || keeper-gateway health-check --json 2>/dev/null' > "$OUT/gateway/health.json" 2>/dev/null
  HCEN=$(docker inspect "$CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep -i 'KEEPER_GATEWAY_HEALTH_CHECK_ENABLED=' | cut -d= -f2)
  HCPORT=$(docker inspect "$CONTAINER" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null | grep -i 'KEEPER_GATEWAY_HEALTH_CHECK_PORT=' | cut -d= -f2)
  if printf '%s' "${HCEN:-}" | grep -qiE '^(1|true|yes)$'; then
    note "health-check HTTP endpoint enabled (port ${HCPORT:-8099})"
    docker exec "$CONTAINER" sh -c "curl -sk http://127.0.0.1:${HCPORT:-8099}/health 2>/dev/null" >> "$OUT/gateway/health.json" 2>/dev/null
  else
    note "TIP: HTTP health endpoint disabled; set KEEPER_GATEWAY_HEALTH_CHECK_ENABLED=true for websocket latency/uptime monitoring"
  fi
  # surface websocket latency + connection_status as a one-line summary
  WSLAT=$(grep -oE '"latency_ms"[: ]*[0-9]+' "$OUT/gateway/health.json" 2>/dev/null | grep -oE '[0-9]+' | head -1)
  CSTAT=$(grep -oE '"connection_status"[: ]*"[^"]*"' "$OUT/gateway/health.json" 2>/dev/null | head -1)
  [ -n "${CSTAT:-}${WSLAT:-}" ] && note "control-plane: ${CSTAT:-status n/a}${WSLAT:+  websocket latency=${WSLAT}ms}"
  # gateway self-reported resource pressure -- authoritative for slow/refused RBI
  PRESS=$(grep -oE '"under_pressure"[: ]*(true|false)' "$OUT/gateway/health.json" 2>/dev/null | grep -oE 'true|false' | head -1)
  RBIOK=$(grep -oE '"can_accept_rbi"[: ]*(true|false)' "$OUT/gateway/health.json" 2>/dev/null | grep -oE 'true|false' | head -1)
  [ -n "${PRESS:-}${RBIOK:-}" ] && note "gateway self-report: under_pressure=${PRESS:-?}  can_accept_rbi=${RBIOK:-?}"
  [ "${PRESS:-}" = "true" ] && note "WARN: gateway reports UNDER PRESSURE (resource-constrained) -- direct cause of slow/refused RBI & connections; scale CPU/RAM"
  [ "${RBIOK:-}" = "false" ] && note "WARN: gateway reports can_accept_rbi=false -- it is refusing/degrading RBI sessions right now"
elif [ "$MODE" = "native" ]; then
  if have journalctl; then
    { echo "\$ journalctl -u keeper-gateway -n $LINES --no-pager"; sudo -n journalctl -u keeper-gateway -n "$LINES" --no-pager 2>/dev/null || journalctl -u keeper-gateway -n "$LINES" --no-pager; } 2>&1 \
      | redact_logs > "$OUT/gateway/journal.txt"
  fi
  cap "$OUT/gateway/service.txt" systemctl status keeper-gateway --no-pager
  # candidate native log/config locations (existence only; config is NOT dumped)
  for p in /var/log/keeper-gateway /etc/keeper-gateway /opt/keeper-gateway "$HOME/.keeper"; do
    [ -e "$p" ] && { echo "== $p =="; ls -la "$p" 2>/dev/null; } >> "$OUT/gateway/locations.txt"
  done
  # copy any *.log found in those dirs, redacted; never copy *config*.json
  for p in /var/log/keeper-gateway /opt/keeper-gateway "$HOME/.keeper"; do
    [ -d "$p" ] && find "$p" -maxdepth 2 -name '*.log' -type f 2>/dev/null | while read -r lf; do
      redact_logs < "$lf" > "$OUT/gateway/$(echo "$lf" | tr '/' '_')"
    done
  done
  note "native install: config file is intentionally NOT collected (contains keys/tokens)"
else
  note "could not locate gateway logs automatically; check deployment mode"
fi

# ---- WebRTC / ICE media-path analysis -------------------------------------
# Scan the just-collected gateway logs for the ICE/relay failure signatures that
# decide WHY a session fails. The same user-visible symptom ("can't connect" /
# "drops after ~30s") has very different causes -- this separates them:
#   * never reaches 'connected' + "no candidate pairs"  -> ICE never paired
#   * srflx gathered but NO relay candidate             -> TURN allocation failing
#   * IPv6 resolve/bind failures to the relay           -> host IPv6 starving relay
#   * remote side also host-only (no relay)             -> problem is on BOTH ends
GLOG=""
for c in "$OUT/gateway/container-logs.txt" "$OUT/gateway/journal.txt"; do
  [ -s "$c" ] && GLOG="$GLOG $c"
done
if [ -n "$GLOG" ]; then
  echo "[*] WebRTC / ICE analysis"
  WA="$OUT/network/webrtc-ice-analysis.txt"
  wcm() { grep -hcE "$1" $GLOG 2>/dev/null | awk '{s+=$1} END{print s+0}'; } # sum matches across logs
  ICE_FAIL=$(wcm 'connection state changed: failed|ICE connection failed')
  ICE_OK=$(wcm 'connection state changed: (connected|completed)|selected candidate pair|nominated pair')
  NOPAIRS=$(wcm 'pingAllCandidates called with no candidate pairs')
  V6RES=$(wcm 'failed to resolve stun host.*No available ipv6 IP address')
  V6BIND=$(wcm 'could not listen udp fe80')
  LRELAY=$(wcm 'udp[46] relay |Local ICE candidate.*typ=relay')
  LSRFLX=$(wcm 'udp[46] srflx |Local ICE candidate.*typ=srflx')
  RRELAY=$(wcm 'Remote ICE candidate.*typ=relay')
  RHOST=$(wcm 'Remote ICE candidate.*typ=host')
  {
    echo "== WebRTC / ICE media-path analysis =="
    echo "(scanned:$GLOG)"
    echo
    echo "ICE sessions failed                  : $ICE_FAIL"
    echo "ICE reached connected/selected pair  : $ICE_OK"
    echo "pingAllCandidates: no candidate pairs: $NOPAIRS"
    echo "IPv6 relay-resolve failures (krelay) : $V6RES"
    echo "IPv6 link-local bind failures (fe80) : $V6BIND"
    echo "LOCAL  relay (TURN) candidates        : $LRELAY"
    echo "LOCAL  srflx candidates               : $LSRFLX"
    echo "REMOTE relay (TURN) candidates        : $RRELAY"
    echo "REMOTE host candidates                : $RHOST"
  } > "$WA"
  if [ "$ICE_FAIL" -gt 0 ] && [ "$ICE_OK" -eq 0 ]; then
    note "WARN: WebRTC ICE never reached 'connected' (${ICE_FAIL} failed / 0 connected) -- sessions are not establishing at all, NOT a mid-session drop (see network/webrtc-ice-analysis.txt)"
  fi
  [ "$NOPAIRS" -gt 0 ] && note "WARN: ICE logged 'no candidate pairs' x${NOPAIRS} -- the two sides never produced a usable candidate pair (relay/NAT path problem)"
  if [ "$LRELAY" -eq 0 ] && [ "$LSRFLX" -gt 0 ]; then
    note "WARN: gateway gathered srflx but NO relay (TURN) candidate -- it could not allocate a relay on $RELAY:3478. Verify UDP 3478 + a TURN allocation outbound (not just TCP/STUN), and check the host IPv6 note above. (Cause class: relay path never established.)"
  fi
  if [ "$LRELAY" -gt 0 ] && [ "$RRELAY" -gt 0 ] && [ "$ICE_OK" -eq 0 ]; then
    note "WARN: relay (TURN) candidates were gathered on BOTH sides yet NO pair connected -- TURN allocation works but the relayed UDP media/connectivity-checks are being dropped. Classic of a cloud proxy / SWG (e.g. Zscaler) or UDP stripped between the relay and the peer. Verify UDP is not proxied/filtered end-to-end -- a TCP 'open' on 3478 does not prove this. (Cause class: relay allocates but media blocked, NOT a missing relay.)"
  fi
  if [ "$V6BIND" -gt 0 ]; then
    note "WARN: gateway failed to bind an IPv6 interface ('could not listen udp fe80::' x${V6BIND}) -- the host has link-local-only IPv6 (typical of Hyper-V VMs) that the ICE agent tries and fails to use. Disable IPv6 on the host or force IPv4 for $RELAY, then retry."
  fi
  [ "$V6RES" -gt 0 ] && note "NOTE: ${V6RES}x 'failed to resolve stun host ... No available ipv6' -- EXPECTED noise ($RELAY publishes no native IPv6/AAAA, only IPv4-mapped), NOT a host defect on its own; do not chase it."
  [ "$RRELAY" -eq 0 ] && [ "$RHOST" -gt 0 ] && note "NOTE: the REMOTE (client) side also offered NO relay candidate (host-only) -- the missing relay path is on BOTH ends; check the client/viewer network too, not only the gateway."
  echo "  -> network/webrtc-ice-analysis.txt"
fi

# ---- RBI specifics --------------------------------------------------------
echo "[*] RBI / Chromium"
if [ "$MODE" = "docker" ] && [ -n "$CONTAINER" ]; then
  cap "$OUT/rbi/shm.txt" docker exec "$CONTAINER" df -h /dev/shm
  # human-readable shm_size from inspect (bytes)
  if [ -n "${SHM:-}" ] && [ "${SHM:-0}" -gt 0 ] 2>/dev/null; then
    SHM_GB=$(( SHM / 1073741824 ))
    echo "HostConfig.ShmSize = ${SHM} bytes (~${SHM_GB} GiB)" > "$OUT/rbi/shm_size.txt"
    # Keeper guidance: shm_size >= half of total RAM (example uses 16g).
    MEMKB=$(grep -i '^MemTotal:' /proc/meminfo 2>/dev/null | awk '{print $2}')
    if [ -n "${MEMKB:-}" ]; then
      RAM_GB=$(( MEMKB / 1048576 )); HALF_GB=$(( RAM_GB / 2 ))
      echo "host RAM ~${RAM_GB} GiB; Keeper recommends shm_size >= half (~${HALF_GB} GiB)" >> "$OUT/rbi/shm_size.txt"
      [ "$SHM_GB" -lt "$HALF_GB" ] 2>/dev/null \
        && note "NOTE: shm_size ~${SHM_GB} GiB is below Keeper's guidance of half-RAM (~${HALF_GB} GiB); RBI Chromium can fail/slow under concurrent sessions"
    fi
    [ "$SHM_GB" -lt 2 ] && note "WARN: shm_size ~${SHM_GB} GiB is very low for RBI; Chromium needs generous /dev/shm"
  fi
  # count chromium processes without assuming procps is installed
  CHROME=$(docker exec "$CONTAINER" sh -c 'grep -l -i chrom /proc/*/comm 2>/dev/null | wc -l' 2>/dev/null)
  echo "chromium-like processes in container: ${CHROME:-unknown}" > "$OUT/rbi/chromium.txt"
  cap "$OUT/rbi/security_opt.txt" cat "$OUT/docker/security_opt.txt"
  note "RBI needs an unconfined/permissive seccomp + apparmor and CAP_SYS_ADMIN; see rbi/security_opt.txt"
  # CEF/Chromium lifecycle + crash signatures from the collected log. A healthy
  # RBI session shows: DBus mount -> "Initialized CEF process" -> clean exit.
  # seccomp/apparmor denials or SIGSEGV/SIGTRAP here = confinement (black screen).
  if [ -r "$OUT/gateway/container-logs.txt" ]; then
    grep -iE 'cef|chrom|dbus|sandbox|seccomp|apparmor|denied|SIGSEGV|SIGTRAP|zygote|namespace|swiftshader|EGL|No usable|renderer' \
      "$OUT/gateway/container-logs.txt" 2>/dev/null | tail -60 > "$OUT/rbi/cef-lifecycle.txt"
    if grep -qiE 'seccomp|apparmor.*(denied|DENIED)|SIGSEGV|SIGTRAP|sandbox.*fail|No usable sandbox' "$OUT/rbi/cef-lifecycle.txt" 2>/dev/null; then
      note "WARN: CEF sandbox denial/crash signatures in log -- likely RBI black screen from seccomp/apparmor confinement (see rbi/cef-lifecycle.txt)"
    elif grep -qi 'Initialized CEF process' "$OUT/rbi/cef-lifecycle.txt" 2>/dev/null; then
      note "RBI/CEF initialised cleanly in the log window (confinement OK); if RBI is SLOW look at the media path, not the sandbox"
    fi
  fi
else
  echo "RBI checks require a container deployment (Chromium runs inside the gateway container)." > "$OUT/rbi/note.txt"
fi

# Host LSM audit -- DISTRO-AWARE (the decisive RBI black-screen evidence):
#   RHEL/Rocky/CentOS/Fedora -> SELinux (getenforce; type=AVC ... denied)
#   Debian/Ubuntu            -> AppArmor (aa-status; apparmor="DENIED")
#   both                     -> seccomp  (type=SECCOMP audit records)
# A denial against the CEF sandbox's namespace/mount syscalls = RBI/DB black
# screen. We capture whichever LSM is actually in force, not just one family.
LSM="$OUT/rbi/host-lsm-audit.txt"
: > "$LSM"
LSM_HIT=""

# Relevance filter: only denials touching the gateway/CEF/container stack
# matter for an RBI black screen. Unrelated host AVCs (other services) are
# captured as a count only, so the WARN never cries wolf on background noise.
# Match container-confinement SELinux domains + explicit CEF/gateway names.
# Deliberately NOT the bare word "docker" -- it matches unrelated host
# filenames like docker-disk-alert.sh and floods the result with false hits.
REL='chrome|chromium|chrome-sandbox|guacd|conmon|kcm-cef|container_t|container_file_t|svirt|spc_t|/run/dbus|/dev/dri'

# --- SELinux (RHEL family) ---
if have getenforce || [ -e /sys/fs/selinux/enforce ]; then
  { echo "== SELinux =="; have getenforce && getenforce; have sestatus && sestatus 2>/dev/null | head -6; } >> "$LSM" 2>&1
  [ "$MODE" = "docker" ] && [ -n "$CONTAINER" ] \
    && echo "container ProcessLabel: $(docker inspect "$CONTAINER" --format '{{.ProcessLabel}}' 2>/dev/null) (empty = SELinux not confining this container)" >> "$LSM"
  AVC="$( { sudo -n ausearch -m AVC -ts recent 2>/dev/null || ausearch -m AVC -ts recent 2>/dev/null || sudo -n grep -aE 'type=AVC' /var/log/audit/audit.log 2>/dev/null; } )"
  AVC_REL="$(printf '%s\n' "$AVC" | grep -iE "$REL")"
  { echo "-- AVC denials: total=$(printf '%s\n' "$AVC" | grep -c 'type=AVC'), gateway/container-related below --"
    if [ -n "$AVC_REL" ]; then printf '%s\n' "$AVC_REL" | tail -40; else echo "(none gateway/container-related; any other AVCs are unrelated host noise)"; fi; } >> "$LSM" 2>&1
  [ -n "$AVC_REL" ] && LSM_HIT="SELinux AVC (container/CEF)"
fi

# --- AppArmor (Debian/Ubuntu family) ---
if have aa-status || [ -d /sys/module/apparmor ]; then
  { echo "== AppArmor =="; have aa-status && { sudo -n aa-status 2>/dev/null || aa-status 2>/dev/null; }; } >> "$LSM" 2>&1
  APP="$( { have dmesg && dmesg -T 2>/dev/null; have journalctl && { sudo -n journalctl -k --no-pager 2>/dev/null || journalctl -k --no-pager 2>/dev/null; }; } | grep -iE 'apparmor=.?(DENIED|ALLOWED)' )"
  APP_REL="$(printf '%s\n' "$APP" | grep -iE "$REL")"
  { echo "-- apparmor denials (DENIED=enforce, ALLOWED=complain): total=$(printf '%s\n' "$APP" | grep -c 'apparmor='), gateway-related below --"
    if [ -n "$APP_REL" ]; then printf '%s\n' "$APP_REL" | tail -40; else echo "(none gateway-related)"; fi; } >> "$LSM" 2>&1
  printf '%s\n' "$APP_REL" | grep -qiE 'apparmor=.?DENIED' && LSM_HIT="${LSM_HIT:+$LSM_HIT + }AppArmor DENIED"
fi

# --- seccomp (both families) ---
SEC="$( { have ausearch && { sudo -n ausearch -m SECCOMP -ts recent 2>/dev/null || ausearch -m SECCOMP -ts recent 2>/dev/null; }; have dmesg && dmesg -T 2>/dev/null | grep -iE 'seccomp'; } )"
SEC_REL="$(printf '%s\n' "$SEC" | grep -iE "$REL")"
{ echo "== seccomp =="; if [ -n "$SEC_REL" ]; then printf '%s\n' "$SEC_REL" | tail -20; else printf '%s\n' "$SEC" | grep -iE 'type=SECCOMP|seccomp' | tail -10; fi; } >> "$LSM" 2>&1
printf '%s\n' "$SEC_REL" | grep -qiE 'type=SECCOMP|seccomp.*(killed|denied)' && LSM_HIT="${LSM_HIT:+$LSM_HIT + }seccomp"

if [ -n "$LSM_HIT" ]; then
  note "WARN: host confinement denials present ($LSM_HIT) -- likely cause of an RBI/DB black screen (blocking the CEF sandbox); see rbi/host-lsm-audit.txt"
else
  note "no LSM denials found (SELinux/AppArmor/seccomp) -- if RBI is black/slow, it is not host confinement; see network/webrtc.txt"
fi

# ---- network reachability -------------------------------------------------
if [ "$DO_NET" = "yes" ]; then
  echo "[*] Outbound reachability"
  NF="$OUT/network/reachability.txt"
  : > "$NF"
  # Documented required outbound egress (gateway is outbound-only; no inbound
  # rules needed). Per Keeper docs -- compare against the probe results below.
  {
    echo "Required outbound egress (Keeper docs):"
    echo "  TCP 443            -> $ROUTER (router) + $CLOUD (cloud)"
    echo "  TCP+UDP 3478       -> $RELAY (STUN/TURN)"
    echo "  TCP+UDP 49152-65535-> WebRTC media (range; not probeable to one host -- verify firewall allows it)"
    echo "  -- probe results --"
  } >> "$NF"
  tcp_probe() { # host port
    if have nc; then timeout "$TIMEOUT" nc -z -w "$TIMEOUT" "$1" "$2" >/dev/null 2>&1; return $?; fi
    timeout "$TIMEOUT" bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1; return $?
  }
  udp_probe() { # host port -- best-effort: UDP is connectionless, so a "reachable"
    # only means the datagram left and no ICMP port-unreachable came back. Needs nc.
    have nc && timeout "$TIMEOUT" nc -u -z -w "$TIMEOUT" "$1" "$2" >/dev/null 2>&1
  }
  for h in "$ROUTER" "$RELAY" "$CLOUD"; do
    if have getent; then echo "DNS $h -> $(getent ahosts "$h" | awk '{print $1}' | sort -u | paste -sd, -)" >> "$NF"
    else echo "DNS $h -> (getent unavailable)" >> "$NF"; fi
  done
  # Does the relay resolve over IPv6 (AAAA)? If the gateway prefers IPv6 but the host
  # has no usable global IPv6, gathering fails -- cross-reference the host IPv6 note.
  if have getent; then echo "DNS(AAAA) $RELAY -> $(getent ahostsv6 "$RELAY" 2>/dev/null | awk '{print $1}' | sort -u | paste -sd, - || echo none)" >> "$NF"; fi
  for hp in "$ROUTER:443" "$CLOUD:443" "$RELAY:3478"; do
    h="${hp%:*}"; p="${hp##*:}"
    if tcp_probe "$h" "$p"; then echo "TCP $h:$p OPEN" >> "$NF"; else echo "TCP $h:$p BLOCKED" >> "$NF"; note "WARN: $h:$p not reachable"; fi
  done
  # STUN/TURN is UDP -- a TCP-open on 3478 does NOT prove the media path. Probe UDP too.
  if have nc; then
    if udp_probe "$RELAY" 3478; then echo "UDP $RELAY:3478 (STUN/TURN) reachable (best-effort)" >> "$NF"
    else echo "UDP $RELAY:3478 (STUN/TURN) BLOCKED or no response (best-effort)" >> "$NF"
      note "WARN: UDP 3478 to $RELAY appears blocked / no response. STUN/TURN is UDP -- a firewall that allows TCP 3478 but drops UDP 3478 (and the relay range) yields 'no relay candidate / session never connects'. Confirm UDP 3478 + 49152-65535 outbound to $RELAY."
    fi
  else
    echo "UDP $RELAY:3478 -- skipped (nc not installed; UDP probe needs nc)" >> "$NF"
  fi
  if have openssl; then
    echo | timeout "$TIMEOUT" openssl s_client -connect "${ROUTER}:443" -servername "$ROUTER" 2>/dev/null \
      | openssl x509 -noout -issuer -dates 2>/dev/null >> "$NF" || echo "TLS check to $ROUTER failed" >> "$NF"
  fi
fi

# ---- container DNS / routing + target test --------------------------------
if [ "$MODE" = "docker" ] && [ -n "$CONTAINER" ]; then
  echo "[*] Container DNS / routing"
  cap "$OUT/network/container-resolv.conf.txt" docker exec "$CONTAINER" cat /etc/resolv.conf
  cap "$OUT/network/container-route.txt" docker exec "$CONTAINER" ip route
  if [ -n "$TARGET" ]; then
    THOST="${TARGET%:*}"; TPORT="${TARGET##*:}"; [ "$TPORT" = "$TARGET" ] && TPORT=""
    echo "[*] Target test from inside container: $TARGET"
    { echo "== getent (DNS) =="; docker exec "$CONTAINER" getent hosts "$THOST"; } > "$OUT/network/target.txt" 2>&1 \
      || echo "DNS resolution of $THOST FAILED inside container" >> "$OUT/network/target.txt"
    if [ -n "$TPORT" ]; then
      if docker exec "$CONTAINER" bash -c "timeout $TIMEOUT bash -c 'echo > /dev/tcp/$THOST/$TPORT'" >/dev/null 2>&1; then
        echo "TCP $THOST:$TPORT reachable (by name) from container" >> "$OUT/network/target.txt"
      else
        echo "TCP $THOST:$TPORT NOT reachable from container" >> "$OUT/network/target.txt"
        note "rotation/RBI target $TARGET not reachable from inside the container (DNS or routing) -- see network/target.txt"
      fi
    fi
  fi
fi

# ---- WebRTC / media path --------------------------------------------------
# The gateway is outbound-only; PAM session media uses ICE over STUN/TURN.
# Sessions that reach "connected" then drop to "disconnected"/"failed" point
# here, not at the control plane.
echo "[*] WebRTC / media path"
WF="$OUT/network/webrtc.txt"
: > "$WF"

# relay IPs (used to grep conntrack + as the UDP egress target)
RELAY_IPS=""
have getent && RELAY_IPS="$(getent ahosts "$RELAY" 2>/dev/null | awk '{print $1}' | sort -u)"
{ echo "relay host: $RELAY"; echo "relay IPs: ${RELAY_IPS:-<unresolved>}"; } >> "$WF"

# what public IPv4 the relay actually sees us as (NAT egress), from the container
if [ "$MODE" = "docker" ] && [ -n "$CONTAINER" ] && [ "$DO_NET" = "yes" ]; then
  EGRESS4="$(docker exec "$CONTAINER" sh -c 'curl -s -4 --max-time 6 ifconfig.me 2>/dev/null' 2>/dev/null)"
  echo "container egress IPv4 (NAT public IP): ${EGRESS4:-unknown}" >> "$WF"
  # UDP 3478 egress to the relay from inside the container
  docker exec "$CONTAINER" sh -c "timeout 5 bash -c 'echo > /dev/udp/${RELAY}/3478' 2>/dev/null && echo SENT || echo FAIL" 2>/dev/null \
    | { read -r r; echo "UDP 3478 -> $RELAY from container: ${r:-FAIL}" >> "$WF"; }
fi

# live conntrack entries for the relay (best evidence of an active media flow)
if have conntrack && [ -n "$RELAY_IPS" ]; then
  PAT="$(printf '%s\n' $RELAY_IPS | paste -sd'|' -)"
  echo "conntrack entries to relay right now:" >> "$WF"
  conntrack -L 2>/dev/null | grep -E "$PAT" >> "$WF" || echo "  (none -- expected if no session is active)" >> "$WF"
fi

# log signature: connect/disconnect/fail ratio + a sample disconnect->failed gap
GWLOG=""
[ -r "$OUT/gateway/container-logs.txt" ] && GWLOG="$OUT/gateway/container-logs.txt"
[ -z "$GWLOG" ] && [ -r "$OUT/gateway/journal.txt" ] && GWLOG="$OUT/gateway/journal.txt"
if [ -n "$GWLOG" ]; then
  C_OK=$(grep -cE 'state changed: connected' "$GWLOG" 2>/dev/null)
  C_DIS=$(grep -cE 'state changed: disconnected' "$GWLOG" 2>/dev/null)
  C_FAIL=$(grep -cE 'state changed: failed|ICE connection failed' "$GWLOG" 2>/dev/null)
  {
    echo "ICE state counts in collected log window:"
    echo "  connected=$C_OK  disconnected=$C_DIS  failed=$C_FAIL"
    echo "recent ICE state transitions:"
    grep -E 'state changed: (connected|disconnected|failed)|ICE connection (failed|disconnected)' "$GWLOG" 2>/dev/null | tail -20
  } >> "$WF"
  if [ "${C_FAIL:-0}" -gt 0 ] 2>/dev/null && [ "${C_FAIL:-0}" -ge "${C_OK:-0}" ] 2>/dev/null; then
    note "WARN: more ICE 'failed' than 'connected' in the log window -- media path is degraded (see network/webrtc.txt; check host conntrack UDP timeout + INPUT policy)"
  fi

  # candidate-type usage: relay (TURN) means an extra hop = higher latency =
  # "slow session". Direct (host/srflx/prflx) is the fast path.
  C_RELAY=$(grep -cE 'typ=relay|udp4 relay|candidate:.* relay ' "$GWLOG" 2>/dev/null)
  C_SRFLX=$(grep -cE 'typ=srflx|udp4 srflx|candidate:.* srflx ' "$GWLOG" 2>/dev/null)
  C_HOST=$(grep -cE 'typ=host|udp4 host|candidate:.* host '   "$GWLOG" 2>/dev/null)
  {
    echo "ICE candidate types seen: relay=$C_RELAY srflx=$C_SRFLX host=$C_HOST"
    echo "relay RTT samples (latency to relay):"
    grep -iE 'latency to .*krelay|latency to .*3478' "$GWLOG" 2>/dev/null | tail -5
  } >> "$WF"
  if [ "${C_RELAY:-0}" -gt 0 ] 2>/dev/null && [ "${C_HOST:-0}" -eq 0 ] 2>/dev/null; then
    note "NOTE: sessions use the TURN relay (no direct/host candidates) -- expected for a bridge-mode container behind NAT; adds latency, the usual cause of 'slow' RBI/RDP on a VPS gateway"
  fi

  # IPv6 ICE noise: gateway attempting IPv6 STUN with no container IPv6 path
  IPV6_FAIL=$(grep -cE 'No available ipv6 IP address|failed to resolve stun.*ipv6' "$GWLOG" 2>/dev/null)
  NOPAIRS=$(grep -cE 'pingAllCandidates called with no candidate pairs' "$GWLOG" 2>/dev/null)
  echo "IPv6 STUN failures: ${IPV6_FAIL:-0}   'no candidate pairs' events: ${NOPAIRS:-0}" >> "$WF"
  if [ "${IPV6_FAIL:-0}" -gt 0 ] 2>/dev/null; then
    note "NOTE: ${IPV6_FAIL} IPv6 STUN-resolution failures -- gateway attempts IPv6 but the container has no IPv6 path; adds connection-setup latency + log noise"
  fi
fi

# does the gateway container actually have a usable global IPv6 address?
if [ "$MODE" = "docker" ] && [ -n "$CONTAINER" ]; then
  C6=$(docker exec "$CONTAINER" sh -c 'ip -6 addr show scope global 2>/dev/null | grep -c inet6' 2>/dev/null)
  echo "container global IPv6 addresses: ${C6:-0}" >> "$WF"
fi

# ---- rotation / discovery (host-side log evidence) ------------------------
# Vault-side rotation status comes from Commander ('pam action job-info' /
# 'service list') which needs vault auth -- this collector deliberately does NOT
# run it (avoids a non-interactive keeper login). Here we parse the gateway log
# for the rotation/discovery action signatures + their failures.
echo "[*] Rotation / discovery (log)"
if [ -n "${GWLOG:-}" ]; then
  RF="$OUT/gateway/rotation.txt"
  {
    echo "Rotation/discovery activity in the collected log window:"
    echo "  rotate-action lines : $(grep -cE 'rotate-action' "$GWLOG" 2>/dev/null)"
    echo "  discover-action     : $(grep -cE 'discover-action' "$GWLOG" 2>/dev/null)"
    echo "  kdnrm (rotation eng): $(grep -cE 'kdnrm' "$GWLOG" 2>/dev/null)"
    echo "-- recent rotation/discovery lines (status + errors) --"
    grep -iE 'rotate-action|discover-action|kdnrm|job-info-action' "$GWLOG" 2>/dev/null \
      | grep -iE 'ERROR|WARN|fail|exception|denied|timeout|unreachable|refused|started|completed|success' | tail -30
  } > "$RF"
  RERR=$(grep -ciE '(rotate-action|discover-action|kdnrm).*(ERROR|fail|exception|denied|timeout|unreachable|refused)' "$GWLOG" 2>/dev/null)
  if [ "${RERR:-0}" -gt 0 ] 2>/dev/null; then
    note "NOTE: ${RERR} rotation/discovery error line(s) in the log -- see gateway/rotation.txt (vault-side status: run 'pam action job-info' in Commander)"
  fi
else
  echo "(no gateway log available to parse for rotation activity)" > "$OUT/gateway/rotation.txt"
fi

# ---- debug how-to (printed, never auto-applied) ---------------------------
cat > "$OUT/DEBUG-HOWTO.txt" <<'EOF'
Enabling verbose Gateway debug logs (do this WITH support, then revert)

Docker / Docker Compose:
  In the keeper-gateway service "environment:" block add:
      KEEPER_GATEWAY_LOG_LEVEL: "debug"   # gateway
      LOG_LEVEL: "debug"                  # guacd
  Apply and restart:
      docker compose up -d
  Tail:
      docker logs -f <gateway-container>

  Valid levels: error, warning, info, debug (guacd also supports trace).
  Structured formats (json, logfmt, cef, ...) require gateway 1.8.0+.

Native (Linux service):
  Restart at debug per the Linux install docs, then:
      journalctl -u keeper-gateway -f

Windows installer:
  "Turn on debug logging" enables verbose gateway logs. Use only when
  debugging with Keeper support; not recommended for production.

Workflow: enable debug -> reproduce the failing connection/rotation/RBI
session -> re-run this collector -> revert the log level afterwards.
EOF

# ---- collection notice in the bundle -------------------------------------
{
  echo "COLLECTION NOTICE -- read before sharing this bundle"
  echo "Generated: $(date)   Mode: $([ "$MINIMAL" = yes ] && echo MINIMAL || echo FULL)"
  echo
  echo "WHAT THIS BUNDLE CONTAINS:"
  echo "  host OS/resources, container config + logs, firewall, conntrack,"
  echo "  network interfaces/routes/DNS, WebRTC media analysis, RBI/LSM audit."
  if [ "$MINIMAL" = "yes" ]; then
    echo "  (MINIMAL: container list filtered to keeper/guac; firewall trimmed to"
    echo "   gateway rules; full interface/socket inventory + /etc/hosts skipped.)"
  else
    echo "  (FULL: EVERY container, ALL interfaces, COMPLETE firewall ruleset, ALL"
    echo "   listening ports, /etc/hosts -- reveals your whole infra topology.)"
  fi
  echo
  echo "WHAT IT DOES NOT CONTAIN:"
  echo "  gateway config file / GATEWAY_CONFIG payload, .env files, secret VALUES"
  echo "  (redacted -> [REDACTED]), or 'keeper get --unmask' output."
  echo
  echo "CONSEQUENCES OF OVER-SHARING: the more you collect, the more infrastructure"
  echo "detail (topology, unrelated services, project names in firewall comments,"
  echo "internal IPs) you hand to the recipient. Secrets are redacted + scanned"
  echo "(see REDACTION-SCAN.txt), but review before sending externally, and prefer"
  echo "--minimal when the recipient is a third party."
} > "$OUT/COLLECTION-NOTICE.txt"

# ---- secret scan (defense-in-depth: flag anything redaction missed) -------
echo
echo "[*] Secret scan"
SCAN="$OUT/REDACTION-SCAN.txt"
# scan key list mirrors SECRET_KEYS so the defense-in-depth scan can catch a
# redaction miss for ANY secret-shaped key (not a narrower subset).
grep -rinIE '(-----BEGIN [A-Z ]*PRIVATE KEY|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}|://[^:/@ ]+:[^@/ ]+@|(GATEWAY_CONFIG|KCM_LICENSE|[A-Za-z0-9_]*(PASSWORD|PASSWD|PWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|PASSPHRASE|CREDENTIALS?|_KEY|_SEED|SEED))"?[ ]*[:=][ ]*"?[^ ",}]{6,})' "$OUT" 2>/dev/null \
  | grep -viE 'REDACTED' \
  | grep -vF 'REDACTION-SCAN.txt' > "$SCAN" 2>/dev/null || true
RESID=$(grep -cE '.' "$SCAN" 2>/dev/null); RESID=${RESID:-0}
if [ "${RESID:-0}" -gt 0 ] 2>/dev/null; then
  note "WARN: secret-scan flagged ${RESID} line(s) that may be UNREDACTED -- open REDACTION-SCAN.txt and review/scrub before sharing"
else
  echo "no residual secret patterns detected ($(date))" > "$SCAN"
  note "secret-scan: clean (no residual secret patterns detected)"
fi

# ---- bundle ---------------------------------------------------------------
echo
echo "[*] Packaging"
BUNDLE="${OUT}.tar.gz"
tar czf "$BUNDLE" -C "$(dirname "$OUT")" "$(basename "$OUT")" 2>/dev/null \
  && echo "Bundle: $BUNDLE" || echo "tar failed; the folder is still at $OUT"

echo
echo "Summary"
if [ "${#NOTES[@]}" -eq 0 ]; then echo "  (no notable flags)"; fi
echo
echo "What this bundle DOES NOT contain: the gateway config file / GATEWAY_CONFIG"
echo "payload, .env files, secret values (redacted -> [REDACTED]), or 'keeper get"
echo "--unmask' output. It DOES contain host/container config, logs, firewall, and"
echo "network topology. Secrets are redacted best-effort + scanned (REDACTION-SCAN.txt);"
echo "still eyeball the bundle before sharing externally."
