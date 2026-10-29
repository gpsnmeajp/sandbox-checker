#!/usr/bin/env bash
# check_sandbox.sh - Non-destructive sandbox / isolation probe for Linux and macOS.
#
# PURPOSE
#   Answer two questions about the environment a coding agent is running in:
#     1. How isolated is it? (host / container / VM / OS sandbox)
#     2. What could the agent reach or damage if it misbehaved? ("blast radius")
#   The output is plain "key: value" text meant to be read by a human or an AI
#   agent, which then writes a risk report (see ../SKILL.md).
#
# WHY SOME CHECKS MAY LOOK SUSPICIOUS
#   A security self-check necessarily looks at the same things an attacker
#   would look at: credential files, sudo, the Docker socket, the cloud
#   metadata endpoint, and so on. This script only asks "does it exist?" and
#   "would access be allowed?". It never uses what it finds. Every such check
#   has a comment explaining what is (and is not) done.
#
# SAFETY GUARANTEES (read-only by design)
#   - Never creates, modifies or deletes files. Write access is checked with
#     `test -w`, which asks the kernel about permissions without writing.
#   - Never reads the contents of credential files. `test -r` only checks
#     whether a read *would* be permitted.
#   - Never prints secret values. Only environment variable NAMES are listed.
#   - Never attempts privilege escalation, container escape or exploitation.
#     The only privilege-related command is `sudo -n true`, which does nothing
#     and fails immediately if a password would be required.
#   - Never contacts external hosts unless --network is given explicitly.
#     Even then, only DNS lookups, HTTPS HEAD requests to example.com/github.com
#     and bare TCP connects are made.
#   - No heavy work: no whole-disk scans, no port scans, no process spawning loops.
#
# USAGE
#   bash check_sandbox.sh            # local checks only
#   bash check_sandbox.sh --network  # also test outbound connectivity
#
# LICENSE: MIT-0

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
NETWORK=0
for arg in "$@"; do
  case "$arg" in
    --network) NETWORK=1 ;;
    -h|--help) sed -n '2,36p' "$0"; exit 0 ;;  # print the header comment above
  esac
done

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
section() { printf '\n== %s ==\n' "$1"; }          # section header
kv() { printf '%-28s %s\n' "$1:" "$2"; }            # aligned "key: value" line
have() { command -v "$1" >/dev/null 2>&1; }         # is a command available?
# Run a test command silently and print yes/no. Used with `test -r/-w` etc.
yesno() { if "$@" >/dev/null 2>&1; then echo yes; else echo no; fi; }

OS="$(uname -s 2>/dev/null)"

# Git Bash / MSYS / Cygwin emulate POSIX permissions on top of NTFS with the
# "noacl" mount option, so `test -w` reports almost everything as writable.
# Warn instead of producing misleading results; the PowerShell script is the
# right tool on Windows.
case "$OS" in
  MINGW*|MSYS*|CYGWIN*)
    echo "WARNING: running under $OS (Git Bash/MSYS/Cygwin on Windows)."
    echo "  POSIX permission checks are unreliable here (noacl mounts report everything writable)."
    echo "  Use scripts/check_sandbox.ps1 instead; results below are indicative only."
    ;;
esac

# ---------------------------------------------------------------------------
# System: basic facts used to interpret everything else.
# ---------------------------------------------------------------------------
section "System"
kv "os" "$OS"
kv "kernel" "$(uname -r 2>/dev/null)"
kv "arch" "$(uname -m 2>/dev/null)"
kv "hostname" "$(hostname 2>/dev/null)"
if [ -r /etc/os-release ]; then
  # Sourced in a subshell so its variables do not leak into this script.
  kv "distro" "$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
fi
if [ "$OS" = "Darwin" ] && have sw_vers; then
  kv "macos" "$(sw_vers -productVersion 2>/dev/null)"
fi
# WSL kernels contain "microsoft" in /proc/version. WSL is NOT an isolation
# boundary: Windows drives are usually mounted read-write under /mnt/c.
if grep -qi microsoft /proc/version 2>/dev/null; then
  kv "wsl" "yes ($(grep -o 'WSL[0-9]*' /proc/version 2>/dev/null | head -1))"
fi
kv "shell" "${SHELL:-unknown}"
kv "cwd" "$(pwd)"

# ---------------------------------------------------------------------------
# Identity & privileges: running as root (or able to become root) is the
# single biggest factor in how much damage is possible.
# ---------------------------------------------------------------------------
section "Identity & privileges"
kv "user" "$(id -un 2>/dev/null) (uid=$(id -u 2>/dev/null))"
kv "groups" "$(id -Gn 2>/dev/null)"   # e.g. membership in sudo/wheel/docker
if [ "$(id -u 2>/dev/null)" = "0" ]; then kv "is_root" "YES"; else kv "is_root" "no"; fi
if have sudo; then
  # `sudo -n true`: -n means "non-interactive, never prompt for a password".
  # `true` is a no-op command. So this only reveals whether passwordless sudo
  # is configured (which would make the agent effectively root). Nothing runs
  # as root other than `true` itself.
  kv "sudo_without_password" "$(yesno sudo -n true)"
else
  kv "sudo_without_password" "sudo not installed"
fi
# Linux only: the kernel publishes the process's security state in
# /proc/self/status. Reading our own status file is harmless.
if grep -q '^CapEff' /proc/self/status 2>/dev/null; then
  # Effective / bounding capability sets (hex bitmasks). All-ones suggests a
  # privileged container; zero is a normal unprivileged process.
  kv "CapEff" "$(awk '/^CapEff/{print $2}' /proc/self/status)"
  kv "CapBnd" "$(awk '/^CapBnd/{print $2}' /proc/self/status)"
  # NoNewPrivs=1 means setuid binaries cannot grant extra privileges.
  kv "NoNewPrivs" "$(awk '/^NoNewPrivs/{print $2}' /proc/self/status)"
  # Seccomp=2 means a syscall filter is active (Docker default, bubblewrap...).
  kv "Seccomp" "$(awk '/^Seccomp:/{print $2}' /proc/self/status) (0=off 1=strict 2=filter)"
  if have capsh; then
    # Turn the hex mask into readable names like cap_sys_admin (decode only).
    kv "caps_decoded" "$(capsh --decode="$(awk '/^CapEff/{print $2}' /proc/self/status)" 2>/dev/null | cut -d= -f2)"
  fi
fi
if [ -r /proc/self/uid_map ]; then
  # User-namespace mapping. "0 1000 1" = container root is an ordinary user on
  # the host (good). "0 0 4294967295" = same UID space as the host.
  kv "uid_map" "$(tr -s ' ' < /proc/self/uid_map | head -3 | tr '\n' ';')"
fi

# ---------------------------------------------------------------------------
# Container / VM detection: several weak signals, combined by the reader.
# No single signal is conclusive, so all of them are reported.
# ---------------------------------------------------------------------------
section "Container / VM detection"
# Marker files created by Docker and Podman inside containers.
[ -e /.dockerenv ] && kv "/.dockerenv" "present"
[ -e /run/.containerenv ] && kv "/run/.containerenv" "present (podman)"
# systemd-nspawn, LXC and others set $container.
[ -n "${container:-}" ] && kv "\$container" "$container"
# Kubernetes injects these into every pod. Only presence is reported; the
# service account token under /var/run/secrets is NOT read.
[ -n "${KUBERNETES_SERVICE_HOST:-}" ] && kv "kubernetes" "KUBERNETES_SERVICE_HOST set"
[ -d /var/run/secrets/kubernetes.io ] && kv "k8s_serviceaccount" "present (/var/run/secrets/kubernetes.io)"
if [ -r /proc/1/cgroup ]; then
  # cgroup path of PID 1; names like docker/kubepods/lxc indicate a container.
  kv "pid1_cgroup" "$(head -3 /proc/1/cgroup | tr '\n' ';')"
fi
# Name of PID 1. On a real host it is systemd/init/launchd; in a container it
# is often the app itself (bash, node, tini...).
if [ -r /proc/1/comm ]; then
  kv "pid1_comm" "$(cat /proc/1/comm 2>/dev/null)"
elif have ps; then
  kv "pid1_comm" "$(ps -p 1 -o comm= 2>/dev/null)"
fi
if have systemd-detect-virt; then
  # Read-only query; prints the detected VM / container technology or "none".
  kv "systemd-detect-virt" "$(systemd-detect-virt 2>/dev/null || echo none)"
  kv "container_virt" "$(systemd-detect-virt -c 2>/dev/null || echo none)"
fi
if [ -r /sys/class/dmi/id/product_name ]; then
  # Firmware strings such as "VirtualBox", "KVM", "Google Compute Engine".
  kv "dmi_product" "$(cat /sys/class/dmi/id/product_name 2>/dev/null)"
  kv "dmi_vendor" "$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null)"
fi
if [ "$OS" = "Darwin" ] && have sysctl; then
  # kern.hv_vmm_present=1 when macOS itself runs inside a VM.
  kv "hv_vmm_present" "$(sysctl -n kern.hv_vmm_present 2>/dev/null)"
  kv "hw_model" "$(sysctl -n hw.model 2>/dev/null)"
fi
if [ -r /proc/cpuinfo ]; then
  # The "hypervisor" CPU flag is set when running under any hypervisor.
  grep -qw hypervisor /proc/cpuinfo 2>/dev/null && kv "cpu_hypervisor_flag" "yes"
fi
if [ -e /proc/self/ns/pid ] && [ -e /proc/1/ns/pid ]; then
  # Namespace identifiers (e.g. "pid:[4026531836]"). Values that differ from
  # the host's well-known initial namespaces indicate isolation.
  kv "self_pid_ns" "$(readlink /proc/self/ns/pid 2>/dev/null)"
  kv "self_mnt_ns" "$(readlink /proc/self/ns/mnt 2>/dev/null)"
  kv "self_net_ns" "$(readlink /proc/self/ns/net 2>/dev/null)"
fi
# How many processes can we see? A handful means a separate PID namespace;
# hundreds means we share the host's process table.
if [ -d /proc ]; then
  kv "visible_processes" "$(ls -d /proc/[0-9]* 2>/dev/null | wc -l | tr -d ' ')"
elif have ps; then
  kv "visible_processes" "$(ps -A 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')"
fi

# ---------------------------------------------------------------------------
# Sandbox mechanisms: which kernel / OS confinement features are active.
# ---------------------------------------------------------------------------
section "Sandbox mechanisms"
if [ -r /proc/self/attr/current ]; then
  # AppArmor / SELinux label of this process, e.g. "docker-default (enforce)".
  kv "lsm_label" "$(tr -d '\0' < /proc/self/attr/current 2>/dev/null)"
fi
[ -r /sys/kernel/security/lsm ] && kv "active_lsms" "$(cat /sys/kernel/security/lsm 2>/dev/null)"
have getenforce && kv "selinux" "$(getenforce 2>/dev/null)"   # read-only query
[ -e /proc/self/attr/landlock ] && kv "landlock" "attr present"
# Only checks whether sandboxing tools are installed; none of them is executed.
for tool in bwrap firejail nsjail gvisor runsc sandbox-exec; do
  have "$tool" && kv "tool:$tool" "installed"
done
if [ "$OS" = "Darwin" ]; then
  [ -n "${APP_SANDBOX_CONTAINER_ID:-}" ] && kv "app_sandbox" "APP_SANDBOX_CONTAINER_ID set"
  # Seatbelt-confined processes usually cannot read /Library/Keychains, so a
  # "no" here hints at a macOS sandbox. Only permission is tested; nothing in
  # the keychain directory is opened.
  kv "read_/Library/Keychains" "$(yesno test -r /Library/Keychains)"
fi
# Environment variable NAMES hinting at a sandbox / CI / cloud dev environment.
# `cut -d= -f1` drops everything after "=", so values are never printed.
SANDBOX_VARS="$(env | cut -d= -f1 | grep -iE 'sandbox|container|codespace|gitpod|devcontainer|^CI$|github_actions|replit|e2b|modal|daytona' | sort | tr '\n' ' ')"
kv "sandbox_related_env_names" "${SANDBOX_VARS:-none}"

# ---------------------------------------------------------------------------
# Filesystem: where could the agent write (and therefore delete or tamper)?
# ---------------------------------------------------------------------------
section "Filesystem"
# `test -w` asks whether writing would be permitted; no file is created.
# Caveat: Landlock/seccomp/Seatbelt can deny writes that `test -w` allows.
for p in / /etc /usr /bin "$HOME" "$(pwd)" /tmp /var/tmp; do
  [ -e "$p" ] || continue
  kv "writable:$p" "$(yesno test -w "$p")"
done
if [ -r /proc/self/mounts ]; then
  # Root filesystem type and options (overlay = container, "ro" = read-only).
  kv "root_mount" "$(awk '$2=="/"{print $1" "$3" "$4}' /proc/self/mounts | head -1)"
  # List real (non-pseudo) mounts to spot host directories bind-mounted into
  # the sandbox, e.g. /home or /var/run/docker.sock.
  echo "-- notable mounts (bind/host-ish, max 25) --"
  awk '$3!~/^(proc|sysfs|cgroup2?|devpts|mqueue|tmpfs|devtmpfs|securityfs|debugfs|tracefs|pstore|bpf|configfs|fusectl|hugetlbfs|autofs|binfmt_misc|nsfs)$/ {print "  "$2" <- "$1" ("$3", "substr($4,1,40)")"}' /proc/self/mounts 2>/dev/null | head -25
elif have mount; then
  # macOS: `mount` with no arguments only lists mounts.
  echo "-- mounts (max 15) --"
  mount 2>/dev/null | head -15 | sed 's/^/  /'
fi
if have df; then
  kv "disk_free_cwd" "$(df -h . 2>/dev/null | awk 'NR==2{print $4" free of "$2}')"
fi

# ---------------------------------------------------------------------------
# Credentials reachable: well-known locations of keys and tokens.
# IMPORTANT: file contents are never opened. Only existence (`-e`) and
# permission (`-r` / `-w`) are tested, so nothing secret can end up in output.
# ---------------------------------------------------------------------------
section "Credentials reachable (existence/readability only, contents NOT read)"
check_path() {
  local p="$1"
  if [ -e "$p" ]; then
    local r w
    r="$(yesno test -r "$p")"; w="$(yesno test -w "$p")"
    kv "$p" "exists readable=$r writable=$w"
  fi
}
# Each path is a common credential store; see references/interpretation.md
# for what leaking each one would mean. /etc/shadow and /etc/sudoers should
# be unreadable for non-root users; "readable=yes" there means root-level access.
for p in \
  "$HOME/.ssh" "$HOME/.ssh/id_rsa" "$HOME/.ssh/id_ed25519" "$HOME/.ssh/authorized_keys" \
  "$HOME/.aws/credentials" "$HOME/.aws/config" "$HOME/.config/gcloud" "$HOME/.azure" \
  "$HOME/.kube/config" "$HOME/.docker/config.json" "$HOME/.config/gh/hosts.yml" \
  "$HOME/.git-credentials" "$HOME/.netrc" "$HOME/.npmrc" "$HOME/.pypirc" \
  "$HOME/.gnupg" "$HOME/.password-store" "$HOME/.config/op" \
  "$HOME/.bash_history" "$HOME/.zsh_history" \
  "$HOME/.claude.json" "$HOME/.claude/.credentials.json" "$HOME/.codex/auth.json" \
  "$HOME/Library/Keychains" \
  /etc/shadow /etc/sudoers /root \
  ; do
  check_path "$p"
done
# .env files in the current project. Limited to depth 2 to stay fast; only
# file names are printed.
ENVFILES="$(find . -maxdepth 2 -name '.env*' -type f 2>/dev/null | head -10 | tr '\n' ' ')"
kv "project_.env_files" "${ENVFILES:-none}"
# Names of environment variables that look like secrets. Values are cut off
# by `cut -d= -f1` and never printed.
SECRET_ENV="$(env | cut -d= -f1 | grep -iE 'token|secret|passw|api_?key|access_?key|private|credential|auth' | sort | tr '\n' ' ')"
kv "secret_like_env_names" "${SECRET_ENV:-none}"

# ---------------------------------------------------------------------------
# Dangerous interfaces: things that turn "inside a sandbox" into "host root".
# Only existence and permission bits are tested; nothing is connected to,
# opened or written.
# ---------------------------------------------------------------------------
section "Dangerous interfaces"
# A writable container-runtime socket lets anyone start a privileged container
# that mounts the host's / - equivalent to host root.
for s in /var/run/docker.sock /run/docker.sock /run/containerd/containerd.sock /run/podman/podman.sock "${XDG_RUNTIME_DIR:-/nonexistent}/podman/podman.sock" "$HOME/.docker/run/docker.sock" /var/run/crio/crio.sock; do
  [ -e "$s" ] && kv "socket:$s" "exists rw=$(yesno test -w "$s")"
done
[ -n "${DOCKER_HOST:-}" ] && kv "DOCKER_HOST" "set"
# An SSH agent can sign with loaded keys even if key files are unreadable.
[ -n "${SSH_AUTH_SOCK:-}" ] && kv "ssh_agent_socket" "SSH_AUTH_SOCK set (agent keys usable)"
# Raw devices: writable disk or memory devices allow destroying the system.
for d in /dev/kvm /dev/mem /dev/kmem /dev/sda /dev/nvme0n1 /dev/fuse /dev/net/tun; do
  [ -e "$d" ] && kv "device:$d" "exists rw=$(yesno test -w "$d")"
done
# Writable sysrq-trigger / cgroup fs are typical of privileged containers.
# Only `test -w` is used; NOTHING is ever written to these files.
[ -e /proc/sysrq-trigger ] && kv "/proc/sysrq-trigger" "writable=$(yesno test -w /proc/sysrq-trigger)"
[ -d /sys/fs/cgroup ] && kv "cgroup_fs_writable" "$(yesno test -w /sys/fs/cgroup)"

# ---------------------------------------------------------------------------
# Resource limits: whether runaway processes (fork bombs, memory leaks) are
# contained. Values are read, not changed.
# ---------------------------------------------------------------------------
section "Resource limits"
kv "ulimit_procs" "$(ulimit -u 2>/dev/null)"
kv "ulimit_files" "$(ulimit -n 2>/dev/null)"
[ -r /sys/fs/cgroup/memory.max ] && kv "cgroup_memory.max" "$(cat /sys/fs/cgroup/memory.max)"
[ -r /sys/fs/cgroup/cpu.max ] && kv "cgroup_cpu.max" "$(cat /sys/fs/cgroup/cpu.max)"
[ -r /sys/fs/cgroup/pids.max ] && kv "cgroup_pids.max" "$(cat /sys/fs/cgroup/pids.max)"

# ---------------------------------------------------------------------------
# Network (local view): configuration only, no packets are sent.
# ---------------------------------------------------------------------------
section "Network (local view)"
if have ip; then
  # Only "lo" here would mean the sandbox has no network at all.
  kv "interfaces" "$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | tr '\n' ' ')"
  kv "default_route" "$(ip route show default 2>/dev/null | head -1)"
elif have ifconfig; then
  kv "interfaces" "$(ifconfig -l 2>/dev/null || ifconfig 2>/dev/null | awk '/^[a-z]/{print $1}' | tr '\n' ' ')"
fi
[ -r /etc/resolv.conf ] && kv "nameservers" "$(awk '/^nameserver/{print $2}' /etc/resolv.conf | tr '\n' ' ')"
# Proxy variable NAMES only: proxy URLs can embed user:password.
PROXY_VARS="$(env | cut -d= -f1 | grep -iE '^(http|https|all|no)_proxy$' | tr '\n' ' ')"
kv "proxy_env_names" "${PROXY_VARS:-none}"

# ---------------------------------------------------------------------------
# Network egress (opt-in with --network): can data leave this machine?
# Contacts external hosts, so it is off by default.
# ---------------------------------------------------------------------------
if [ "$NETWORK" = "1" ]; then
  section "Network egress (opt-in)"
  # TCP reachability test: opens a connection and closes it immediately.
  # No data is sent. Prefers `nc -z` (zero-I/O mode), falls back to bash's
  # /dev/tcp pseudo-device with a 3-second timeout.
  tcp_probe() { # host port -> reachable/blocked
    if have nc; then nc -z -w 3 "$1" "$2" >/dev/null 2>&1 && echo reachable || echo blocked
    elif have timeout; then timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1 && echo reachable || echo blocked
    else echo "no nc/timeout"; fi
  }
  # DNS resolution of a reserved, harmless domain (example.com, RFC 2606).
  if have getent; then kv "dns:example.com" "$(getent hosts example.com >/dev/null 2>&1 && echo resolves || echo fails)"
  elif have host; then kv "dns:example.com" "$(host example.com >/dev/null 2>&1 && echo resolves || echo fails)"; fi
  if have curl; then
    # HTTPS HEAD request (-I): only the status code is printed, the response
    # is discarded. github.com shows whether an allowlist permits dev hosts.
    kv "https:example.com" "$(curl -sS -o /dev/null -m 5 -I -w '%{http_code}' https://example.com 2>/dev/null || echo blocked)"
    kv "https:github.com" "$(curl -sS -o /dev/null -m 5 -I -w '%{http_code}' https://github.com 2>/dev/null || echo blocked)"
  fi
  # Raw TCP to a public IP (Cloudflare DNS) bypasses DNS-based filtering.
  kv "tcp:1.1.1.1:443" "$(tcp_probe 1.1.1.1 443)"
  # Cloud instance metadata service (AWS/GCP/Azure). If reachable, temporary
  # cloud credentials may be obtainable - a high-severity finding. This is a
  # TCP connect ONLY; no HTTP request is sent and no credentials are fetched.
  kv "tcp:169.254.169.254:80" "$(tcp_probe 169.254.169.254 80) (cloud metadata)"
else
  section "Network egress"
  echo "skipped (run with --network to test outbound connectivity)"
fi

echo
echo "done. (read-only probe; no files were written)"
