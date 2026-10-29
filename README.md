# sandbox-checker

[日本語版 README はこちら](README_JA.md)

An [Agent Skill](https://docs.claude.com/en/docs/agents-and-tools/agent-skills/overview) that lets a coding agent (Claude Code, etc.) inspect **how isolated its own environment is** and **what it could reach or damage** — without changing anything.

Ask things like *"Am I in a sandbox?"*, *"How isolated is this agent?"* or *"What's the worst that could happen if I enable auto-approve?"*, and the agent runs a read-only probe and writes a risk report with an isolation level (L0–L4).

## Why

Before letting an agent run untrusted code, auto-approve commands, or work in "YOLO mode", you want to know the blast radius:

- Is it a container, a VM, an OS sandbox — or just your laptop?
- Is it root / admin? Can it `sudo` without a password?
- Which of your SSH keys, cloud credentials and tokens can it read?
- Can it reach the internet (i.e. exfiltrate them)? The cloud metadata endpoint?
- Is a Docker socket exposed (= host root)?

## Safety: read-only by design

A security self-check has to look at the same things an attacker would. That is why the scripts are heavily commented: every check that might look suspicious explains what it does and does not do.

| Guarantee | How |
|---|---|
| No files are written, modified or deleted | Write access is checked with `test -w` (POSIX) or by reading ACLs (Windows) |
| Credential contents are never read | Only existence and permission are tested; on Windows a read handle is opened and closed without reading bytes |
| Secret values are never printed | Only environment variable **names**; only the **count** of Credential Manager entries |
| No privilege escalation or escape attempts | The only privilege probe is `sudo -n true` (non-interactive no-op) |
| No network traffic by default | Egress tests run only with `--network` / `-Network`: a DNS lookup, HTTPS HEAD to example.com and github.com, and bare TCP connects (no HTTP request to the metadata service) |
| No heavy work | No disk-wide scans, port scans or fork loops |

The skill instructions (`SKILL.md`) apply the same rules to the agent: ask before testing the network, and never put secret values in the report.

## Install

### Claude Code

Copy the skill folder into your personal or project skills directory:

```bash
# personal (all projects)
cp -r sandbox-checker ~/.claude/skills/

# or project-local
cp -r sandbox-checker .claude/skills/
```

On Windows (PowerShell):

```powershell
Copy-Item -Recurse sandbox-checker "$env:USERPROFILE\.claude\skills\"
```

### Claude.ai / other skill-compatible agents

Zip the `sandbox-checker/` folder (with `SKILL.md` at its root) and upload it as a custom skill.

## Usage

Just ask the agent:

```
How isolated is this environment? What could go wrong if you ran untrusted code here?
```

```
Check whether I'm inside a container, and test outbound network access too.
```

You can also run the probes directly:

```bash
# Linux / macOS / WSL
bash sandbox-checker/scripts/check_sandbox.sh
bash sandbox-checker/scripts/check_sandbox.sh --network
```

```powershell
# Windows
powershell -NoProfile -ExecutionPolicy Bypass -File sandbox-checker\scripts\check_sandbox.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File sandbox-checker\scripts\check_sandbox.ps1 -Network
```

(`-ExecutionPolicy Bypass` applies only to that one process.)

### Example output (excerpt)

```
== Identity & privileges ==
is_admin_elevated:             no
integrity_level:               Mandatory Label\Medium Mandatory Level

== Credentials reachable (existence/readability only, contents NOT read) ==
C:\Users\me\.ssh\id_rsa:       exists readable=yes
secret_like_env_names:         GOOGLE_API_KEY OPENAI_API_KEY

== Network egress (opt-in) ==
https:example.com:             200
tcp:169.254.169.254:80:        blocked (cloud metadata)
```

The agent turns this into a report: conclusion and isolation level, environment summary, risks ranked by severity, what is protected, what could not be checked, and recommendations.

## Isolation levels

| Level | Meaning |
|---|---|
| L0 | Running on the host as root / admin |
| L1 | Running on the host as a normal user — all of the user's files and credentials are reachable |
| L2 | Container / sandbox, but home dir, credentials or Docker socket are exposed, or network is unrestricted |
| L3 | Container / sandbox with restricted filesystem and network |
| L4 | Dedicated / disposable VM, strongly separated from host and personal data |

The level is set by the **weakest hole**: a container with a writable Docker socket is not better than L2.

## What is checked

- **System**: OS, kernel, WSL
- **Identity & privileges**: root/admin, passwordless sudo, Linux capabilities, seccomp, NoNewPrivs, user namespaces, Windows integrity level, UAC, AppContainer, dangerous token privileges
- **Container / VM detection**: `/.dockerenv`, cgroups, PID 1, namespaces, DMI, hypervisor flags, Kubernetes, Windows Sandbox / containers
- **Sandbox mechanisms**: AppArmor / SELinux / Landlock, bubblewrap etc., macOS Seatbelt hints, PowerShell language mode, AppLocker, Defender
- **Filesystem**: writable system / home / project / temp dirs, mounts, network drives
- **Credentials**: SSH, AWS/GCP/Azure, kube, Docker, GitHub CLI, git, npm/PyPI, GnuPG, Claude/Codex auth files, shell history, browser password stores, `.env` files, secret-like env var names
- **Dangerous interfaces**: Docker/containerd/Podman sockets and pipes, SSH agent, raw devices, sysrq, cgroup fs, WSL distros, remote-access services
- **Resource limits**: ulimits, cgroup memory/CPU/pids
- **Network**: interfaces, DNS, proxies, firewall; optionally egress and cloud metadata reachability

See [`sandbox-checker/references/interpretation.md`](sandbox-checker/references/interpretation.md) for how each signal is interpreted (Japanese).

## Limitations

- This is a heuristic check of common signals, **not a security guarantee**. A clean result does not prove the environment is safe.
- `test -w` and ACL-based estimates can disagree with Landlock, seccomp, Seatbelt or AppContainer enforcement.
- Container detection signals can be spoofed or hidden.
- On Windows, use the PowerShell script; running the bash script under Git Bash gives unreliable permission results (it prints a warning).
- The bash script has been designed for Linux and macOS; please report issues on distributions it misreads.

## Repository layout

```
sandbox-checker/
├── SKILL.md                      # skill instructions (workflow, safety rules, report format)
├── scripts/
│   ├── check_sandbox.sh          # Linux / macOS / WSL probe
│   └── check_sandbox.ps1         # Windows probe (PowerShell 5.1+)
├── references/
│   └── interpretation.md         # how to interpret each signal, severity rules
└── evals/
    └── evals.json                # test prompts (skill-creator format)
```

Built with Anthropic's [skill-creator](https://github.com/anthropics/skills).

## License

[MIT-0](LICENSE) (MIT No Attribution).
