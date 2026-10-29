<#
check_sandbox.ps1 - Non-destructive sandbox / isolation probe for Windows
(Windows PowerShell 5.1+ and PowerShell 7).

PURPOSE
  Answer two questions about the environment a coding agent is running in:
    1. How isolated is it? (host / VM / Windows Sandbox / container / AppContainer)
    2. What could the agent reach or damage if it misbehaved? ("blast radius")
  The output is plain "key: value" text meant to be read by a human or an AI
  agent, which then writes a risk report (see ..\SKILL.md).

WHY SOME CHECKS MAY LOOK SUSPICIOUS
  A security self-check necessarily looks at the same things an attacker
  would look at: credential files, admin rights, browser password stores, the
  Docker pipe, the cloud metadata endpoint, and so on. This script only asks
  "does it exist?" and "would access be allowed?". It never uses what it
  finds. Every such check has a comment explaining what is (and is not) done.

SAFETY GUARANTEES (read-only by design)
  - Never creates, modifies or deletes files, registry keys or settings.
    Write access is ESTIMATED by reading the directory's ACL (Get-Acl).
  - Never reads the contents of credential files. Readability is tested by
    opening a read handle and closing it immediately, without reading bytes.
  - Never prints secret values: only environment variable NAMES, and only the
    NUMBER of Credential Manager entries.
  - Never attempts privilege escalation. Uses only standard read-only queries
    (whoami, Get-CimInstance, Get-Service, Get-ItemProperty, netsh ... show).
  - Never contacts external hosts unless -Network is given explicitly. Even
    then, only a DNS lookup, HTTPS HEAD requests to example.com/github.com and
    bare TCP connects are made.
  - "-ExecutionPolicy Bypass" in the usage line affects only that single
    powershell.exe process; it does not change the system policy.

USAGE
  powershell -NoProfile -ExecutionPolicy Bypass -File check_sandbox.ps1
  powershell -NoProfile -ExecutionPolicy Bypass -File check_sandbox.ps1 -Network

LICENSE: MIT-0
#>
param([switch]$Network)

# Many probes legitimately fail when access is denied or a feature is absent.
# Failures are treated as "not present" instead of aborting the whole report.
$ErrorActionPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
function Section($name) { Write-Output ""; Write-Output "== $name ==" }
function KV($k, $v) { Write-Output ("{0,-30} {1}" -f ("$k" + ':'), $v) }
function YesNo($b) { if ($b) { 'yes' } else { 'no' } }

# Current access token: user SID plus all group SIDs. Used to evaluate ACLs.
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
$mySids = @($identity.User.Value) + @($identity.Groups | ForEach-Object { $_.Value })

# Estimate whether the current token may create files in a directory, by
# reading its ACL and matching allow/deny entries against our SIDs.
# Nothing is written. Approximate: ignores integrity labels, AppContainer
# capabilities and some inheritance subtleties, so "likely" is not a guarantee.
function Test-WriteAccess($path) {
    $acl = Get-Acl -LiteralPath $path
    if (-not $acl) { return 'unknown' }
    $writeMask = [System.Security.AccessControl.FileSystemRights]::CreateFiles -bor `
                 [System.Security.AccessControl.FileSystemRights]::WriteData
    $allow = $false; $deny = $false
    foreach ($rule in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        if ($mySids -notcontains $rule.IdentityReference.Value) { continue }
        if (($rule.FileSystemRights -band $writeMask) -eq 0) { continue }
        if ($rule.AccessControlType -eq 'Deny') { $deny = $true } else { $allow = $true }
    }
    if ($deny) { return 'no (deny ACE)' }
    if ($allow) { return 'likely' }
    return 'no'
}

# Would reading be allowed? For files: open a read-only handle (sharing
# ReadWrite so other programs are not blocked) and close it immediately.
# No bytes are read. For directories: list entry names only.
function Test-ReadAccess($path) {
    if (Test-Path -LiteralPath $path -PathType Container) {
        try { $null = [System.IO.Directory]::GetFileSystemEntries($path); return $true } catch { return $false }
    }
    try {
        $fs = [System.IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
        $fs.Close(); return $true
    } catch { return $false }
}

# ---------------------------------------------------------------------------
# System: basic facts used to interpret everything else.
# ---------------------------------------------------------------------------
Section 'System'
$os = Get-CimInstance Win32_OperatingSystem
KV 'os' "$($os.Caption) $($os.Version) (build $($os.BuildNumber))"
KV 'arch' $env:PROCESSOR_ARCHITECTURE
KV 'hostname' $env:COMPUTERNAME
KV 'powershell' "$($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
KV 'cwd' (Get-Location).Path

# ---------------------------------------------------------------------------
# Identity & privileges: admin rights / elevation are the biggest factor in
# how much damage is possible.
# ---------------------------------------------------------------------------
Section 'Identity & privileges'
KV 'user' "$($identity.Name) ($($identity.User.Value))"
# True only if this process is actually elevated ("Run as administrator").
KV 'is_admin_elevated' (YesNo $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))
# S-1-5-32-544 = BUILTIN\Administrators. Under UAC an admin's normal token
# carries it as "Group used for deny only": not admin now, but could elevate.
$inAdminGroup = $mySids -contains 'S-1-5-32-544'
$whoamiGroups = whoami /groups /fo csv 2>$null | ConvertFrom-Csv
$adminDenyOnly = $whoamiGroups | Where-Object { $_.SID -eq 'S-1-5-32-544' }
if ($adminDenyOnly) { KV 'admin_group_member' "yes (attributes: $($adminDenyOnly.Attributes))" }
else { KV 'admin_group_member' (YesNo $inAdminGroup) }
# Mandatory integrity level (S-1-16-*): Low/Untrusted = sandboxed,
# Medium = normal user, High = elevated admin, System = SYSTEM.
$label = $whoamiGroups | Where-Object { $_.SID -like 'S-1-16-*' } | Select-Object -First 1
KV 'integrity_level' $(if ($label) { $label.'Group Name' } else { 'unknown' })
# AppContainer tokens carry package / capability SIDs (S-1-15-2-*, S-1-15-3-*).
$isAppContainer = [bool]($mySids | Where-Object { $_ -like 'S-1-15-2-*' -or $_ -like 'S-1-15-3-*' })
KV 'appcontainer_token' (YesNo $isAppContainer)
# UAC settings (registry READ only). ConsentPromptBehaviorAdmin=0 means
# admins are elevated silently, which makes "not elevated" meaningless.
$uac = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
KV 'uac_EnableLUA' $uac.EnableLUA
KV 'uac_ConsentPromptBehaviorAdmin' "$($uac.ConsentPromptBehaviorAdmin) (0=elevate without prompt)"
# Token privileges that enable tampering with other processes or files
# regardless of ACLs. Only listed; none is enabled or used.
$privs = whoami /priv /fo csv 2>$null | ConvertFrom-Csv
$dangerPrivs = $privs | Where-Object { $_.'Privilege Name' -match 'SeDebug|SeImpersonate|SeBackup|SeRestore|SeTakeOwnership|SeLoadDriver|SeTcb|SeAssignPrimaryToken' }
KV 'notable_privileges' $(if ($dangerPrivs) { ($dangerPrivs | ForEach-Object { "$($_.'Privilege Name')[$($_.State)]" }) -join ' ' } else { 'none' })

# ---------------------------------------------------------------------------
# Container / VM detection: several weak signals, combined by the reader.
# ---------------------------------------------------------------------------
Section 'Container / VM detection'
# Manufacturer/Model reveal VMs ("Microsoft Corporation / Virtual Machine",
# "VMware", "QEMU", ...). HypervisorPresent is also True on physical hosts
# with Hyper-V / VBS enabled, so it is not conclusive on its own.
$cs = Get-CimInstance Win32_ComputerSystem
KV 'manufacturer' $cs.Manufacturer
KV 'model' $cs.Model
KV 'hypervisor_present' $cs.HypervisorPresent
# Windows Sandbox always runs as the built-in WDAGUtilityAccount.
if ($env:USERNAME -eq 'WDAGUtilityAccount') { KV 'windows_sandbox' 'YES (WDAGUtilityAccount)' }
# The Container Execution Agent service exists only inside Windows containers.
if (Get-Service cexecsvc) { KV 'windows_container' 'YES (cexecsvc service present)' }
$ctype = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control').ContainerType
if ($ctype) { KV 'ContainerType' $ctype }
# Many visible processes = sharing the full desktop session with the user.
KV 'visible_processes' (@(Get-Process).Count)
# Process owners can only be listed when elevated; otherwise say "unknown"
# rather than a misleading "no".
$withOwner = @(Get-Process -IncludeUserName 2>$null)
if ($withOwner.Count -gt 0) {
    KV 'other_users_processes_visible' (YesNo (@($withOwner | Where-Object { $_.UserName -and $_.UserName -ne $identity.Name }).Count -gt 0))
} else {
    KV 'other_users_processes_visible' 'unknown (owner lookup needs elevation)'
}
# Environment variable NAMES hinting at a sandbox / CI / cloud dev box.
# Values are never printed.
$sandboxVars = Get-ChildItem env: | Where-Object { $_.Name -match 'sandbox|container|codespace|devcontainer|^CI$|github_actions|e2b|daytona' } | ForEach-Object { $_.Name }
KV 'sandbox_related_env_names' $(if ($sandboxVars) { $sandboxVars -join ' ' } else { 'none' })

# ---------------------------------------------------------------------------
# Script restrictions: OS-level controls that limit what code can run.
# All of these are read-only status queries.
# ---------------------------------------------------------------------------
Section 'Script restrictions'
# ConstrainedLanguage indicates WDAC/AppLocker enforcement; FullLanguage is normal.
KV 'language_mode' $ExecutionContext.SessionState.LanguageMode
KV 'execution_policy' (Get-ExecutionPolicy)
# Presence of AppLocker policy key (existence check only).
$applocker = Get-ChildItem 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2'
KV 'applocker_policy' (YesNo ([bool]$applocker))
# Microsoft Defender status (read-only; does not trigger a scan).
$mp = Get-MpComputerStatus
if ($mp) {
    KV 'defender_realtime' $mp.RealTimeProtectionEnabled
    KV 'defender_tamper_protected' $mp.IsTamperProtected
}

# ---------------------------------------------------------------------------
# Filesystem: where could the agent write (and therefore delete or tamper)?
# ---------------------------------------------------------------------------
Section 'Filesystem'
# System locations should be "no" for a non-elevated user; the profile, the
# project and %TEMP% are normally writable.
$paths = @("$env:SystemDrive\", $env:windir, "$env:windir\System32", $env:ProgramFiles, $env:USERPROFILE, (Get-Location).Path, $env:TEMP)
foreach ($p in $paths) {
    if ($p -and (Test-Path -LiteralPath $p)) { KV "writable:$p" (Test-WriteAccess $p) }
}
# Every visible drive is potentially in reach (including USB / extra disks).
Get-PSDrive -PSProvider FileSystem | ForEach-Object {
    KV "drive:$($_.Name)" ("{0:N1} GB free, root={1}" -f ($_.Free / 1GB), $_.Root)
}
# Mapped network drives extend the blast radius to other machines / shares.
$netDrives = Get-CimInstance Win32_MappedLogicalDisk
foreach ($d in $netDrives) { KV "network_drive:$($d.DeviceID)" $d.ProviderName }

# ---------------------------------------------------------------------------
# Credentials reachable: well-known locations of keys, tokens and password
# stores. IMPORTANT: contents are never read (see Test-ReadAccess above).
# Browser "Login Data" and the SAM hive are included because their
# readability is a key risk signal: browser passwords are DPAPI-protected but
# decryptable by any process of the same user; SAM must never be readable.
# ---------------------------------------------------------------------------
Section 'Credentials reachable (existence/readability only, contents NOT read)'
$h = $env:USERPROFILE
$cred = @(
    "$h\.ssh", "$h\.ssh\id_rsa", "$h\.ssh\id_ed25519",
    "$h\.aws\credentials", "$h\.azure", "$env:APPDATA\gcloud",
    "$h\.kube\config", "$h\.docker\config.json", "$env:APPDATA\GitHub CLI\hosts.yml",
    "$h\.git-credentials", "$h\.netrc", "$h\_netrc", "$h\.npmrc", "$h\.pypirc", "$env:APPDATA\gnupg",
    "$h\.claude.json", "$h\.claude\.credentials.json", "$h\.codex\auth.json",
    "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data",
    "$env:APPDATA\Mozilla\Firefox\Profiles",
    "$env:windir\System32\config\SAM"
)
foreach ($p in $cred) {
    if (Test-Path -LiteralPath $p) { KV $p "exists readable=$(YesNo (Test-ReadAccess $p))" }
}
# .env files in the project (current dir + one level down); names only.
$envFiles = Get-ChildItem -Path . -Filter '.env*' -File -Force -Depth 1 | Select-Object -First 10 | ForEach-Object { $_.FullName }
KV 'project_.env_files' $(if ($envFiles) { $envFiles -join ' ' } else { 'none' })
# Names of secret-looking environment variables. Only .Name is selected,
# so values never reach the output.
$secretEnv = Get-ChildItem env: | Where-Object { $_.Name -match 'token|secret|passw|api_?key|access_?key|private|credential|auth' } | ForEach-Object { $_.Name }
KV 'secret_like_env_names' $(if ($secretEnv) { $secretEnv -join ' ' } else { 'none' })
# Windows Credential Manager: `cmdkey /list` shows target names (never
# passwords). Even the names are withheld here; only the count is reported.
$cmdkey = cmdkey /list 2>$null | Select-String 'Target:'
KV 'credential_manager_entries' (@($cmdkey).Count)

# ---------------------------------------------------------------------------
# Dangerous interfaces: things that widen the blast radius beyond this user
# session. Existence checks only; nothing is connected to.
# ---------------------------------------------------------------------------
Section 'Dangerous interfaces'
# Enumerating \\.\pipe\ lists pipe NAMES without opening any of them.
# docker_engine access usually means admin-equivalent control of the host;
# openssh-ssh-agent means loaded SSH keys can be used for signing.
$pipes = [System.IO.Directory]::GetFiles('\\.\pipe\')
foreach ($name in 'docker_engine', 'dockerDesktopLinuxEngine', 'podman-machine-default', 'openssh-ssh-agent') {
    if ($pipes | Where-Object { $_ -like "*\$name" }) { KV "pipe:$name" 'exists' }
}
if ($env:DOCKER_HOST) { KV 'DOCKER_HOST' 'set' }
# Installed WSL distributions: another environment the agent can enter.
# `wsl -l -q` only lists names; it does not start a distribution.
if (Get-Command wsl.exe) {
    $distros = (wsl.exe -l -q 2>$null) -replace "`0", '' | Where-Object { $_.Trim() }
    KV 'wsl_distros' $(if ($distros) { $distros -join ' ' } else { 'none' })
}
# Remote-access services (status read only): open entry points to this machine.
foreach ($svc in 'sshd', 'WinRM', 'TermService') {
    $s = Get-Service $svc
    if ($s) { KV "service:$svc" $s.Status }
}

# ---------------------------------------------------------------------------
# Network (local view): configuration only, no packets are sent.
# ---------------------------------------------------------------------------
Section 'Network (local view)'
Get-NetIPConfiguration | ForEach-Object {
    KV "if:$($_.InterfaceAlias)" "$($_.IPv4Address.IPAddress) gw=$($_.IPv4DefaultGateway.NextHop)"
}
# Proxy variable NAMES only: proxy URLs can embed user:password.
$proxyVars = Get-ChildItem env: | Where-Object { $_.Name -match '^(http|https|all|no)_proxy$' } | ForEach-Object { $_.Name }
KV 'proxy_env_names' $(if ($proxyVars) { $proxyVars -join ' ' } else { 'none' })
# `netsh winhttp show proxy` is a read-only query; only direct/configured is
# reported, not the proxy address.
$winhttp = (netsh winhttp show proxy 2>$null | Out-String)
KV 'winhttp_proxy' $(if ($winhttp -match 'Direct access') { 'direct' } elseif ($winhttp) { 'configured' } else { 'unknown' })
# Firewall profile state; outbound "NotConfigured" means the default (allow).
$fw = Get-NetFirewallProfile
foreach ($f in $fw) { KV "firewall:$($f.Name)" "enabled=$($f.Enabled) outbound_default=$($f.DefaultOutboundAction)" }

# TCP reachability test: connect with a 3-second timeout, then close.
# No data is sent over the connection.
function Test-Tcp($hostName, $port) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $ar = $c.BeginConnect($hostName, $port, $null, $null)
        if ($ar.AsyncWaitHandle.WaitOne(3000) -and $c.Connected) { 'reachable' } else { 'blocked' }
    } catch { 'blocked' } finally { $c.Close() }
}

# ---------------------------------------------------------------------------
# Network egress (opt-in with -Network): can data leave this machine?
# Contacts external hosts, so it is off by default.
# ---------------------------------------------------------------------------
if ($Network) {
    Section 'Network egress (opt-in)'
    # DNS resolution of a reserved, harmless domain (example.com, RFC 2606).
    KV 'dns:example.com' $(if ([System.Net.Dns]::GetHostAddresses('example.com')) { 'resolves' } else { 'fails' })
    # HTTPS HEAD request: only the status code is printed. github.com shows
    # whether an allowlist permits common developer hosts.
    foreach ($hostName in 'example.com', 'github.com') {
        try {
            $r = Invoke-WebRequest -Uri "https://$hostName" -Method Head -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            KV "https:$hostName" $r.StatusCode
        } catch { KV "https:$hostName" 'blocked' }
    }
    # Raw TCP to a public IP (Cloudflare DNS) bypasses DNS-based filtering.
    KV 'tcp:1.1.1.1:443' (Test-Tcp '1.1.1.1' 443)
    # Cloud instance metadata service (AWS/GCP/Azure). If reachable, temporary
    # cloud credentials may be obtainable - a high-severity finding. This is a
    # TCP connect ONLY; no HTTP request is sent and no credentials are fetched.
    KV 'tcp:169.254.169.254:80' "$(Test-Tcp '169.254.169.254' 80) (cloud metadata)"
} else {
    Section 'Network egress'
    Write-Output 'skipped (run with -Network to test outbound connectivity)'
}

Write-Output ''
Write-Output 'done. (read-only probe; no files were written)'
