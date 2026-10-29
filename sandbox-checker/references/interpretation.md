# 検査結果の解釈ガイド

スクリプト出力の各項目が何を意味し、どう評価すべきかをまとめる。判断は単一の兆候ではなく、複数の兆候の組み合わせで行う。

## 目次
1. 実行形態の判定（ホスト / コンテナ / VM / WSL）
2. 権限
3. サンドボックス機構
4. ファイルシステム
5. 認証情報・秘密
6. 危険なインターフェース
7. ネットワーク
8. 重大度の付け方

---

## 1. 実行形態の判定

| 兆候 | 示唆 | 注意 |
|---|---|---|
| `/.dockerenv` がある | Docker コンテナ | 消されていることもある |
| `/run/.containerenv` | Podman コンテナ | |
| `pid1_cgroup` に `docker`, `kubepods`, `containerd`, `lxc` | コンテナ | cgroup v2 では `0::/` だけになり判別できないことが多い |
| `pid1_comm` が `systemd`/`init`/`launchd` 以外（`bash`, `node`, `sleep`, `tini`, `dumb-init` 等） | コンテナ（PID 1 がアプリ） | |
| `visible_processes` が非常に少ない（〜数十） | PID namespace で分離されている | |
| `systemd-detect-virt -c` が `none` 以外 | コンテナ | |
| `dmi_product` / `manufacturer` が `VirtualBox`, `VMware`, `KVM`, `QEMU`, `Virtual Machine`(Hyper-V), `Google Compute Engine`, `Amazon EC2` 等 | VM | VM 内でもユーザー個人の VM なら隔離は弱い |
| `cpu_hypervisor_flag` / `hypervisor_present` / `hv_vmm_present=1` | 何らかのハイパーバイザ上 | Windows は VBS/Hyper-V 有効だとホストでも True になる |
| `wsl: yes` | WSL 上 | WSL2 は `/mnt/c` 経由で Windows 側のファイルに通常フルアクセスできる。隔離とはみなさない |
| `KUBERNETES_SERVICE_HOST`, `k8s_serviceaccount` | Kubernetes Pod | サービスアカウントトークンでクラスタ API を叩ける可能性 |
| `CODESPACES`, `GITPOD_*`, `REMOTE_CONTAINERS` 等の env 名 | クラウド開発環境 / devcontainer | |
| `windows_sandbox: YES` | Windows Sandbox（使い捨て VM） | 強い隔離 |
| `appcontainer_token: yes` | AppContainer 内 | ファイル・ネットワークがケーパビリティで制限される |

**WSL / Git Bash の注意**: Windows 上の Git Bash で bash 版を動かすと、ほぼホスト直実行。PowerShell 版の結果を優先する。

## 2. 権限

- `is_root: YES` / `is_admin_elevated: yes` → それだけで重大度「高」。コンテナ内 root でも、ケーパビリティやマウント次第でホストに影響しうる。
- `sudo_without_password: yes` → 実質 root と同等。重大度「高」。
- `CapEff` が `000001ffffffffff` や `0000003fffffffff` のように全ビット立っている → privileged コンテナの可能性。`CAP_SYS_ADMIN`(bit 21)、`CAP_SYS_PTRACE`、`CAP_SYS_MODULE`、`CAP_NET_ADMIN`、`CAP_DAC_READ_SEARCH` は特に危険。一般ユーザーなら通常 `0000000000000000`。
- `CapBnd` が狭い → 仮に root でも取れる権限が限られている（良い兆候）。
- `NoNewPrivs: 1` → setuid バイナリでの昇格ができない（良い兆候）。
- `uid_map` が `0 1000 1` のような形 → user namespace で、コンテナ内 root はホストでは一般ユーザー（良い兆候）。`0 0 4294967295` はホストと同じ UID 空間。
- Windows: `integrity_level` が `High` は管理者昇格済み。`Medium` は通常ユーザー。`Low` / `Untrusted` や AppContainer は強く制限されている。`admin_group_member` で "Group used for deny only" なら UAC で制限された管理者（昇格プロンプトを経れば管理者になれる）。`uac_ConsentPromptBehaviorAdmin=0` だとプロンプトなしで昇格でき危険。
- `notable_privileges` に `SeDebugPrivilege`, `SeImpersonatePrivilege` 等が Enabled → 他プロセスへの干渉や昇格の足がかりになりうる。

## 3. サンドボックス機構

- `Seccomp: 2` → システムコールフィルタあり（Docker 既定や bubblewrap など）。`0` ならなし。
- `lsm_label` が `docker-default (enforce)` など → AppArmor プロファイル適用中。`unconfined` は無効。
- `selinux: Enforcing` → SELinux 有効。
- `tool:bwrap` などが「インストール済み」なのは使える可能性を示すだけで、今その中にいる証拠ではない。今いるかどうかは mount namespace、Seccomp、見えるプロセス数、書き込み可否で判断する。
- macOS: Seatbelt (`sandbox-exec`) 内で動いていると、`$HOME` 配下の多くが読めない／書けない、`/Library/Keychains` が読めない、などの形で現れる。Claude Code の bash サンドボックスは macOS では Seatbelt、Linux では bubblewrap を使う。
- Windows: `language_mode: ConstrainedLanguage` は WDAC/AppLocker によるスクリプト制限。`FullLanguage` が通常。

## 4. ファイルシステム

- `writable:/`、`/etc`、`/usr`、`C:\Windows\System32` が yes/likely → システムを壊せる。重大度「高」。
- `writable:$HOME` が yes → ドットファイル（`.bashrc`、`.ssh/authorized_keys`、`.gitconfig`）を書き換えて永続化・乗っ取りが可能。重大度「中〜高」。
- 作業ディレクトリのみ書き込み可、他は読み取り専用 → よく設計されたサンドボックスの典型（良い兆候）。
- マウント一覧に `/home`, `/Users`, `/mnt/c`, `/var/run/docker.sock`, `/` などホスト由来のパスが bind されていれば、その範囲はホストと共有されている。
- `root_mount` が `overlay` → コンテナの典型。`ro` が付いていれば読み取り専用ルート。
- ネットワークドライブ / 共有フォルダが見えている → 被害が他マシンや組織の共有に及ぶ可能性。

`test -w` / ACL 推定の限界: Landlock・seccomp・Seatbelt・AppContainer は「権限ビット上は書けるが実際は拒否」することがある。また読み取り専用 mount は `test -w` で正しく no になる。断定せず「可能性が高い」と表現する。

## 5. 認証情報・秘密

存在して読めるファイルはすべて、エージェントが読んで外部へ送れる（ネットワーク egress がある場合）情報。

| 対象 | 漏れると |
|---|---|
| `~/.ssh/id_*` | サーバー・GitHub へのなりすまし |
| `SSH_AUTH_SOCK` | 鍵ファイルが読めなくても、エージェント経由で署名に使える |
| `~/.aws/credentials`, gcloud, `.azure`, `~/.kube/config` | クラウド資源の操作・課金・データ流出 |
| `~/.docker/config.json`, `.npmrc`, `.pypirc` | レジストリへの不正 push（サプライチェーン被害） |
| `gh/hosts.yml`, `.git-credentials`, `.netrc` | リポジトリへの書き込み |
| `.claude/.credentials.json`, `.codex/auth.json` | AI サービスのアカウント悪用 |
| シェル履歴 | 過去にコマンドラインで打った秘密 |
| ブラウザの `Login Data` | 保存パスワード（Windows では DPAPI で同ユーザーなら復号可能） |
| `.env` ファイル | API キー等 |
| `secret_like_env_names` | 環境変数はプロセスから常に読める。名前から重要度を推測する |

認証情報が読める ＋ 外向き通信が自由 の組み合わせが最も危険（流出経路が揃っている）。

## 6. 危険なインターフェース

- **Docker / containerd / podman ソケットが書き込み可** → `docker run -v /:/host --privileged` でホスト root 相当。コンテナ内でもこれがあれば隔離は無意味。重大度「高」。
- Windows の `pipe:docker_engine` も同様。
- `/dev/kvm` 書き込み可 → VM を起動できる（それ自体は低リスクだが隔離境界の手がかり）。
- `/dev/mem`, ブロックデバイス (`/dev/sda` 等) 書き込み可 → ディスク直接破壊が可能。重大度「高」。
- `/proc/sysrq-trigger` 書き込み可 → ホストの再起動等。privileged コンテナの兆候。
- `cgroup_fs_writable: yes` → 既知のコンテナ脱出手法の前提条件になりうる。
- `wsl_distros` あり → Windows 側から Linux 環境に、あるいはその逆に移動できる。
- `service:sshd`/`WinRM` Running → リモートからの入口が開いている（エージェントの隔離とは直接関係ないが攻撃面）。

## 7. ネットワーク

- `--network` なしの場合は「未検査」として報告し、推測で埋めない。
- `https:example.com` が 200 系 / 3xx → 任意の外部へ通信可能。秘密の流出経路あり。
- 外部は blocked だが `github.com` だけ通る、プロキシ env がある → allowlist 型の egress 制御（良い兆候）。ただしプロキシ経由で何が許可されているかは別途確認が必要。
- `tcp:169.254.169.254:80 reachable` → クラウドのメタデータサービスに届く。IAM 一時認証情報が取得できる可能性があり重大度「高」（スクリプトは TCP 接続だけで、HTTP リクエストは送っていない）。
- インターフェースが `lo` だけ → ネットワーク namespace で遮断されている（良い兆候）。

## 8. 重大度の付け方

- **高**: システム全体・他ユーザー・クラウド資源・ホストに影響しうる（root/管理者、passwordless sudo、Docker ソケット、システム領域書き込み、メタデータ到達、クラウド認証情報が読めて egress あり）
- **中**: ユーザーのデータ・アカウントに影響しうる（ホーム書き込み、SSH 鍵/トークン読み取り、egress 無制限）
- **低**: 影響が作業ディレクトリ内や一時的な範囲にとどまる、または悪用に追加の条件が必要

総合の隔離レベルは「最も弱い穴」で決める。良い兆候がいくつあっても、Docker ソケットひとつでホスト root 相当になる。
