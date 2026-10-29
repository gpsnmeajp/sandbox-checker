# sandbox-checker

[English README](README.md)

コーディングエージェント（Claude Code など）が、**自分の動いている環境がどの程度隔離されているか** と **そこから何に手が届いてしまうか** を、**何も変更せずに** 調べるための [Agent Skill](https://docs.claude.com/en/docs/agents-and-tools/agent-skills/overview) です。

「サンドボックスの中？」「このエージェントの隔離レベルを調べて」「auto-approve にしたら最悪何が起きる？」などと頼むと、エージェントが読み取り専用の検査を実行し、隔離レベル（L0〜L4）付きのリスクレポートを作成します。

## なぜ必要か

信頼できないコードを実行させる前や、コマンドの自動承認（いわゆる YOLO モード）を有効にする前に、被害範囲を知っておきたいものです。

- コンテナ？ VM？ OS のサンドボックス？ それとも普段使いの PC そのもの？
- root / 管理者で動いている？ パスワードなしで `sudo` できる？
- どの SSH 鍵・クラウド認証情報・トークンが読めてしまう？
- インターネットに出られる（＝それらを外に送れる）？ クラウドのメタデータサービスには？
- Docker ソケットが見えている（＝ホストの root 相当）？

## 安全性: 読み取り専用の設計

セキュリティの自己診断は、攻撃者が見るのと同じ場所を見ることになります。そのためスクリプトには詳細なコメントを付け、怪しく見えうる検査ごとに「何をして、何をしないか」を説明しています。

| 保証 | 方法 |
|---|---|
| ファイルを作成・変更・削除しない | 書き込み可否は `test -w`（POSIX）または ACL の読み取り（Windows）で判定 |
| 認証情報の中身を読まない | 存在と権限のみ確認。Windows では読み取りハンドルを開いてすぐ閉じるだけで、1 バイトも読まない |
| 秘密の値を表示しない | 環境変数は **名前** のみ。資格情報マネージャーは **件数** のみ |
| 権限昇格・脱出を試みない | 権限に関する唯一の確認は `sudo -n true`（対話なし・何もしないコマンド） |
| 既定ではネットワーク通信しない | 外向き通信の検査は `--network` / `-Network` 指定時のみ。DNS 解決、example.com と github.com への HTTPS HEAD、TCP 接続確認だけ（メタデータサービスには HTTP リクエストを送らない） |
| 重い処理をしない | ディスク全体の走査、ポートスキャン、大量のプロセス生成はしない |

スキルの指示書（`SKILL.md`）も、エージェントに同じルールを課しています。ネットワーク検査の前には確認を取り、レポートに秘密の値を書かせません。

## インストール

### Claude Code

スキルのフォルダを、個人用またはプロジェクト用のスキルディレクトリにコピーします。

```bash
# 個人用（全プロジェクト共通）
cp -r sandbox-checker ~/.claude/skills/

# プロジェクト用
cp -r sandbox-checker .claude/skills/
```

Windows（PowerShell）の場合:

```powershell
Copy-Item -Recurse sandbox-checker "$env:USERPROFILE\.claude\skills\"
```

### Claude.ai / その他スキル対応エージェント

`sandbox-checker/` フォルダ（直下に `SKILL.md` がある状態）を zip にして、カスタムスキルとしてアップロードします。

## 使い方

エージェントに頼むだけです。

```
この環境ってどのくらい隔離されてる？知らないコードを動かしたら最悪何が起きる？
```

```
コンテナの中かどうか調べて。ネットワークにも繋いで確認していいよ。
```

スクリプトを直接実行することもできます。

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

（`-ExecutionPolicy Bypass` はそのプロセスにだけ効き、システムの設定は変えません。）

### 出力例（抜粋）

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

エージェントはこれを元に、結論と隔離レベル、環境の概要、重大度順のリスク、守られている点、確認できなかった点、推奨事項をまとめたレポートを書きます。

## 隔離レベル

| レベル | 意味 |
|---|---|
| L0 | ホスト上で root / 管理者として動作 |
| L1 | ホスト上で一般ユーザーとして動作。そのユーザーのファイル・認証情報すべてに手が届く |
| L2 | コンテナ / サンドボックス内だが、ホームディレクトリ・認証情報・Docker ソケットが見えている、またはネットワークが無制限 |
| L3 | ファイル・ネットワークともに制限されたコンテナ / サンドボックス |
| L4 | 専用・使い捨ての VM などで、ホストや個人データから強く分離されている |

レベルは **最も弱い穴** で決まります。書き込み可能な Docker ソケットがあるコンテナは、L2 より上にはなりません。

## 検査項目

- **システム**: OS、カーネル、WSL
- **権限**: root / 管理者、パスワードなし sudo、Linux ケーパビリティ、seccomp、NoNewPrivs、user namespace、Windows の整合性レベル、UAC、AppContainer、危険なトークン特権
- **コンテナ / VM 判定**: `/.dockerenv`、cgroup、PID 1、namespace、DMI、ハイパーバイザフラグ、Kubernetes、Windows Sandbox / コンテナ
- **サンドボックス機構**: AppArmor / SELinux / Landlock、bubblewrap など、macOS Seatbelt の兆候、PowerShell の言語モード、AppLocker、Defender
- **ファイルシステム**: システム・ホーム・プロジェクト・一時ディレクトリへの書き込み可否、マウント、ネットワークドライブ
- **認証情報**: SSH、AWS / GCP / Azure、kube、Docker、GitHub CLI、git、npm / PyPI、GnuPG、Claude / Codex の認証ファイル、シェル履歴、ブラウザのパスワード保存領域、`.env` ファイル、秘密らしい環境変数名
- **危険なインターフェース**: Docker / containerd / Podman のソケットやパイプ、SSH エージェント、生デバイス、sysrq、cgroup fs、WSL ディストリビューション、リモートアクセスサービス
- **リソース制限**: ulimit、cgroup のメモリ / CPU / プロセス数
- **ネットワーク**: インターフェース、DNS、プロキシ、ファイアウォール。オプションで外向き通信とメタデータサービスへの到達性

各項目の解釈は [`sandbox-checker/references/interpretation.md`](sandbox-checker/references/interpretation.md) を参照してください。

## 制限事項

- 代表的な兆候を見るヒューリスティックな検査であり、**安全を保証するものではありません**。問題が見つからなくても、安全だとは言い切れません。
- `test -w` や ACL による推定は、Landlock・seccomp・Seatbelt・AppContainer による実際の制限と食い違うことがあります。
- コンテナ判定の手がかりは、偽装・隠蔽されることがあります。
- Windows では PowerShell 版を使ってください。Git Bash で bash 版を動かすと権限の判定が不正確になります（警告が表示されます）。
- bash 版は Linux と macOS 向けに作っています。誤判定するディストリビューションがあれば報告してください。

## 構成

```
sandbox-checker/
├── SKILL.md                      # スキルの指示書（手順・安全ルール・レポート形式）
├── scripts/
│   ├── check_sandbox.sh          # Linux / macOS / WSL 用の検査スクリプト
│   └── check_sandbox.ps1         # Windows 用の検査スクリプト（PowerShell 5.1 以上）
├── references/
│   └── interpretation.md         # 各項目の解釈と重大度の基準
└── evals/
    └── evals.json                # テスト用プロンプト（skill-creator 形式）
```

Anthropic の [skill-creator](https://github.com/anthropics/skills) を使って作成しました。

## ライセンス

[MIT-0](LICENSE)（MIT No Attribution）
