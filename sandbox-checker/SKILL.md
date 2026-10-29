---
name: sandbox-checker
description: Inspect, without changing anything, how isolated the current coding-agent environment is (container / VM / OS sandbox / plain host) and what an agent running here could reach or damage — privileges, writable paths, readable credentials, secret env vars, network egress, Docker socket, cloud metadata, host processes. Use this whenever the user asks things like "am I in a sandbox?", "how isolated is this agent?", "what could go wrong if the agent runs rm -rf / leaks secrets?", "is this a container?", "check the blast radius", "サンドボックスの中？", "隔離レベルを調べて", "このエージェントは何ができてしまう？", "危険性を確認して", or before running untrusted code / enabling auto-approve / YOLO mode, even if they don't say the word "sandbox".
license: MIT-0
---

# Sandbox Checker

コーディングエージェントが動いている環境が **どの程度隔離されているか** と **そこから何に手が届いてしまうか（＝事故や悪用時の被害範囲）** を、**非破壊的に** 調べてレポートするスキル。

## 大原則: 調べるだけで、何も変えない

このスキルの価値は「安心して実行できる」ことにある。検査そのものが事故を起こしたら本末転倒なので、次を守る。

- **書き込まない**: ファイル作成・削除・権限変更・パッケージ導入・設定変更はしない。書き込み可否は `test -w` / ACL 参照で判定する（実際に書いて試さない）。
- **秘密を表示しない**: 認証情報ファイルや環境変数は「存在する / 読める」かと **名前** だけ報告し、**中身や値は絶対に出力しない**。レポートは他人に共有されうるし、ログにも残るため。
- **権限昇格を試さない**: `sudo -n true` のような「パスワードなしで通るか」の確認だけ。脆弱性を突く・コンテナ脱出を試す・保護を回避するといった能動的な攻撃はしない。
- **外部通信は同意を得てから**: ネットワーク到達性の確認は外部ホストへ接続する行為なので、既定では行わない。ユーザーが egress（外向き通信）も知りたいと言っている、または明示的に許可した場合のみ `--network` を付ける。迷ったら一言確認する。
- **重い処理をしない**: ディスク全体の find、ポートスキャン、大量のプロセス生成などはしない。

バンドルされたスクリプトはこの原則に沿って書かれている。追加で手動確認をする場合も同じ基準で判断すること。

## 手順

### 1. OS を判定してスクリプトを実行する

スクリプトはこの SKILL.md と同じディレクトリの `scripts/` にある。

- **Linux / macOS / WSL / Git Bash 以外の POSIX 環境**:
  ```bash
  bash <skill-dir>/scripts/check_sandbox.sh            # ネットワーク検査なし
  bash <skill-dir>/scripts/check_sandbox.sh --network  # 同意がある場合
  ```
- **Windows (PowerShell)**:
  ```powershell
  powershell -NoProfile -ExecutionPolicy Bypass -File <skill-dir>\scripts\check_sandbox.ps1
  powershell -NoProfile -ExecutionPolicy Bypass -File <skill-dir>\scripts\check_sandbox.ps1 -Network
  ```
  `-ExecutionPolicy Bypass` はこのプロセスだけに効き、システム設定は変えない。

Windows 上の Git Bash で bash 版を動かすと Linux 向けの項目がほぼ空振りするので、Windows では PowerShell 版を使う。

スクリプトの実行自体がブロックされた場合（シェル禁止、スクリプト実行不可など）は、それ自体が「強く制限された環境」という重要な情報。その事実を記録し、使えるツール（ファイル読み取りなど）で `/proc/self/status`、`/proc/1/cgroup`、`/.dockerenv` 等を個別に確認する。

### 2. エージェント側の制御も確認する

OS レベルの隔離とは別に、エージェント自身の権限設定も被害範囲を左右する。分かる範囲で確認する（読み取りのみ）。

- Claude Code なら `.claude/settings.json`、`.claude/settings.local.json`、`~/.claude/settings.json` の `permissions`（allow/deny）や `sandbox` 設定
- 自分（エージェント）が使えるツールと、承認なしで実行できる操作の範囲（自己申告でよい）
- 他のエージェント（Codex、Cursor、Aider など）の場合はその設定ファイルや環境変数名

### 3. 結果を解釈する

出力の各項目の意味と、何が危険信号かは `references/interpretation.md` にまとめてある。判断に迷う項目があれば読むこと。特に:

- コンテナ判定の根拠（cgroup、`/.dockerenv`、PID 1 のプロセス名、mount namespace 等）は単独では誤判定しうるので、複数の兆候を組み合わせて結論を出す。
- `test -w` は Landlock / seccomp / macOS Seatbelt などの一部のサンドボックスでは実際の可否と食い違うことがある。「書き込めそう」は「書き込める可能性が高い」と表現し、断定しない。

### 4. レポートを書く

ユーザーの言語で、次の構成で報告する。

```markdown
# サンドボックス診断レポート

## 結論
隔離レベル: <L0〜L4> — <一言で>
（例: L1 — ホスト上で一般ユーザー権限のまま直接動作。サンドボックスなし）

## 環境の概要
- OS / 実行形態（ホスト・コンテナ・VM・WSL など）と判定根拠
- 実行ユーザーと権限（root/管理者か、sudo 可否）
- 有効なサンドボックス機構（seccomp、AppArmor、Seatbelt、AppContainer、bubblewrap 等）

## 手が届くもの（リスク）
重大度の高い順に。各項目に「何が起こりうるか」を 1 行で。
| 重大度 | 項目 | 観測内容 | 起こりうること |

## 守られているもの
制限が効いていると確認できた点。

## 確認できなかったこと
検査の限界（ネットワーク未検査、権限不足で読めなかった等）。

## 推奨事項
リスクを下げる具体策を 3〜5 個。
```

隔離レベルの目安:

| レベル | 状態 |
|---|---|
| L0 | ホスト上で root / 管理者として動作。何でもできる |
| L1 | ホスト上で一般ユーザーとして動作。ユーザーのファイル・認証情報に全て手が届く |
| L2 | OS サンドボックスやコンテナ内だが、ホームディレクトリ・認証情報・Docker ソケット等がマウント/公開されている、またはネットワークが無制限 |
| L3 | コンテナ / サンドボックスでファイル・ネットワークともに制限されている。作業ディレクトリ外への影響は限定的 |
| L4 | 専用 VM・使い捨て環境などで、ホストや個人データから強く分離されている |

レベルは目安なので、根拠とともに示す。例えばコンテナ内でも Docker ソケットが見えていればホスト root 相当になりうるので L2 以下と判断する、というように「最も弱い穴」に合わせて評価する。

## 注意

- レポートに秘密の値・トークン・パスワード・プライベートキーの中身を含めない。ファイルパスや変数名だけでよい。
- 「安全です」と言い切らない。この検査は代表的な項目を見るだけで、見落としがありうることを「確認できなかったこと」に正直に書く。
