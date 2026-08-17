# seki — Claude Code 向けネットワーク関所

## 概要

Claude Code の子プロセスが発する全アウトバウンド通信を OS レベルで監視し、
ドメイン単位の許可リストに基づいて制御するツール。

### 解く問題

Claude Code の現行パーミッションモデルは **行為ベース**（ファイル書き込み、コマンド実行）だが、
本当のリスクは **通信先ベース**（prompt injection 等で機微情報がどこに流出するか）にある。

- hooks で Bash コマンドの文字列をパースしても、難読化一発で突破される
- `python -c "..."` 内の `urllib` や、コンパイル済みバイナリの通信は捕捉できない
- ローカルファイルの破壊はリカバリ可能だが、情報の流出は不可逆

### 2レイヤーモデル

seki は 2 つの制御レイヤーを統合する:

| レイヤー | 方式 | デフォルト | 守るもの |
|----------|------|------------|----------|
| ネットワーク監視 | **ホワイトリスト** (DNS+SNI) | deny | 「どこに出るか」— 未知の通信先を遮断 |
| コマンド承認 | **ブラックリスト** (hook) | allow | 「何をするか」— 既知の危険操作を検問 |

この 2 層は対称的で、両方あって初めて完成する:
- ネットワーク層が未知の通信を止める（流出防止）
- コマンド承認層が既知の危険操作を止める（意図の検問）

ネットワーク層は全通信に網をかける必要があるが、コマンド承認は
パターンが決まっている（`git push`, `npm publish`, `curl` 等）ので網は不要。

### 既存手段との棲み分け

| 層 | 手段 | 守るもの | 限界 |
|----|------|----------|------|
| コマンド承認 | seki + hooks (PreToolUse) | 「何をするか」— push, deploy, auth | ネットワーク通信を直接制御できない |
| ネットワーク監視 | seki (DNS+SNI) | 「どこに出るか」— 全プロトコルのドメイン制御 | 操作の意図は判断できない |

### Claude Code Sandbox を使わない理由

Claude Code には bubblewrap ベースの Sandbox が組み込まれているが、seki はこれと**併用しない**。

**脅威モデルの前提**: 本当のリスクはローカルファイルの破壊ではなく情報の流出。
ファイル破壊は git で復元可能だが、情報流出は不可逆。
seki がネットワーク出口を塞いでいれば、ファイルを読まれても流出しない。

**Sandbox のコストが価値を上回る**:
- プロセス置換 (`<(cmd)`) が壊れる — Claude がよく使うパターン
- Docker, watchman 等の互換性問題
- `excludedCommands` のバグ（ネットワーク制限が漏れるケースがある）
- `dangerouslyDisableSandbox` escape hatch がデフォルト有効で穴を開ける
- HTTP/HTTPS プロキシベースなので SSH/raw TCP は制御外
- domain fronting が既知のリスクとして残る

**seki が Sandbox のネットワーク機能を上位互換する**:
- DNS 層で全プロトコル（HTTP, HTTPS, SSH, 任意の TCP）を制御
- domain fronting を DNS 制御で軽減
- escape hatch が存在しない（ネットワーク名前空間の外側から制御するため）
- ネットワークのみの分離なので、bubblewrap 由来の互換性問題が発生しない

### スコープ外

- **Docker**: Docker daemon は seki のネットワーク名前空間の外で動作するため、
  Docker 経由の通信は seki の制御外。Docker のネットワーク制御は Docker 自身の
  network policy やファイアウォールの責務とする。
- **ファイルシステム保護**: seki のスコープ外。ファイル破壊は git で復元可能であり、
  ネットワーク出口が塞がっていればファイル読み取りは無害。

## アーキテクチャ

### rootless 設計

seki は **sudo 不要** で動作する。unprivileged user namespace + slirp4netns を使い、
ユーザー権限のみで完全なネットワーク分離を実現する。

```
seki exec -- claude        (unprivileged)
    │
    ├─ fork/exec (CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS)
    │   └─ uid 0 (user ns 内) にマッピング
    │
    ├─ slirp4netns          (TAP デバイス提供、ingress ポートフォワード)
    │
    └─ socket server        (watch 用 Unix socket)
```

依存: `slirp4netns` (apt install slirp4netns)

### プロセストポロジ

```
[seki exec (parent, unprivileged)]
    │  slirp4netns → tap0 (namespace 内にネットワーク提供)
    │  socket server (watch 用)
    │
    │  fork (CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS)
    ▼
[seki __child (user+net+mount namespace)]
    │  DNS resolver (127.0.0.1:5353)
    │  TCP proxy (127.0.0.1:10200)
    │  iptables REDIRECT + SO_MARK bypass
    │  SQLite logger, rule evaluator
    │
    │  exec
    ▼
[user command, e.g. claude]
```

旧設計では DNS/TCP プロキシがホスト側で動き veth pair 経由で通信していたが、
slirp4netns 化により**全監視ロジックが namespace 内に統合**された。
redirect proxy + host proxy の 2 段構成も単一プロキシに簡素化。

### ネットワークデータパス

```
User process (namespace 内)
  → DNS query (udp/tcp :53)
  → iptables DNAT → 127.0.0.1:5353 (seki DNS resolver)
  → ルール評価 → allow: upstream 転送 / deny: NXDOMAIN 返却
  → upstream DNS は slirp4netns 経由 (10.0.2.3:53, SO_MARK=1 で DNAT bypass)

User process
  → TCP connect (e.g. 93.184.216.34:443)
  → iptables REDIRECT → 127.0.0.1:10200 (seki TCP proxy)
  → SO_ORIGINAL_DST で元宛先を取得
  → TLS ClientHello から SNI 抽出
  → ルール評価 → allow: SO_MARK=1 で実接続 (slirp4netns 経由) / deny: 接続切断
  → allow の場合、bidirectional relay
```

### iptables 構成 (namespace 内、ホスト無影響)

```bash
# SO_MARK=1 の通信は seki 自身の外部接続 → REDIRECT/DNAT をバイパス
iptables -t nat -A OUTPUT -m mark --mark 0x1 -j RETURN

# DNS: seki の DNS リゾルバにリダイレクト
iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT --to 127.0.0.1:5353
iptables -t nat -A OUTPUT -p tcp --dport 53 -j DNAT --to 127.0.0.1:5353

# TCP: loopback はバイパス、それ以外は seki プロキシにリダイレクト
iptables -t nat -A OUTPUT -p tcp -d 127.0.0.0/8 -j RETURN
iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports 10200

# UDP: seki の外部通信 (marked) と loopback (DNATed DNS) は許可、他は DROP
iptables -A OUTPUT -p udp -m mark --mark 0x1 -j ACCEPT
iptables -A OUTPUT -p udp -d 127.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -p udp -j DROP

# ICMP: 全 DROP (ICMP トンネリング防止、seki は ICMP を使わない)
iptables -A OUTPUT -p icmp -j DROP

# IPv6: loopback のみ許可、他は DROP (seki のサービスは IPv4 only)
ip6tables -A OUTPUT -m mark --mark 0x1 -j ACCEPT
ip6tables -A OUTPUT -d ::1/128 -j ACCEPT
ip6tables -A OUTPUT -j DROP
```

### ホスト安全性保証

seki が crash・SIGKILL されてもホスト環境を破壊しないことを構造的に保証する。

| リソース | 場所 | crash 時 |
|----------|------|----------|
| user namespace | カーネル | namespace 消滅で自動削除 |
| slirp4netns | ホストプロセス | exit-fd 検知で自動終了 |
| iptables REDIRECT | namespace 内 | namespace 消滅で自動削除 |
| DNS リゾルバ | namespace 内 | プロセス死で自動消滅 |
| TCP プロキシ | namespace 内 | プロセス死で自動消滅 |
| Unix socket | ファイル | stale socket は次回起動時に削除 |

**ホスト側の変更はゼロ** — iptables, sysctl, resolv.conf, veth いずれも触らない。

### 同期メカニズム

```
Parent                     slirp4netns              Child
------                     -----------              -----
fork child (CLONE_NEWUSER
  | CLONE_NEWNET | CLONE_NEWNS)
                                                    blocks on fd 3 read
start slirp4netns
  --configure -r readyFD
                           tap0 を設定
                           readyFD に書き込み
read readyFD (unblocks)
syncPipe に書き込み
                                                    syncPipe 読み取り (unblocks)
                                                    lo up, resolv.conf 差し替え
                                                    DNS/TCP proxy 起動
                                                    iptables 適用
                                                    user command 実行
...child 終了待ち...
                                                    child 終了
exitPipe close
                           終了
slirp4netns wait
done
```

## 3層の検問

ドメイン捕捉は DNS を一次手段、SNI を二次手段とする。

```
一次: DNS リゾルバ  — ドメイン捕捉 + allowlist 判定 + ECH 設定除去
二次: SNI スニッフィング — DNS を経由しない通信の検出・照合
最終: IP 直打ち → デフォルト deny
```

### 一次: DNS リゾルバ

ネットワーク名前空間内の DNS を seki が完全に掌握する。

```
子プロセス → DNS クエリ "target.example.com"
               │
               ▼
         seki 内蔵 DNS リゾルバ (127.0.0.1:5353)
         ├─ ドメインをログに記録 (← ここで捕捉完了)
         ├─ allowlist 判定 (deny なら NXDOMAIN を返す)
         ├─ HTTPS/SVCB レコードから ECH 設定を除去 (→ SNI fallback 強制) [未実装]
         └─ DoH/DoT 迂回の防止 (namespace 内で seki 以外への DNS トラフィックを遮断)
               │
               ▼
         slirp4netns DNS (10.0.2.3:53) → ホスト DNS (SO_MARK=1 で DNAT bypass)
```

### 二次: SNI スニッフィング

TLS ClientHello の `server_name` 拡張からドメインを抽出する。
DNS を経由せず IP 直打ちで TLS 接続する場合の検出に使う。

### 最終: IP 直打ち

DNS も SNI も得られない通信はデフォルト deny。
ただし正当な用途で IP 直打ちが必要なケースは CIDR allowlist で対応する。

## ルール構造

```jsonc
// ~/.config/seki/rules.json
{
  "rules": [
    // ドメインベース (DNS + SNI で判定)
    { "match": "*.github.com", "action": "allow", "tag": "git" },
    { "match": "github.com", "action": "allow", "tag": "git" },
    { "match": "registry.npmjs.org", "action": "allow", "tag": "npm" },
    { "match": "*.anthropic.com", "action": "allow", "tag": "anthropic" },

    // IP/CIDR ベース (DNS を経由しない通信用)
    { "match": "127.0.0.0/8", "action": "allow", "tag": "loopback" },
    { "match": "::1/128", "action": "allow", "tag": "loopback" },
    { "match": "10.0.0.0/8", "action": "allow", "tag": "private" },
    { "match": "172.16.0.0/12", "action": "allow", "tag": "private" },

    // prompt: 承認キューに入れてユーザー判断を待つ
    // { "match": "*.example.com", "action": "prompt", "tag": "review" },

    // デフォルト: 未知はブロック (learning_mode 時はログのみ)
    { "match": "*", "action": "deny" }
  ],

  // true: deny/prompt ルールにマッチしてもブロックせずログだけ取る
  "learning_mode": true
}
```

ルールアクション:
- **allow**: 自動で通す
- **deny**: 自動で拒否（enforce mode 時）
- **prompt**: TCP をブロックし、watch の承認キューで判断を待つ
```

### ルールのライフサイクル

```
[1. 観察]  learning mode で全 outbound を記録
              ├─ 接続先 (domain:port)
              ├─ タイムスタンプ
              └─ SNI

[2. 抽出]  seki log で通信パターンをレビュー
              "api.anthropic.com (AAAA, A) — would deny"
              "pypi.org (AAAA, A) — would deny"

[3. 判断]  seki rules add で許可ルールを追加
              seki rules add "api.anthropic.com" --allow --tag anthropic

[4. 適用]  seki mode enforce で未知をブロック
```

### ヒューリスティクス (将来)

以下の条件に該当する接続は警告表示する:
- 未知ドメイン + 高頻度アクセス
- `.site`, `.xyz`, `.tk` など使い捨てドメインの TLD
- IP アドレス直打ち
- 非標準ポート (443, 80 以外)

## コマンド承認レイヤー

ネットワーク監視とは独立した、手続き単位の承認メカニズム。
Claude Code の hooks (PreToolUse) と連携し、watch で統合表示する。

### 設計思想

- **ブラックリスト方式**: デフォルト allow、危険パターンだけ止める
- **手続き単位**: ドメイン単位ではなく「npm publish」「git push」のような操作単位
- **パターンベース**: 承認が必要な操作は限られているため、全数監視は不要

## watch UX

watch は 2 つの独立した領域で構成される。

### 画面構成

```
┌─ seki watch ──────────────────────────────────────┐
│                                                    │
│  [ログ領域] 全イベント流し                          │
│  dns  api.anthropic.com (A)                        │
│  tcp  160.79.104.10:443 (api.anthropic.com)        │
│  cmd  git push origin main                         │
│  dns  unknown.xyz (A)                              │
│  tcp  ⏳ 93.184.216.34:443 (unknown.xyz) — 承認待ち│
│                                                    │
│  [承認キュー] (2件)                                 │
│  ❯ unknown.xyz:443 — [a]llow [d]eny               │
│    git push origin main — [a]pprove [d]eny         │
│                                                    │
└────────────────────────────────────────────────────┘
```

- **ログ領域**: ネットワーク (DNS/TCP) + コマンド承認、全イベントが流れる
- **承認キュー**: 判断が必要なイベントが溜まる。件数表示付き。先頭から順に処理

### ルールアクション

ルールには 3 つのアクションがある:

| アクション | 挙動 |
|-----------|------|
| `allow` | 自動で通す |
| `deny` | 自動で拒否 |
| `prompt` | TCP をブロックし、承認キューに追加。watch で判断を待つ |

未知のドメイン・コマンド（ルールにマッチしない）は `prompt` と同様にキューに入る。

### prompt 時のブロック挙動

```
Client → TCP connect
  → iptables REDIRECT → seki proxy
  → ルール評価:
      allow  → 即 Dial、relay 開始
      deny   → 即 close
      prompt → TCP をブロック (Dial しない)
                → 承認キューに追加
                → watch で approve → Dial、relay 開始
                → watch で deny → close
                → タイムアウト → close (キューには残す)
```

**DNS は止めない** — DNS クライアントのタイムアウト (2-5秒) が短すぎるため。
DNS は通して名前解決だけさせ、TCP 接続時にブロックする。
これにより承認キューに「93.184.216.34:443」ではなく「unknown.xyz:443」と
ドメイン名付きで表示でき、ユーザーの判断がしやすい。

### タイムアウト

TCP のブロックにはタイムアウトを設ける（数十秒）。

- タイムアウト → 接続失敗としてクライアントに返す
- **キューには残す** — ユーザーが後から watch で判断できる
- 次に同じドメインへのリクエストが来たら、キューの判断結果を適用
- 一度 allow/deny したら以降は自動適用（ルールとして記憶）

### watch 未起動時

承認キューに入るべきイベントはデフォルト deny（安全側に倒す）。
watch を起動することが自然な運用フローになる。

## エージェントへのブロック通知

seki がブロックした事実をサンドボックス内のエージェントに伝える仕組み。
これがないとエージェントは「ネットワーク障害」と「セキュリティブロック」を区別できず、
リトライ地獄に陥る。

### 方式: PostToolUse hook によるブロック情報注入

```
┌─ Claude Code ─────────────────────────────────────┐
│  Bash: curl unknown.xyz                            │
│  → TCP ブロック → タイムアウト → connection refused │
│                                                     │
│  PostToolUse hook 発火                              │
│  → seki query --since=5s --format=hook             │
│  → stdout に追記:                                   │
│    "[seki] unknown.xyz は承認待ちです。             │
│     seki watch で承認してください。"                │
│                                                     │
│  Claude: 承認が必要です。                           │
│          seki watch で unknown.xyz を承認して       │
│          ください。その後リトライします。            │
└─────────────────────────────────────────────────────┘
```

`seki query` は以下の状態を区別して返す:
- **denied**: ルールで明示的に deny されている
- **pending**: 承認キューで判断待ち（watch で操作が必要）
- **timeout**: 承認待ちでタイムアウトした（watch で操作後リトライ可能）

## CLI インターフェース

```bash
# 基本: Claude Code をネットワーク関所の中で実行 (sudo 不要)
seki exec -- claude

# 監視 (別ターミナル)
seki watch

# ログの確認
seki log
seki log --domain webhook.site

# ルール管理
seki rules add "*.github.com" --allow --tag git
seki rules remove "*.github.com"
seki rules list

# ブロック情報の問い合わせ (hook 用)
seki query --since=5s
seki query --since=5s --format=hook

# learning mode の切替
seki mode learning
seki mode enforce
```

## メタデータ保護

seki のルール・ログは子プロセスと同じ uid で動くため、
ファイルパーミッションだけでは保護できない。
mount 名前空間で `~/.config/seki/` を read-only bind mount する。

## ソケット信頼検証

seki の Unix socket はイベントの送受信に使われる。sandbox 内のプロセスも
この socket に接続できるため、承認イベント（approve/deny）の送信元を検証する。

### 方式: user namespace による接続元識別

接続時に `SO_PEERCRED` でピアの PID を取得し、`/proc/<pid>/ns/user` を
ホストの user namespace と比較する。

| 接続元 | user namespace | 信頼レベル |
|--------|---------------|-----------|
| watch | ホスト NS | trusted — 制御イベント送信可 |
| child (seki 内部) | sandbox NS | untrusted — 制御イベントはドロップ |
| sandbox プロセス | sandbox NS (またはその子孫) | untrusted — 制御イベントはドロップ |

**制御イベント**: `approve`, `deny`, `cmd_approve`, `cmd_deny`
**非制御イベント**: `dns`, `tcp`, `status`, `dnat`, `forward` 等 — 信頼レベル不問

### なぜ user namespace 比較が堅牢か

- sandbox は常に child user namespace にいる（ホスト NS と異なる inode）
- `unshare(CLONE_NEWUSER)` で新 NS を作っても descendant であり、ホスト NS にはなれない
- `setns()` でホスト NS に入るには `CAP_SYS_ADMIN` in ホスト NS が必要 → sandbox から不可能
- fail-closed: SO_PEERCRED や /proc 読み取り失敗時は untrusted 扱い

## slirp4netns API 保護

slirp4netns の API socket はポートフォワード等の操作に使われる。
sandbox から直接アクセスされると意図しないサービス公開が可能なため、保護する。

- ChildSetup で API socket に `/dev/null` を bind mount して隠蔽
- 環境変数 `SEKI_SLIRP_API` を sandbox env からフィルタ
- ポートフォワードは seki parent socket 経由でプロキシ（parent が slirp API を呼ぶ）

## クレデンシャル隔離

sandbox 内のプロセスから永続的なシークレット（API キー、トークン等）を
構造的に不可視にする仕組み。ネットワーク隔離が「出口を塞ぐ」のに対し、
クレデンシャル隔離は「そもそも盗むものがない」状態を作る。

### 背景

現状 `cmd.Env = os.Environ()` で親プロセスの環境変数を全てそのまま渡しているため、
`ANTHROPIC_API_KEY`, `GH_TOKEN` 等が sandbox 内から読める。
seki がネットワークを塞いでいるので流出リスクは低いが、
多層防御の観点から「見えない」方が筋がいい。

参考: [Anthropic Managed Agents](https://www.anthropic.com/engineering/managed-agents) の
vault+proxy パターン — エージェントの実行環境にクレデンシャルを置かず、
ツール呼び出し時にプロキシが注入する設計。

### 方式: 環境変数フィルタ + credential helper proxy

2 段構成で実現する。コマンド全体を host で代理実行するのではなく、
**credential だけを socket 経由で注入し、コマンド自体は sandbox 内で実行する**。

**1. 環境変数フィルタ（受動的隔離）**

sandbox 起動時に秘密の環境変数を除外する。

```go
// netns.go — sandbox 作成時
cmd.Env = filterEnv(os.Environ(), credentials.SecretKeys())
```

これだけで sandbox 内から credential が「見えない」状態になる。

**2. credential helper proxy（能動的注入）**

各ツールのネイティブ credential 機構を利用し、認証情報だけを socket 経由で取得する。
コマンドの stdin/stdout/exit code を proxy する必要がない。

| ツール | 機構 | sandbox 側の設定 |
|--------|------|-----------------|
| git (HTTPS) | `git credential helper` | `credential.helper = /path/to/seki-credential` |
| git (SSH) | SSH agent proxy | `SSH_AUTH_SOCK=/path/to/seki-ssh-agent.sock` |
| npm | `.npmrc` token | seki が起動時に一時 `.npmrc` を生成 |
| gh | `GH_TOKEN` | seki-credential が環境変数として注入 |

```
sandbox 内                      Unix socket            host 側 (seki parent)
──────────                      ───────────            ─────────────────────
git push
  → git credential fill
  → seki-credential helper
    → socket で credential 要求
                                ─────────→
                                                       keychain/env から読み出し
                                                       credential を返却
                                ←─────────
    → git credential プロトコルで応答
  → HTTPS 認証成功
  → push 実行 (sandbox 内で完結)
```

### git credential helper

git のネイティブ credential helper プロトコルに準拠する。

```
# git → seki-credential (stdin)
protocol=https
host=github.com

# seki-credential → git (stdout)
protocol=https
host=github.com
username=x-access-token
password=ghp_xxxxx
```

`seki-credential` は:
1. stdin から host/protocol を読む
2. SEKI_SOCK 経由で host 側に credential 要求
3. host 側が keychain/env から読み出して返却
4. git credential プロトコルで stdout に出力

### SSH agent proxy

SSH 鍵での git 操作用。sandbox 内に SSH agent socket を作り、
署名リクエストだけ host 側の SSH agent に転送する。
**秘密鍵は sandbox に入らない**（署名結果だけ返る）。

```
sandbox 内                      Unix socket            host 側
──────────                      ───────────            ────────
ssh git@github.com
  → SSH_AUTH_SOCK → seki agent
    → 署名リクエスト転送
                                ─────────→
                                                       host の ssh-agent で署名
                                ←─────────
    → 署名結果を返却
  → SSH 認証成功
```

### クレデンシャルマッピング

```jsonc
// ~/.config/seki/credentials.json
{
  "credentials": [
    {
      "name": "github",
      "type": "git-credential",
      "host": "github.com",
      "source": "env:GH_TOKEN"      // 環境変数から取得
    },
    {
      "name": "npm",
      "type": "npmrc",
      "registry": "https://registry.npmjs.org/",
      "source": "env:NPM_TOKEN"
    },
    {
      "name": "anthropic",
      "type": "env",
      "inject": "ANTHROPIC_API_KEY",
      "source": "env:ANTHROPIC_API_KEY"
    }
  ],
  "ssh_agent_forward": true          // host の SSH agent を転送
}
```

### セキュリティモデル

| 状態 | sandbox 内 | host 側 |
|------|-----------|---------|
| 環境変数 | フィルタ済み（秘密なし） | 全て保持 |
| SSH 秘密鍵 | 不可視（agent proxy のみ） | ssh-agent が保持 |
| git credential | helper 経由で一時取得 | keychain/env から読み出し |
| npm token | 一時 .npmrc（sandbox 終了で消滅） | env から読み出し |

三重防御:
1. **見えない** — 環境変数フィルタ + .ssh 非マウントで credential が存在しない
2. **出せない** — ネットワーク隔離で外部送信が不可能
3. **使えない** — credential helper は承認キューと統合可能（prompt アクション）

### コマンド承認との統合

credential helper は既存のコマンド承認レイヤーと自然に合流する。

| 操作 | 承認 | credential |
|------|------|-----------|
| `git push` | prompt (承認キュー) | git credential helper が注入 |
| `npm publish` | prompt | 一時 .npmrc |
| `curl api.example.com` | allow (ルール次第) | 注入なし |

承認と credential 注入が同じフローで処理できるため、
「承認された操作だけに credential が渡る」という原則が自然に成立する。

### 暫定措置: .ssh bind-mount

credential helper proxy が未実装の間は、~/.ssh を /root/.ssh に
bind-mount して SSH を直接使えるようにしている。
credential helper proxy 完成後にこの bind-mount は削除する。

## Claude Code プロファイル切り替え

プロジェクトごとに異なる Claude Code の OAuth アカウント（サブスクリプション）を使い分ける仕組み。
seki の mount namespace を利用して、credentials ファイルだけをプロジェクトに応じて差し替える。

### 解く問題

複数の Anthropic アカウント（個人用・業務用など）を持っている場合、
プロジェクトによって使うアカウントを切り替えたい。
Claude Code の OAuth credentials は `~/.claude/` に保存されるが、
同ディレクトリには `CLAUDE.md`、`settings.json` 等の共有設定も含まれており、
ディレクトリごと差し替えると設定が分断される。

### 方式: credentials ファイルの bind-mount

ディレクトリ全体ではなく、**credentials ファイルだけ** を bind-mount で差し替える。

```
~/.claude-profiles/
  personal/
    .credentials.json      ← OAuth credentials (個人アカウント)
  work/
    .credentials.json      ← OAuth credentials (業務アカウント)

~/.claude/
  CLAUDE.md                ← 共有 (差し替えない)
  settings.json            ← 共有 (差し替えない)
  .credentials.json        ← bind-mount でプロファイルのものに差し替え
```

sandbox 起動時に、mount namespace 内で credentials ファイルを bind-mount する:

```
host 側 (実体)                                 sandbox 内 (bind-mount)
────────────────                               ──────────────────────
~/.claude-profiles/work/.credentials.json  →   ~/.claude/.credentials.json
```

`~/.claude/` 配下の他のファイル（設定・ドキュメント）はそのまま見える。

### プロファイルマッピング

seki のグローバル設定でプロジェクトパス → プロファイルの対応を定義する。
glob パターンと default フォールバックで、新規プロジェクト追加時の手間を最小化する。

```jsonc
// ~/.config/seki/config.json
{
  "claude_profiles": {
    "default": "personal",
    "projects": [
      { "match": "/home/kr9ly/projects/kurashiru-*", "profile": "work" },
      { "match": "/home/kr9ly/projects/nell-*", "profile": "work" }
    ]
  }
}
```

**マッチングルール:**
1. `seki exec --claude-profile <name>` の明示指定（環境変数 `SEKI_CLAUDE_PROFILE` 経由で伝搬）があればそれが最優先
2. なければ sandbox 起動時のカレントディレクトリをキーにする
3. `projects` の glob パターンを上から順にマッチ
4. マッチしなければ `default` にフォールバック
5. `default` も未設定ならプロファイル切り替えなし（通常の `~/.claude/.credentials.json` をそのまま使用）

明示指定は、同一プロジェクトで並列セッションを立てるときに usage をアカウント間で
分散させる用途を想定している（cwd ベースの解決では全並列セッションが同じプロファイルになる）。

### 初回ログイン

プロファイルの初回セットアップは、sandbox 内で通常通り `claude login` するだけ。
bind-mount 先のプロファイルディレクトリに credentials が書き込まれる。

```bash
# 1. プロファイルディレクトリを作成
mkdir -p ~/.claude-profiles/work

# 2. work プロファイルが適用されるプロジェクトで seki sandbox に入る
cd /home/kr9ly/projects/kurashiru-android
seki shell  # (または通常の alias 経由)

# 3. sandbox 内で普通にログイン
claude login
# → ~/.claude-profiles/work/.credentials.json に保存される
```

### アカウント identity の分離（~/.claude.json の oauthAccount）

credentials だけの差し替えでは分離が不完全だったことが運用で判明した（2026-08-17）。
`~/.claude.json` の `oauthAccount`（アカウント表示・機能ゲートに使われる identity 情報）が
全プロファイル共有のままで、どのセッションも「ホストで最後に /login したアカウント」を
名乗ってしまう。トークン層（API 課金・レートリミット）は分離できていたが、
表示と Claude Code 内の分岐は最後のログインに引きずられていた。

一方 `~/.claude.json` には共有していたい状態（`mcpServers`、`projects` の信頼状態、
プロンプト履歴）も同居しているため、ファイル丸ごとのプロファイル分離はドリフトを生む。
そこで **oauthAccount フィールドだけ差し替えたコピーを bind-mount** する:

- **起動時** (`bindClaudeJSON`): ホストの `~/.claude.json` をスナップショットし、
  `oauthAccount` をプロファイルの保存分（`~/.claude-profiles/<p>/oauthAccount.json`）に
  差し替えて `~/.claude-profiles/<p>/.claude.json` に書き出し、ホストパスに bind-mount。
  保存分がまだ無い場合はフィールドを**削除**する — Claude Code が bind 済みトークンで
  identity を再取得するので、他プロファイルの identity を継承しない（自己修復ブートストラップ）。
- **終了時** (`SyncBackClaudeJSON`): セッションの `oauthAccount` をプロファイルストアに保存。
  ただし保存済み identity と `accountUuid` が一致する場合のみ更新（後述の rename detach 後は
  他セッションの identity が混入しうるため、クロス汚染ガードとして機能する）。
  bind が生きていれば（`os.SameFile` で判定）unmount してから非 identity フィールドを
  ホストファイルにマージ（`projects` はキー単位マージ、`oauthAccount` はホスト側を維持）。
  マージは flock（`~/.claude-profiles/.claude.json.seki-lock`）で seki 同士を直列化。

**既知の限界**: Claude Code は `~/.claude.json` を atomic rename で頻繁に書き換えるため、
bind は最初の書き込みで剥がれ、以降セッションはホストファイルを直接書く
（credentials の rename detach と同じ挙動）。この間ホストファイルの `oauthAccount` は
最後に書いたセッションのものになる — `.credentials.json` のホスト実体と同様、
**ホストの `~/.claude.json` の identity はスクラッチ扱い**とする（seki 経由のセッションは
毎回起動時に差し替えるので影響しない。seki 外で起動した claude だけが揺れた identity を見る）。

darwin backend はこの仕組みの対象外 — mount namespace が無いため元々
`CLAUDE_CONFIG_DIR` によるディレクトリ丸ごと分離で、identity も分離済み。

### クレデンシャル隔離との関係

既存のクレデンシャル隔離（環境変数フィルタ + credential helper proxy）とは独立した仕組み。

- **クレデンシャル隔離**: sandbox 内から API キー等の秘密を不可視にする（防御）
- **プロファイル切り替え**: Claude Code 自体の認証アカウントを選択する（利便性）

両者は同じ mount namespace 内で共存する。

## 実装状況

言語: **Go** (ネットワーク操作、バイナリ配布、既存ツールとの一貫性)

### 完了

- [x] unprivileged user namespace + slirp4netns による rootless ネットワーク分離
- [x] DNS リゾルバ (127.0.0.1:5353, SO_MARK bypass, slirp4netns DNS upstream)
- [x] TCP プロキシ (127.0.0.1:10200, SO_ORIGINAL_DST + SO_MARK, SNI 抽出)
- [x] iptables REDIRECT + DNAT (namespace 内、ホスト無影響)
- [x] ルール評価エンジン (glob + CIDR マッチ、learning/enforce mode、specificity ソート)
- [x] SQLite ログ永続化 (WAL mode)
- [x] seki watch (Unix socket イベントストリーム、複数セッション対応、接続復帰)
- [x] watch TUI (スクロールリージョン 2 領域分離、承認キュー対話操作、ルール自動永続化)
- [x] DNS NXDOMAIN 返却 (deny 時)
- [x] TCP 接続拒否 (deny 時)
- [x] DNS キャッシュ (TCP 接続時のドメイン名逆引き補完)
- [x] learning mode で Claude Code の通信パターン観察を確認
- [x] PostToolUse hook (`seki hook post-bash` — ブロック通知注入)
- [x] PreToolUse hook (`seki hook pre-bash` — コマンド承認連携)
- [x] seki mode (learning/enforce 切り替え)
- [x] seki query (ブロック情報クエリ、--format=hook 対応)
- [x] credentials.json (クレデンシャルマッピング設定)
- [x] git credential helper proxy (socket 経由で host から取得)
- [x] SSH agent proxy (署名リクエスト転送、秘密鍵は sandbox に入らない)
- [x] .ssh コピーベース配置 (config + known_hosts のみ、秘密鍵なし)
- [x] 環境変数フィルタ (sandbox 起動時に SecretKeys() 参照の環境変数を除外)
- [x] ~/.config/seki/ read-only bind mount (ルール・設定の改ざん防止)
- [x] ソケット信頼検証 (SO_PEERCRED + user namespace 比較で sandbox からの approve をドロップ)
- [x] ICMP DROP (ICMP トンネリング防止)
- [x] ip6tables (IPv6 トラフィックを loopback 以外全 DROP)
- [x] slirp API 保護 (/dev/null bind mount + parent プロキシ経由でポートフォワード)

### 未実装
- [ ] ECH 除去 (HTTPS/SVCB レコードから ECH 設定を除去)
- [ ] 起動時パーミッションチェック
- [ ] ルール自動提案 (`seki log --suggest` 的な)

## サービス宣言（sandbox 内常駐デーモン）

### 概要

`~/.config/seki/config.json` の `services` フィールドに、sandbox 起動時に内部で spawn するデーモンを宣言できる。
宣言されたサービスはユーザーコマンドの前に起動し、ユーザーコマンド終了後に道連れで停止する。

### config schema

```json
{
  "sandbox_env": { "TESTCONTAINERS_RYUK_DISABLED": "true" },
  "services": [
    {
      "name": "podman-api",
      "command": ["podman", "system", "service", "--time=0"],
      "ready_socket": "$XDG_RUNTIME_DIR/podman/podman.sock",
      "ready_timeout_sec": 15,
      "stop_command": ["podman", "stop", "--all", "--time", "5"],
      "env": { "EXAMPLE": "per-service-override" }
    }
  ]
}
```

| フィールド | 必須 | 説明 |
|-----------|------|------|
| `name` | yes | 識別子。ログファイル名 (`~/.cache/seki/services/<name>.log`) に使う |
| `command` | yes | argv 配列。シェル経由にしない |
| `ready_socket` | no | connect できるまで待つ unix socket パス。`os.ExpandEnv` で展開 |
| `ready_timeout_sec` | no | readiness 待ちの上限（デフォルト 15s）。超えたら警告してそのまま続行 |
| `stop_command` | no | SIGTERM の前に同期実行するクリーンアップコマンド（timeout 10s） |
| `env` | no | サービス専用の追加環境変数 |

### プロセスモデル（supervisor mode）

services が宣言されている場合のみ動作が変わる。**services が空なら現行の syscall.Exec パスを完全維持**。

```
seki exec
  └── seki __child (CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS)
        └── seki __ns-exec (CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID ← services 宣言時のみ追加)
              ├── service-1 (Setpgid=true, 独立 pgrp)
              ├── service-2 (Setpgid=true)
              └── user command (前景 pgrp, Ctrl-C 直達)
```

`__ns-exec` が pid 1 になることで:
- supervisor 終了時に pid namespace 内の全プロセスへ SIGKILL（カーネル保証）
- double-fork デーモン（conmon 等）も逃げられない
- orphan の zombie reaping を pid 1 が担う（`syscall.Wait4(-1, ...)` ループ）

### シャットダウンシーケンス

ユーザーコマンド終了後、逆順で各サービスを停止:

1. `stop_command` を同期実行（timeout 10s）
2. サービスの pgid に SIGTERM
3. 最大 5s 待つ → 残っていれば SIGKILL

### サービスログ

- `~/.cache/seki/services/<name>.log` に append（sandbox 終了後もデバッグ可能）
- 起動時にタイムスタンプ付き開始マーカーを書く

### フォールバック

subuid が利用不可の環境（`ParseSubIDEnv` が nil を返す場合）は `__ns-exec` を経由しないため services 非対応。
services が宣言されていても「subuid not available — services will not be started」と警告し、スキップする。

## macOS ネイティブ対応（darwin backend）

### 背景: VM アプローチの破棄

v0.1.0 で Apple container の Linux VM 内で seki を動かす方式（seki-mac、docs/macos.md）を
リリースしたが、**開発環境として成立しない**と判断し破棄する:

- ワーキングツリーが常に共有ファイルシステム上に置かれる。virtiofs 越しの I/O 性能に加え、
  VM 内で作った linux/arm64 アーティファクト（node_modules、ビルドキャッシュ）と
  Mac 側ツール（エディタ LSP 等）が同じツリー上で衝突する
- VM 内の構成管理が Mac 側（homebrew）と二重化する。Mac ユーザーに
  「VM 内にもう一つの開発環境を維持しろ」と要求することになる
- darwin ネイティブが必要な開発（iOS ビルド、Safari 検証）が原理的に射程外

結論: Mac 対応 = **darwin ネイティブバイナリ + macOS の隔離機構**でなければならない。

### 方式の選択

Linux 版の依存機構を macOS で代替する選択肢は 3 つ:

| 方式 | 透過性 | rootless | 配布 | 判定 |
|------|--------|----------|------|------|
| Network Extension (NEFilterDataProvider) | ○ プロセス単位で OS レベルフィルタ | △ ユーザー承認は GUI | ✗ 署名済み System Extension + entitlement + app bundle 必須 | 棚上げ（配布を本格化する段階で再検討） |
| PF (pfctl) | ○ UID 単位で rdr 可能 | ✗ sudo 必須 + システムワイド設定変更 | ○ | 不採用（「ホスト無変更」の設計判断に反する） |
| **Seatbelt (sandbox-exec) + 明示プロキシ** | △ プロキシ環境変数への協力が前提 | ○ | ○ シングルバイナリ維持 | **採用** |

Seatbelt 方式の骨子: sandbox profile で**外向きネットワークを全 deny し、localhost の
seki プロキシへの接続だけを allow** する。プロセスには `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` で
プロキシを教える。協力的なプロセスはプロキシ経由で検問を通り、迂回を試みるプロセスは
Seatbelt が接続自体を拒否する。「検問を通らない通信は存在できない」という不変条件は
透過モデルと同じ強度で維持される。

`sandbox-exec` は deprecated 扱いだが、Bazel や Anthropic の sandbox-runtime が
現役で同じ構成（Seatbelt + プロキシ強制）を使っており、事実上の安定 API。

### 機構マッピング（Linux → darwin）

| Linux backend | darwin backend |
|---------------|----------------|
| user / net / mount namespace | Seatbelt profile（プロセス単位 deny-all） |
| iptables REDIRECT + SO_ORIGINAL_DST | 明示プロキシ（HTTP CONNECT）+ プロキシ環境変数 |
| slirp4netns | 不要（ホストネットワークを直接使用、出口はプロキシのみ） |
| DNS リゾルバ検問（:5353 DNAT） | プロキシ側ホスト名解決に統合（下記） |
| SO_PEERCRED + user ns 比較 | LOCAL_PEERCRED + Seatbelt による接続禁止（下記） |
| PID namespace 道連れ（サービス宣言） | プロセスグループ + kqueue EVFILT_PROC（ベストエフォート） |
| ~/.config/seki read-only bind mount | Seatbelt file ルールで write deny |

移植不要（そのまま動く）: ルールエンジン、watch UI、コマンド承認レイヤー、hooks 連携、
credential helper proxy、SSH agent proxy、環境変数フィルタ、SQLite ログ。
3 層検問の頭脳部分はネットワーク機構に依存しない。

### ネットワークデータパス（darwin）

```
User process (Seatbelt 内)
  → HTTPS_PROXY=127.0.0.1:<port> に従い CONNECT example.com:443
  → seki プロキシ: CONNECT のホスト名でルール評価
  → allow: 200 を返しトンネル確立 → TLS ClientHello を peek し、SNI が CONNECT
    ホストと異なる場合（ドメインフロンティング）は SNI で再評価
  → deny: トンネル確立前なら 403 Forbidden（クライアントに理由が見える）、
    確立後（SNI 再評価）なら接続切断
  → PostToolUse hook でブロック理由をエージェントに注入（Linux 版と共通）

User process が直接 connect を試みた場合
  → Seatbelt が deny（errno EPERM）— 検問迂回は「通信不能」に落ちる
```

### DNS の扱い

darwin では DNS 検問を独立レイヤーとして持たず、**プロキシ側解決に一本化**する:

- CONNECT プロキシはホスト名で受けて自分で解決するため、クライアント側の DNS が不要
- sandbox 内からの直接解決（mDNSResponder への mach-lookup / :53 直行）は Seatbelt で遮断
  → DNS トンネリングも同時に塞がる
- 副産物: クライアントが HTTPS/SVCB レコードを引けないため、**ECH 迂回問題が構造的に消える**
  （Linux 版では ECH 除去が未実装 TODO として残っている）

### ソケット信頼検証（darwin）

Linux 版は SO_PEERCRED + user namespace 比較で sandbox 内からの approve をドロップする。
darwin では sandbox プロセスがホストと同一 euid で走るため、peer credential では
watch と sandbox を区別できない。そこで**ソケット自体を 2 本に分離**する:

1. **制御ソケット**（`seki-<pid>.sock`）— watch 専用。Seatbelt profile がパスへの
   接続を deny するため sandbox 内から届かない（機構としてはこちらが本体）。
   LOCAL_PEERCRED の euid 検証は他ユーザーに対する多層防御
2. **イベントソケット**（`seki-sb-<pid>.sock`）— sandbox 内の hooks / emit 用。
   `SEKI_SOCK` はこちらを指す。接続は常に untrusted 扱いで、approve/deny 等の
   制御イベントはドロップされる（イベント送信と rebroadcast 受信のみ可能）

### SSH

ssh はプロキシ環境変数を見ないため、`ProxyCommand` で seki 経由に固定する。
darwin には mount namespace がなく .ssh/config のコピーベース差し替えができないので、
環境変数で git のみに注入する:

```
GIT_SSH_COMMAND=ssh -o ProxyCommand="seki proxy-connect %h %p"
```

`seki proxy-connect` は stdio ↔ seki プロキシ（CONNECT）の relay。ルール評価は
ホスト名ベースでプロキシ側に乗る。SSH agent proxy（署名転送）は Linux 版と共通。
git 以外の直接の ssh 実行はプロキシを知らないため Seatbelt に落とされる
（ユーザーが手動で `-o ProxyCommand="seki proxy-connect %h %p"` を付ければ通る）。

### 失うもの・トレードオフ

- **透過性**: プロキシ環境変数を無視するツールは「検問で観察される」ではなく
  「通信できない」になる。learning mode の観察力が一段落ちる
  （ブロックは Seatbelt の deny として起き、seki のログに乗らない可能性がある —
  スパイクで確認）
- **PID namespace のカーネル保証**: サービス宣言機能の道連れ停止がベストエフォートに落ちる。
  darwin ではサービス宣言を当面スコープ外とし、必要になった時点で kqueue 監視を設計する
- **プロファイル切り替えの bind-mount**: mount namespace がないため、credentials の
  bind-mount 方式は使えない。環境変数（`CLAUDE_CONFIG_DIR` 等）ベースの方式に置き換える

### ビルド・配布

- `//go:build linux` / `//go:build darwin` でバックエンドを分離し、検問ロジックを共有する
- `make release` に `seki-darwin-arm64` を追加。CGO 不要を維持
  （Seatbelt は `/usr/bin/sandbox-exec` の exec で使い、libsandbox にリンクしない）
- seki-mac ランチャーと docs/macos.md の VM 手順は deprecated

### 実装状態（2026-07）

darwin backend は実装済み（`internal/sandbox/backend_darwin.go`、CONNECT プロキシは
`internal/proxy/connect.go`、profile 生成は `internal/seatbelt`）。プラットフォーム
中立な部分（CONNECT トンネル、ルール評価、SNI 再評価、absolute-URI HTTP、profile
生成）は Linux 上のユニットテストで検証済み。**Seatbelt の実挙動は Mac 実機で未検証**
— 下記スパイクが通るまでこの backend は信頼できない。

### スパイク計画（Mac 実機で検証する前提）

リスク順。1 つでも落ちたら方式を再交渉する:

1. **Seatbelt deny-all + localhost allow が強制できるか** — profile を書いて
   `sandbox-exec` 経由で `curl https://example.com` が EPERM、
   `HTTPS_PROXY` 経由が通ることを確認（macOS 26 実機）
2. **mDNSResponder 経由の DNS 解決を遮断できるか** — `dig` / `getaddrinfo` 両経路
3. **主要ツールのプロキシ追従** — claude / git (https) / npm / gh / curl が
   `HTTPS_PROXY` + CONNECT で動くか
4. **ssh ProxyCommand 経路** — git over ssh がルール評価に乗るか
5. **LOCAL_PEERCRED** — Go から取得できるか（`golang.org/x/sys/unix.GetsockoptXucred`）
6. **Seatbelt deny のログ可視性** — ブロックが seki 側で観察できるか
   （できない場合、learning mode の darwin 版は「プロキシに来たものだけ観察」に縮退）

## 確定済み設計判断

- ドメイン単位のネットワーク制御 (パス・メソッド・ボディは見ない)
- TLS 終端しない — Certificate Pinning を壊さない
- learning mode → enforce mode の段階的移行
- DNS を一次手段、SNI を二次手段とする 3 層検問
- ECH 対策: DNS リゾルバで HTTPS/SVCB レコードから ECH 設定を除去し SNI fallback を強制
- DoH/DoT 迂回防止: namespace 内で seki 以外への DNS トラフィックを遮断
- ブロック通知: PostToolUse hook でエージェントにブロック理由を注入
- rootless: unprivileged user namespace + slirp4netns (sudo 不要)
- SO_MARK=1 で seki 自身の外部通信を iptables bypass
- ホスト安全性: ホスト側の変更はゼロ (veth pair も不要に)
- 承認は手続き単位 (ドメイン単位ではなく「git push」のような操作単位)
- 2レイヤーモデル: ネットワーク (ホワイトリスト) + コマンド承認 (ブラックリスト)
- Mac 対応は darwin ネイティブ (Seatbelt + 明示プロキシ) — Apple container VM アプローチは破棄
- stderr 出力は抑制し、ログは SQLite + watch socket に集約
- クレデンシャル隔離: 環境変数フィルタ + credential helper proxy (代理実行ではなく credential だけ注入)
- 承認された操作だけに credential が渡る (承認キューとの統合)
- SSH は agent proxy で署名転送 (秘密鍵は sandbox に入らない)
- ソケット信頼: user namespace 比較で接続元を識別 (sandbox からの制御イベントをドロップ)
- ICMP/IPv6: 全 DROP (seki のサービスは TCP+UDP over IPv4 のみ)
- slirp API: sandbox から隠蔽、ポートフォワードは parent プロキシ経由
