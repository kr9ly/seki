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

### 未実装
- [ ] ECH 除去 (HTTPS/SVCB レコードから ECH 設定を除去)
- [ ] 起動時パーミッションチェック
- [ ] ルール自動提案 (`seki log --suggest` 的な)

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
- stderr 出力は抑制し、ログは SQLite + watch socket に集約
- クレデンシャル隔離: 環境変数フィルタ + credential helper proxy (代理実行ではなく credential だけ注入)
- 承認された操作だけに credential が渡る (承認キューとの統合)
- SSH は agent proxy で署名転送 (秘密鍵は sandbox に入らない)
