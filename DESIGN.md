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

### 既存手段との棲み分け

| 層 | 手段 | 守るもの | 限界 |
|----|------|----------|------|
| 意味レベル | hooks (PreToolUse) | 「何をするか」— push, deploy, auth | ネットワーク通信を直接制御できない |
| ネットワークレベル | **seki** | 「どこに出るか」— 全プロトコルのドメイン制御 | 操作の意図は判断できない |

この 2 層は補完関係にあり、どちらか一方では不十分。

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
- これらの問題に対処する設定の手間

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

## メタデータ保護

seki のルール・ログは子プロセス（Claude Code）と同じ uid で動くため、
ファイルパーミッションだけでは保護できない。
`unshare --mount` で seki のメタデータディレクトリを read-only にする。

### 起動時チェック (git 方式)

`seki exec` 起動時に以下を検証し、不合格なら起動を拒否する:

```
~/.config/seki/
├─ rules.json   — 0600 or 0644, owner = 自分
├─ seki.db      — 0600, owner = 自分
└─ (dir自体)    — 0700 or 0755, owner = 自分
```

- グループ・other に書き込み権限がある場合 → エラーで停止
- オーナーが自分でない場合 → エラーで停止

### 子プロセスからの書き換え防止

パーミッションチェックは安全弁だが、同一 uid の子プロセスには効かない。
ネットワーク名前空間と合わせて mount 名前空間も分離し、
メタデータを read-only bind mount で保護する。

```
seki exec 起動時:
  1. パーミッションチェック (上記)
  2. unshare --net --mount で名前空間を作成
  3. ~/.config/seki/ を read-only bind mount
  4. seki 自身はマウント前の fd を保持してログ書き込みを継続
  5. 子プロセスを起動 (Claude Code)
     → 子プロセスから ~/.config/seki/ は読めるが書けない
```

## ホスト安全性保証

seki が crash・SIGKILL されてもホスト環境を破壊しないことを構造的に保証する。

### 原則: ホスト側の変更を veth pair のみに限定する

veth pair はネットワーク名前空間の消滅時に自動削除される。
それ以外のホスト側状態（iptables, sysctl, resolv.conf）は **一切変更しない**。

| リソース | 場所 | crash 時 |
|----------|------|----------|
| veth pair | ホスト | namespace 消滅で自動削除 |
| iptables REDIRECT | 子の名前空間内 | namespace 消滅で自動削除 |
| DNS リゾルバ | seki プロセス | プロセス死で自動消滅 |
| TCP プロキシ | seki プロセス | プロセス死で自動消滅 |

### やらないこと

- **ホスト側の iptables を触らない**: NAT (MASQUERADE) は使わない。
  TCP プロキシで代替する。既存の iptables チェーン（Tailscale 等）と干渉しない。
- **sysctl を変更しない**: `ip_forward` 等のカーネルパラメータは変更不要。
  NAT を使わず TCP プロキシで中継するため。
- **ホストの /etc/resolv.conf を触らない**: 子の名前空間内で
  `iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT --to 10.200.1.1:53`
  により DNS を seki にリダイレクトする。bind mount は使わない。

### 子プロセス側のネットワーク構成

子の名前空間内でのみ iptables を使用する（ホストに影響しない）。

```
# DNS: 全ての DNS クエリを seki のリゾルバにリダイレクト
iptables -t nat -A OUTPUT -p udp --dport 53 -j DNAT --to-destination 10.200.1.1:53
iptables -t nat -A OUTPUT -p tcp --dport 53 -j DNAT --to-destination 10.200.1.1:53

# TCP: 全ての TCP 接続を seki のプロキシにリダイレクト
iptables -t nat -A OUTPUT -p tcp -j DNAT --to-destination 10.200.1.1:<proxy-port>

# UDP: DNS 以外の UDP をブロック（QUIC/HTTP3 による検問迂回を防止）
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp -d 10.200.1.0/24 -j ACCEPT
iptables -A OUTPUT -p udp -j DROP
```

seki の TCP プロキシは元の宛先 IP:port を `SO_ORIGINAL_DST` で取得し、
実際の接続先に中継する。

## アーキテクチャ

```
┌─────────────────────────────────────────┐
│  seki exec -- claude                    │
│  ┌───────────────────────────────────┐  │
│  │  Claude Code                      │  │
│  │  ┌─ hooks (PreToolUse) ────────┐  │  │
│  │  │  意味レベルのゲート          │  │  │
│  │  │  "git push" → 外部承認待ち   │  │  │
│  │  │  "aws deploy" → 外部承認待ち │  │  │
│  │  └────────────────────────────┘  │  │
│  └───────────────────────────────────┘  │
│  ┌─ network namespace ───────────────┐  │
│  │  一次: DNS リゾルバ (捕捉+判定)    │  │
│  │  二次: SNI スニッフィング (照合)    │  │
│  │  最終: IP 直打ち → deny            │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
```

### ネットワーク分離

- `unshare --net --mount` + ユーザー名前空間で子プロセスを隔離
- mount 名前空間で `~/.config/seki/` を read-only bind mount（メタデータ保護）
- veth pair でホスト側の seki プロセスにのみ接続可能にする
- **ホスト側の状態変更は veth pair のみ** — iptables, sysctl, resolv.conf は触らない
  （詳細は「ホスト安全性保証」セクションを参照）
- 子の名前空間内で iptables REDIRECT → seki の DNS リゾルバ + TCP プロキシへ
- TLS を終端 **しない** — Certificate Pinning を使うツールを壊さない

### 3層の検問

ドメイン捕捉は DNS を一次手段、SNI を二次手段とする。

```
一次: DNS リゾルバ  — ドメイン捕捉 + allowlist 判定 + ECH 設定除去
二次: SNI スニッフィング — DNS を経由しない通信の検出・照合
最終: IP 直打ち → デフォルト deny
```

#### 一次: DNS リゾルバ

ネットワーク名前空間内の DNS を seki が完全に掌握する。

```
子プロセス → DNS クエリ "target.example.com"
               │
               ▼
         seki 内蔵 DNS リゾルバ
         ├─ ドメインをログに記録 (← ここで捕捉完了)
         ├─ allowlist 判定 (deny なら NXDOMAIN を返す)
         ├─ HTTPS/SVCB レコードから ECH 設定を除去 (→ SNI fallback 強制)
         └─ DoH/DoT 迂回の防止 (名前空間内で seki 以外への DNS トラフィックを遮断)
               │
               ▼
         上流 DNS へ転送 (allow の場合)
```

DNS が一次手段である理由:
- ECH が普及しても DNS クエリの時点でドメインが見える
- 名前空間を握っている以上、DNS の迂回 (DoH/DoT) もブロックできる
- deny 時に NXDOMAIN を返せば、接続自体が発生しない (より安全)

#### 二次: SNI スニッフィング

TLS ClientHello の `server_name` 拡張からドメインを抽出する。
DNS を経由せず IP 直打ちで TLS 接続する場合の検出に使う。
通信路に割り込まず、パケットを覗くだけなので TLS セッション自体は元のサーバーとそのまま張られる。

DNS ログとの照合にも使える（DNS で解決したドメインと実際の接続先の一致確認）。

#### 最終防衛: IP 直打ち

DNS も SNI も得られない通信（IP アドレス直打ち + 非 TLS or ECH）はデフォルト deny。

ただし正当な用途で IP 直打ちが必要なケースがある:
- `127.0.0.0/8`, `::1` — ローカル開発サーバー、DB
- `172.16.0.0/12`, `10.0.0.0/8` — Docker 内部ネットワーク
- `169.254.169.254` — クラウドメタデータエンドポイント

これらは IP/CIDR ベースの allowlist で対応する（ルール構造を参照）。
DNS で解決された通信は一次層で捕捉済みのため、proxy 層に到達する IP 直打ち通信は
「DNS を経由しなかったもの」だけに限定される。

## ルール構造

```jsonc
// ~/.config/seki/rules.json
{
  "rules": [
    // ドメインベース (DNS + SNI で判定)
    { "match": "*.github.com", "action": "allow", "tag": "git" },
    { "match": "github.com", "action": "allow", "tag": "git" },
    { "match": "registry.npmjs.org", "action": "allow", "tag": "npm" },

    // IP/CIDR ベース (DNS を経由しない通信用)
    { "match": "127.0.0.0/8", "action": "allow", "tag": "loopback" },
    { "match": "::1/128", "action": "allow", "tag": "loopback" },
    { "match": "10.0.0.0/8", "action": "allow", "tag": "private" },
    { "match": "172.16.0.0/12", "action": "allow", "tag": "private" },

    // デフォルト: 未知はブロック (learning_mode 時はログのみ)
    { "match": "*", "action": "deny" }
  ],

  // true: deny ルールにマッチしてもブロックせずログだけ取る
  "learning_mode": true
}
```

### ルールのライフサイクル

```
[1. 観察]  proxy が全 outbound を記録
              ├─ 接続先 (domain:port)
              ├─ タイムスタンプ
              └─ プロセス情報 (可能なら)

[2. 抽出]  セッション後 or リアルタイムで
              "新しい接続先を検出: registry.npmjs.org (3 reqs)"
              "新しい接続先を検出: webhook.site (1 req, port 443)" ⚠️

[3. 判断]  人間が TUI で決める
              ├─ allow  → allowlist に追加
              ├─ deny   → blocklist に追加
              └─ skip   → 判断を保留

[4. 適用]  learning_mode: false で未知をブロック
```

### ヒューリスティクス (⚠️ マーク)

以下の条件に該当する接続は review 時に警告表示する:
- 未知ドメイン + 高頻度アクセス
- `.site`, `.xyz`, `.tk` など使い捨てドメインの TLD
- IP アドレス直打ち
- 非標準ポート (443, 80 以外)

## エージェントへのブロック通知

seki がブロックした事実をサンドボックス内のエージェントに伝える仕組み。
これがないとエージェントは「ネットワーク障害」と「セキュリティブロック」を区別できず、
リトライ地獄に陥る。

### 方式: PostToolUse hook によるブロック情報注入

Claude Code の PostToolUse hook を使い、Bash 実行後にブロックログを問い合わせて出力に追記する。

```
┌─ Claude Code ─────────────────────────┐
│  Bash: curl blocked.com               │
│  → connection refused                  │
│                                        │
│  PostToolUse hook 発火                 │
│  → seki query --since=5s --json       │
│  → stdout に追記:                      │
│    "[seki] blocked.com はブロック中。  │
│     許可するには: seki rules add ..."  │
│                                        │
│  Claude: ブロックされている。          │
│          ユーザーに許可を確認しよう。   │
└────────────────────────────────────────┘
```

利点:
- プロトコルに依存しない（HTTP, SSH, 任意の TCP で動作）
- エージェントの意志に依存しない（hook が自動で注入する）
- 既存の Claude Code hooks インフラをそのまま活用

### seki query コマンド

hook から呼び出すための問い合わせインターフェース。

```bash
# 直近 N 秒間のブロックイベントを取得
seki query --since=5s

# JSON 出力 (hook でのパース用)
seki query --since=5s --json

# 出力例
# {"blocked": [{"domain": "blocked.com", "time": "...", "rule": "default deny"}]}
```

### hook 設定例

```jsonc
// ~/.claude/settings.json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash",
        "command": "seki query --since=5s --format=hook"
      }
    ]
  }
}
```

`--format=hook` は hook 出力に適した形式（ブロックがなければ空、あれば人間可読なメッセージ）を返す。

## CLI インターフェース

```bash
# 基本: Claude Code をネットワーク関所の中で実行
seki exec -- claude

# learning mode を明示的に指定
seki exec --learning -- claude

# 監視・承認 TUI (別ターミナルで起動)
seki watch

# ログの確認
seki log
seki log --domain webhook.site

# ルールの直接編集
seki rules add "*.github.com" --allow --tag git
seki rules remove "*.github.com"
seki rules list

# ブロック情報の問い合わせ (hook 用)
seki query --since=5s
seki query --since=5s --json
seki query --since=5s --format=hook

# learning mode の切替
seki mode learning
seki mode enforce
```

### seki watch

別ターミナルで常駐する監視・承認 TUI。`seki exec` と Unix socket で通信する。

```
Terminal 1                    Terminal 2
┌─ seki exec -- claude ──┐   ┌─ seki watch ─────────────┐
│                         │   │                           │
│  Claude: git push...    │   │  ⏳ git push (hooks)      │
│  → PreToolUse hook      │──→│  [a]pprove [d]eny [i]nfo │
│  → 承認待ち...          │   │                           │
│                         │   │  > a                      │
│  → 承認された、続行     │←──│  ✓ approved               │
│                         │   │                           │
│  Claude: curl unknown.. │   │  ⚠ unknown.xyz (blocked)  │
│  → PostToolUse で通知   │   │  [a]dd-rule [s]kip        │
└─────────────────────────┘   └───────────────────────────┘
```

機能:
- **リアルタイム承認**: PreToolUse hook からの承認リクエストを表示し、approve/deny を返す
- **ブロック通知**: ネットワークブロックが発生したらリアルタイムで表示。その場でルール追加も可能
- **ルールレビュー**: 未判断ドメインの一覧表示と allow/deny 操作（旧 `seki review` の機能を統合）
- **接続ログ**: 現在のセッションの通信ログをリアルタイム表示

### 通信方式

`seki exec` と `seki watch` は Unix socket (`~/.config/seki/seki.sock`) で通信する。

```
seki exec (ネットワーク名前空間 + プロセス管理)
    │
    │ Unix socket
    ▼
seki watch (TUI)
    ├─ イベントストリーム: 接続ログ、ブロック、承認リクエスト
    └─ コマンド: approve/deny、ルール追加
```

`seki watch` が起動していない場合:
- ブロックはルールに従って自動処理（learning → ログのみ、enforce → 遮断）
- 承認リクエストはタイムアウトで deny（安全側に倒す）

## 実装計画

言語: **Go** (ネットワーク操作、バイナリ配布、既存ツールとの一貫性)

### コンポーネント

```
seki/
├── cmd/
│   └── seki/
│       └── main.go          # CLI エントリポイント
├── internal/
│   ├── netns/
│   │   └── netns.go         # network namespace セットアップ (unshare + veth)
│   ├── dns/
│   │   └── dns.go           # DNS リゾルバ (捕捉 + allowlist 判定 + ECH 除去)
│   ├── sni/
│   │   └── sni.go           # TLS ClientHello パーサー (SNI 抽出・照合)
│   ├── proxy/
│   │   └── proxy.go         # TCP プロキシ (DNS/SNI 判定 → allow/deny/log)
│   ├── rules/
│   │   └── rules.go         # ルール評価エンジン (glob マッチ)
│   ├── logger/
│   │   └── logger.go        # 接続ログ (SQLite)
│   ├── watch/
│   │   └── watch.go         # 監視・承認 TUI (seki watch)
│   └── socket/
│       └── socket.go        # Unix socket 通信 (exec ↔ watch)
├── go.mod
└── go.sum
```

### Phase 1: 観察できる状態にする

1. `unshare --net --mount` + veth pair で子プロセスを隔離 (WSL2 動作確認含む)
2. DNS リゾルバ — 10.200.1.1:53 で listen、全クエリをログに記録し上流に転送
3. TCP プロキシ — 10.200.1.1 で listen、`SO_ORIGINAL_DST` で元の宛先を取得して中継。SNI を抽出してログに記録
4. 子の名前空間内で iptables REDIRECT — DNS (udp/tcp 53) と全 TCP を seki にリダイレクト。ホスト側の iptables/sysctl は一切触らない
5. `seki exec --learning -- <command>` で任意のコマンドを監視下で実行
6. `seki log` でログを確認

### Phase 2: ルールとレビュー

6. ルール評価エンジン (glob マッチ、allow/deny)
7. `seki review` TUI — 未判断ドメインの一覧と allow/deny 操作
8. `seki mode enforce` — 未知ドメインのブロック

### Phase 3: エージェント通知と承認 TUI

9. Unix socket 通信 — `seki exec` と `seki watch` 間のイベントストリーム
10. `seki watch` TUI — リアルタイム監視・承認・ルール管理を統合
11. `seki query` — ブロックイベントの問い合わせ CLI (hook 用)
12. PostToolUse hook 連携 — Bash 実行後にブロック情報をエージェントに注入
13. PreToolUse hook 連携 — 承認リクエストを `seki watch` に送り、応答を待つ

## 開いてる設計判断

### 確定済み

- [x] ドメイン単位の制御 (パス・メソッド・ボディは見ない)
- [x] TLS 終端しない — Certificate Pinning を壊さない
- [x] learning mode → enforce mode の段階的移行
- [x] DNS を一次手段、SNI を二次手段とする 3 層検問
- [x] ECH 対策: DNS リゾルバで HTTPS/SVCB レコードから ECH 設定を除去し SNI fallback を強制
- [x] DoH/DoT 迂回防止: 名前空間内で seki 以外への DNS トラフィックを遮断
- [x] ブロック通知: PostToolUse hook でエージェントにブロック理由を注入
- [x] 承認 UI: 別ターミナルの TUI (`seki watch`) で承認。Unix socket で通信
- [x] watch 未起動時: 承認リクエストはタイムアウトで deny（安全側に倒す）
- [x] メタデータ保護: mount 名前空間で `~/.config/seki/` を read-only bind mount
- [x] 起動時パーミッションチェック: git 方式でオーナー・権限を検証、不合格なら起動拒否
- [x] ホスト安全性: ホスト側の変更は veth pair のみ。iptables/sysctl/resolv.conf は触らない
- [x] NAT 不使用: iptables MASQUERADE の代わりに TCP プロキシで中継（ホスト iptables との干渉を排除）
- [x] DNS リダイレクト: resolv.conf bind mount ではなく、子の名前空間内の iptables DNAT で強制
- [x] UDP ブロック: DNS 以外の UDP は DROP（QUIC/HTTP3 による TCP プロキシ迂回を防止、TCP フォールバックで SNI 捕捉可能に）

### 未決

- [ ] **ログのストレージ**: SQLite か plaintext か。review TUI との相性で SQLite が有力
- [ ] **WSL2 固有の制約**: `unshare` の挙動、Windows 側ネットワークとの関係
- [ ] **Claude Code 以外への汎用性**: 他の AI コーディングツールでも使えるようにするか (設計上は exec の対象を問わない)
- [ ] **DNS リゾルバ実装**: Go の既存ライブラリ (miekg/dns 等) をそのまま使うか、最小限の自前実装か
