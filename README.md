# seki — Claude Code 向けネットワーク関所

Claude Code の全アウトバウンド通信を DNS+SNI で検問するネットワークサンドボックス。
このドキュメントは新環境のセットアップガイド。インストール → 設定ファイル配置 →
learning mode で観察 → enforce 移行、の順に進める。
設計の背景は [DESIGN.md](DESIGN.md) を参照。現時点で対応環境は Linux のみ。
Mac ネイティブ対応（Seatbelt backend）は設計済み・実装前 — DESIGN.md「macOS ネイティブ対応」を参照
（旧 VM アプローチ [docs/macos.md](docs/macos.md) は破棄）。

## 1. インストール

```bash
# リポジトリから
make install          # go build → ~/.local/bin/seki

# またはビルド済みバイナリ（dist/）を配置
cp dist/seki-linux-amd64 ~/.local/bin/seki
```

依存（Linux ネイティブ）:

- `slirp4netns` — ユーザーモードネットワーク（必須）
- `newuidmap` / `newgidmap`（uidmap パッケージ）— rootless namespace 用
- `/etc/subuid`, `/etc/subgid` に自分のエントリがあること（サービス宣言機能に必要）

```bash
# 動作確認
seki exec -- curl -s https://example.com   # rules 未設定なら learning mode で通る
```

## 2. 設定ファイルの全体像

すべて `~/.config/seki/` 配下、**JSON 形式**。同梱サンプルはないので、このガイドの
プリセット（§4, §5）をコピーして作る。

| ファイル | 中身 | いつ触るか |
|----------|------|-----------|
| `rules.json` | ネットワークルール + コマンドルール + `host_ports` + `learning_mode` | 日常的（`seki rules add` で育てる） |
| `config.json` | Claude プロファイル切り替え / `sandbox_env` / サービス宣言 | 環境構築時 |
| `credentials.json` | git credential / SSH agent forward の宣言 | 環境構築時 |

`rules.json` は sandbox 内から read-only bind mount されるため、sandbox 内の
プロセスは改ざんできない。編集はホスト側から行う。

## 3. 初回セットアップの流れ

```bash
# 1. プリセットを配置（§6 の完全版をコピー）
mkdir -p ~/.config/seki
$EDITOR ~/.config/seki/rules.json

# 2. learning mode で通常作業を数セッション回す
seki mode learning
seki watch                # 別端末で観察。未知の通信先がログに出る

# 3. 出てきたドメインをルール化
seki rules add "registry.npmjs.org" --allow --tag package
seki rules add "*.example-cdn.com" --allow

# 4. 落ち着いたら enforce へ
seki mode enforce
```

- learning mode では deny/prompt にマッチしても遮断せずログのみ。まずここで
  プロジェクト固有の通信先を洗い出す
- ルールは保存時に specificity 順（完全一致 > CIDR > `*.domain` > `*`）に自動整列される
- Claude Code との連携: `PreToolUse` hook に `seki hook pre-bash` を登録すると
  コマンド承認レイヤーが効く

## 4. ネットワークルール（ホワイトリスト・デフォルト deny）

- **マッチング**: ドメインはグロブ（`*.example.com` = サブドメインのみ、`example.com` = 完全一致。両方欲しければ 2 行書く）。IP は CIDR / 単一 IP
- **action**: `allow` / `deny` / `prompt`（prompt は `seki watch` の承認キューへ。タイムアウト時 deny）
- CLI: `seki rules add <match> --allow|--deny|--prompt [--tag <tag>]` / `seki rules list` / `seki rules remove <match>`

### 必須プリセット（これがないと Claude Code 自体が動かない）

| match | tag | 理由 |
|-------|-----|------|
| `*.anthropic.com` | anthropic | API 本体 |
| `claude.com` / `code.claude.com` / `platform.claude.com` | anthropic | ドキュメント・配信 |
| `downloads.claude.ai` | anthropic | 自動アップデート |
| `github.com` / `*.github.com` | git | clone / push |
| `raw.githubusercontent.com` / `gist.githubusercontent.com` / `release-assets.githubusercontent.com` | git | raw 取得・リリースアセット |
| `127.0.0.0/8` / `::1/128` | loopback | dev server 等 |
| `10.0.0.0/8` / `172.16.0.0/12` / `192.168.0.0/16` | private | LAN 内サービス |

### 開発スタック別（使う言語だけ入れる）

| スタック | ドメイン |
|----------|---------|
| npm | `registry.npmjs.org` |
| Python | `pypi.org`, `files.pythonhosted.org` |
| Go | `proxy.golang.org`, `sum.golang.org`, `vuln.go.dev` |
| Gradle/Maven | `repo.maven.apache.org`, `plugins.gradle.org`, `plugins-artifacts.gradle.org`, `services.gradle.org`, `repo.gradle.org`, `dl.google.com`, `jitpack.io` |
| Docker | `registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com` |
| ドキュメント参照 | `developer.mozilla.org`, `zenn.dev`, `docs.rs` など随時 |

### catch-all

末尾に必ずこれを置く。未知の通信先は watch で対話承認になる（`deny` にすると
即遮断。無人運用なら deny、対話運用なら prompt）:

```json
{ "match": "*", "action": "prompt" }
```

## 5. コマンドルール（ブラックリスト・デフォルト allow）

ネットワーク層と逆で、**マッチしなければ allow**。危険操作パターンだけを列挙する。

- **マッチング**: Go 正規表現（JSON 内なので `\b` は `\\b` にエスケープ）
- `"kind": "command"` を付ける。CLI では `--command` フラグ
- 評価はファーストマッチ。**deny を prompt より先に**書く（例: `git push --force` deny → `git push` prompt の順）
- prompt は `seki watch` の承認キューへ。`SEKI_APPROVAL_TIMEOUT`（デフォルト 30 秒）超過で deny

### 必須プリセット

dogfooding で確立した実戦セット。新環境ではこれを丸ごと入れる。

**デプロイ・公開系（prompt = 都度承認）**

```json
{ "match": "\\bgit\\b.*\\bpush\\b.*--force", "action": "deny",   "tag": "deploy", "kind": "command" },
{ "match": "\\bgit\\b.*\\bpush\\b",          "action": "prompt", "tag": "deploy", "kind": "command" },
{ "match": "^npm publish",                    "action": "prompt", "tag": "deploy", "kind": "command" },
{ "match": "^npx.*publish",                   "action": "prompt", "tag": "deploy", "kind": "command" },
{ "match": "^(sam|cdk) deploy",               "action": "prompt", "tag": "deploy", "kind": "command" },
{ "match": "^terraform apply",                "action": "prompt", "tag": "deploy", "kind": "command" },
{ "match": "^aws cloudformation (deploy|create-stack|update-stack)", "action": "prompt", "tag": "deploy", "kind": "command" }
```

**破壊系（deny = 無条件拒否）**

```json
{ "match": "^(sam delete|cdk destroy|terraform destroy)", "action": "deny", "tag": "destroy", "kind": "command" },
{ "match": "^aws .* (delete-|terminate-|remove-)",        "action": "deny", "tag": "destroy", "kind": "command" },
{ "match": "^aws s3 (rm|rb)",                             "action": "deny", "tag": "destroy", "kind": "command" }
```

**外部への書き込み HTTP**

```json
{ "match": "^(curl|wget).*-X\\s*(POST|PUT|DELETE|PATCH)", "action": "prompt", "tag": "http-write", "kind": "command" }
```

**GitHub 書き込み（組み込み policy で一括適用可）**

```bash
seki rules policy gh-write
```

適用内容: `gh pr/issue の create/merge/close/...` prompt、`gh release/repo/gist/label の
create/delete/...` prompt、`gh api -X POST/PUT/PATCH/DELETE` prompt。

**パッケージマネージャ（システム汚染防止）**

```json
{ "match": "^(sudo\\s+)?(apt|apt-get)\\s+install",   "action": "deny",   "tag": "pkg-manager", "kind": "command" },
{ "match": "npm\\s+(i|install)\\b.*(-g|--global)",   "action": "deny",   "tag": "pkg-manager", "kind": "command" },
{ "match": "^gem\\s+install",                         "action": "deny",   "tag": "pkg-manager", "kind": "command" },
{ "match": "^go\\s+install\\s+\\S+@",                 "action": "prompt", "tag": "pkg-manager", "kind": "command" },
{ "match": "^pip3?\\s+install",                       "action": "prompt", "tag": "pkg-manager", "kind": "command" },
{ "match": "^cargo\\s+install",                       "action": "prompt", "tag": "pkg-manager", "kind": "command" }
```

### 環境固有プリセット（該当環境のみ）

**NixOS**: 宣言的管理を迂回する操作を全 deny。

```json
{ "match": "^\\s*nix\\s",          "action": "deny", "tag": "nix", "kind": "command" },
{ "match": "^\\s*home-manager\\s", "action": "deny", "tag": "nix", "kind": "command" },
{ "match": "^\\s*nix-env\\s",      "action": "deny", "tag": "nix", "kind": "command" },
{ "match": "^\\s*nix-store\\s",    "action": "deny", "tag": "nix", "kind": "command" },
{ "match": "^\\s*nix-build\\s",    "action": "deny", "tag": "nix", "kind": "command" },
{ "match": "^nix\\s+develop\\b",   "action": "allow", "tag": "nix", "kind": "command" }
```

注意: `nix develop` を許可する場合、allow ルールを deny より**前**に置くこと
（ファーストマッチのため）。

**git worktree 禁止**（worktree 作成時に main の HEAD が巻き戻る事故の前歴あり）:

```json
{ "match": "\\bgit\\b.*\\bworktree\\b", "action": "deny", "tag": "worktree", "kind": "command" }
```

## 6. ポート解放 — `forward` と `host-port` は方向が逆

混同しやすいので対比で覚える:

| | `seki forward <port>` | `seki host-port add <port>` |
|---|---|---|
| 方向 | **ゲスト → ホストに公開**（sandbox 内の dev server をホストから見る） | **ホストへの到達を許可**（sandbox からホストの localhost サービスに繋ぐ） |
| 永続化 | されない（セッション限り） | `rules.json` の `host_ports` に永続化 |
| ホスト側ポート | 空きポート自動割り当て（guest と別番号） | 指定ポートそのまま |
| 実行場所 | sandbox 内（`SEKI_ACTIVE` 環境下） | どちらでも可（稼働中セッションにも即反映） |

### dev server を起動したら（頻出パターン）

```bash
# sandbox 内で
npm run dev &            # guest:3000 で待受
seki forward 3000
# → forwarding guest:3000 → localhost:52341
#   ホストのブラウザでは localhost:52341 を開く
```

network namespace 隔離のため、`seki forward` なしではホストから一切到達できない。
**割り当てられた localhost ポート番号を必ず確認すること**（guest ポートと違う番号になる）。

### ホスト側の常駐サービスに繋ぎたいとき

```bash
# 例: ホストで動く Chrome CDP (9222) に sandbox 内の agent-browser から繋ぐ
seki host-port add 9222
```

実績のある登録例: `9222`（Chrome CDP）、`8389` / `9999`（ローカル API）。

## 7. config.json — プロファイル / 環境変数 / サービス

```json
{
  "claude_profiles": {
    "default": "personal",
    "projects": [
      { "match": "/home/me/projects/work-*", "profile": "work" }
    ]
  },
  "sandbox_env": {
    "DOCKER_HOST": "unix:///run/user/1000/podman/podman.sock",
    "TESTCONTAINERS_RYUK_DISABLED": "true"
  },
  "services": [
    {
      "name": "podman-api",
      "match": "/home/me/projects/needs-docker-*",
      "command": ["podman", "system", "service", "--time=0"],
      "ready_socket": "$XDG_RUNTIME_DIR/podman/podman.sock",
      "ready_timeout_sec": 15
    }
  ]
}
```

- `claude_profiles`: cwd のグロブで Claude Code の設定プロファイルを切り替える
- `sandbox_env`: sandbox 内プロセスに注入する環境変数
- `services`: sandbox 内常駐サービス。`match` にマッチした cwd のセッションだけ起動。
  PID namespace で sandbox 終了時に道連れ保証。ログは `~/.cache/seki/services/<name>.log`。
  詳細は [recipes/services.md](recipes/services.md)

## 8. rules.json 完全プリセット（コピペ用）

新環境ではこれを `~/.config/seki/rules.json` に置いて `learning_mode: true` から始める:

```json
{
  "rules": [
    { "match": "*.anthropic.com", "action": "allow", "tag": "anthropic" },
    { "match": "claude.com", "action": "allow", "tag": "anthropic" },
    { "match": "code.claude.com", "action": "allow", "tag": "anthropic" },
    { "match": "platform.claude.com", "action": "allow", "tag": "anthropic" },
    { "match": "downloads.claude.ai", "action": "allow", "tag": "anthropic" },
    { "match": "github.com", "action": "allow", "tag": "git" },
    { "match": "*.github.com", "action": "allow", "tag": "git" },
    { "match": "raw.githubusercontent.com", "action": "allow", "tag": "git" },
    { "match": "gist.githubusercontent.com", "action": "allow", "tag": "git" },
    { "match": "release-assets.githubusercontent.com", "action": "allow", "tag": "git" },
    { "match": "registry.npmjs.org", "action": "allow", "tag": "package" },
    { "match": "pypi.org", "action": "allow", "tag": "package" },
    { "match": "files.pythonhosted.org", "action": "allow", "tag": "package" },
    { "match": "proxy.golang.org", "action": "allow", "tag": "package" },
    { "match": "sum.golang.org", "action": "allow", "tag": "package" },
    { "match": "127.0.0.0/8", "action": "allow", "tag": "loopback" },
    { "match": "::1/128", "action": "allow", "tag": "loopback" },
    { "match": "10.0.0.0/8", "action": "allow", "tag": "private" },
    { "match": "172.16.0.0/12", "action": "allow", "tag": "private" },
    { "match": "192.168.0.0/16", "action": "allow", "tag": "private" },
    { "match": "*", "action": "prompt" },

    { "match": "\\bgit\\b.*\\bpush\\b.*--force", "action": "deny", "tag": "deploy", "kind": "command" },
    { "match": "\\bgit\\b.*\\bpush\\b", "action": "prompt", "tag": "deploy", "kind": "command" },
    { "match": "^npm publish", "action": "prompt", "tag": "deploy", "kind": "command" },
    { "match": "^npx.*publish", "action": "prompt", "tag": "deploy", "kind": "command" },
    { "match": "^(sam|cdk) deploy", "action": "prompt", "tag": "deploy", "kind": "command" },
    { "match": "^terraform apply", "action": "prompt", "tag": "deploy", "kind": "command" },
    { "match": "^aws cloudformation (deploy|create-stack|update-stack)", "action": "prompt", "tag": "deploy", "kind": "command" },
    { "match": "^(sam delete|cdk destroy|terraform destroy)", "action": "deny", "tag": "destroy", "kind": "command" },
    { "match": "^aws .* (delete-|terminate-|remove-)", "action": "deny", "tag": "destroy", "kind": "command" },
    { "match": "^aws s3 (rm|rb)", "action": "deny", "tag": "destroy", "kind": "command" },
    { "match": "^(curl|wget).*-X\\s*(POST|PUT|DELETE|PATCH)", "action": "prompt", "tag": "http-write", "kind": "command" },
    { "match": "^(sudo\\s+)?(apt|apt-get)\\s+install", "action": "deny", "tag": "pkg-manager", "kind": "command" },
    { "match": "npm\\s+(i|install)\\b.*(-g|--global)", "action": "deny", "tag": "pkg-manager", "kind": "command" },
    { "match": "^gem\\s+install", "action": "deny", "tag": "pkg-manager", "kind": "command" },
    { "match": "^go\\s+install\\s+\\S+@", "action": "prompt", "tag": "pkg-manager", "kind": "command" },
    { "match": "^pip3?\\s+install", "action": "prompt", "tag": "pkg-manager", "kind": "command" },
    { "match": "^cargo\\s+install", "action": "prompt", "tag": "pkg-manager", "kind": "command" }
  ],
  "host_ports": [],
  "learning_mode": true
}
```

配置後に `seki rules policy gh-write` で GitHub 書き込み系も追加する。
enforce への移行は数セッション観察してから `seki mode enforce`。
