# seki サービス宣言機能 — sandbox 内常駐サービスのライフサイクル管理

## 背景（解く問題）

- sandbox 内で `podman system service` 等のデーモンを毎回手で起動している。手間に加え、sandbox 終了後もデーモンが幽霊プロセスとして残る
- 構造的原因: seki は CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWNS のみで **PID namespace を作らない**。sandbox の終了（プロセスチェーンの終了）と内部デーモンの生存が結びついていない
- 解決方針: namespace を作る張本人（seki）が、その中のデーモンのライフサイクルも所有する。config に宣言されたサービスを sandbox 起動時に spawn し、終了時に道連れにする。PID namespace 追加により「道連れ」をカーネル保証にする

## 成果物

1. `internal/profile/profile.go` — `GlobalConfig` に `Services []Service` を追加
2. `cmd/seki/main.go` — `cmdNsExec()` の supervisor モード（services 宣言時のみ）
3. `cmd/seki/main.go` `cmdChild()` — services 宣言時のみ `__ns-exec` の spawn に CLONE_NEWPID を追加
4. `internal/profile/profile_test.go` — config パースの unit test 追加
5. `DESIGN.md` — サービス宣言セクション追記
6. `~/.config/seki/config.json` への Podman 用サンプル設定（ドキュメント内に記載。実ファイルは変更しない）

## 技術方針

### config schema

`~/.config/seki/config.json` の GlobalConfig に追加:

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

- `name` (必須): 識別子。ログファイル名等に使う
- `match` (任意): cwd ベースのプロジェクトマッチ。指定時は cwd が一致する sandbox でのみこのサービスを起動する。マッチング規則は既存の `claude_profiles`（`profile.Config.Resolve` / ProjectMapping.Match）と同一の意味論を流用すること（~ 展開等も同じ挙動に揃える。共通化できるならヘルパーを切り出して両方から使う）。省略時は全セッションに適用
- **マッチ後のサービスがゼロ件なら services 未宣言と完全に同じ扱い**: supervisor にならず現行の syscall.Exec パス、CLONE_NEWPID も付与しない。cmdNsExec と cmdChild の両方で同じマッチ判定（同じ cwd）を行い、判定が食い違わないようにする（判定ロジックは profile パッケージに置いて共有する）
- `command` (必須): argv 配列。シェル経由にしない（exec.Command 直）
- `ready_socket` (任意): このパスに unix socket が現れる（= connect できる）まで待ってからユーザーコマンドを起動。`os.ExpandEnv` で環境変数展開
- `ready_timeout_sec` (任意, default 15): readiness 待ちの上限。超えたら警告を stderr に出してそのまま続行（ユーザーコマンドをブロックしない）
- `stop_command` (任意): shutdown 時、SIGTERM の**前**に同期実行するクリーンアップコマンド（例: コンテナ全停止）。timeout 10s
- `env` (任意): サービス専用の追加環境変数。ベースは os.Environ()（sandbox_env は buildChildEnv 経由で既に入っている）

### 挿入点とプロセスモデル

プロセスチェーン: `seki exec` → `__child`（outer ns, uid 0, ChildSetup で DNS/proxy）→ `__ns-exec`（inner userns + mountns, ambient caps, Podman が動く場所）→ syscall.Exec でユーザーコマンドに変身。

**services が空の場合は現行の syscall.Exec パスを一切変更しない（ゼロ挙動変化）。**

services が宣言されている場合、`cmdNsExec()` は exec せず supervisor として常駐する:

1. 現行のセットアップ（rshared, tmpfs, newuidmap bind, setupPodmanConfig）をそのまま実施
2. 各サービスを起動: `exec.Command`, `SysProcAttr{Setpgid: true}`（サービスごとに独立 pgid）、stdout/stderr はログファイルへ
3. `ready_socket` があれば `net.Dial("unix", path)` リトライループで readiness を待つ
4. ユーザーコマンドを子プロセスとして起動（Setpgid **しない** — supervisor と同じ foreground pgrp に置き、Ctrl-C が直接届くようにする）。stdin/stdout/stderr は素通し
5. ユーザーコマンド終了後、逆順で各サービスを shutdown:
   - `stop_command` があれば同期実行（timeout 10s）
   - サービスの pgid に SIGTERM → 最大 5s 待つ → 残っていれば SIGKILL
6. ユーザーコマンドの exit code で exit

### CLONE_NEWPID（道連れのカーネル保証）

- `cmdChild()` の `__ns-exec` spawn（main.go:251-261 の SysProcAttr）に、**services 宣言時のみ** `CLONE_NEWPID` を追加。supervisor が pid 1 になる
- supervisor 終了 = pid namespace 内全プロセスに SIGKILL。conmon 等の double-fork デーモンも逃げられない
- `cmdNsExec()` で `/proc` を remount する: `syscall.Mount("proc", "/proc", "proc", 0, "")`（CLONE_NEWNS 済み + ambient CAP_SYS_ADMIN があるので可能）。これがないと ps / podman が外側 pidns の /proc を見て混乱する
- **pid 1 の責務（zombie reaping）**: orphan が re-parent されてくるので reap が必要。`cmd.Wait()` と `wait4(-1)` の併用は status を奪い合うため、ユーザーコマンドも `cmd.Start()` のみで起動し、自前の `syscall.Wait4(-1, ...)` ループで全員を回収する。回収した pid がユーザーコマンドの pid なら exit status を記録。サービスの pid なら早期死亡として警告ログ
- **signal**: supervisor は SIGINT を無視（同じ foreground pgrp なのでユーザーコマンドに直接届く）。SIGTERM は受けたらユーザーコマンドへ転送
- **フォールバック**: もし CLONE_NEWPID + /proc remount で Podman rootless が動かない場合（機能テストで判明したら）、CLONE_NEWPID を外して supervisor の pgid kill + stop_command のみで出荷する。その場合は判断ログに理由を残すこと

### サービスログ

- 各サービスの stdout/stderr は `~/.cache/seki/services/<name>.log` に append（ディレクトリは MkdirAll）。HOME はホストと共有なので sandbox 終了後もデバッグ可能
- 起動時にタイムスタンプ付きの開始マーカー行を書く

### 設定ロード

- `cmdNsExec()` 内で `profile.LoadGlobalConfig()` を呼ぶ（HOME はホスト共有なので読める）。エラー時は services なし扱いで現行パスへ
- non-subuid フォールバックパス（cmdChild の else 分岐、main.go:304-330）は `__ns-exec` を経由しないため services 非対応。services が宣言されていたら stderr に「subuid がないため services は起動しません」と警告

## 参照

- `cmd/seki/main.go:145-204` — cmdNsExec（挿入点。最後の syscall.Exec を条件分岐に）
- `cmd/seki/main.go:206-331` — cmdChild（CLONE_NEWPID 追加箇所は 251-261 の SysProcAttr）
- `cmd/seki/main.go:1375-1395` — setupPodmanConfig（既存の Podman 対応の前例）
- `internal/profile/profile.go` — GlobalConfig / LoadGlobalConfig（schema 追加箇所）
- `internal/profile/profile_test.go` — テストの前例
- `internal/netns/netns.go:53-` — Exec（外側の clone。ここは触らない）、`:1043-` buildChildEnv（sandbox_env が環境変数に入る経路）
- 経緯: 2026-06-02 に rshared 化を cmdNsExec に移動済み（Podman rootless の mount propagation 要件）。この上に積む。mount 順序を崩さないこと

## 制約

- **services 未宣言時の挙動は完全に現状維持**（exec チェーン、クローンフラグとも変更なし）。dogfooding 中の環境を壊さない
- 外部依存を増やさない（Go 標準ライブラリ + 既存の golang.org/x/sys のみ）
- サブエージェントの worktree isolation は使わない。main worktree 上で直接作業
- `~/.config/seki/config.json` 実ファイルは変更しない（ユーザーが自分で services を足す。サンプルは DESIGN.md に書く）
- シェル文字列のパースはしない（command は argv 配列のみ。seki の設計思想: 文字列パースは難読化で突破される）

## 完了条件

- `go build ./...` 通過
- `go test ./...` 通過（profile の config パーステスト含む）
- `go vet ./...` 通過
- **E2E（このセッションは sandbox 内 = SEKI_ACTIVE=1 なのでネスト制約あり）**: 可能なら一時 config で `seki exec -- sh -c '...'` を **Bash の timeout 同期実行**で試し、(1) サービスが起動する (2) ユーザーコマンド終了後にサービスプロセスが残らない、を `ps` で確認する。テスト用サービスは `sleep 1000` のような単純なもので良い（Podman 不要）。HOME の config を汚さないため `HOME=/tmp/seki-test-home` 等で隔離した config を使うこと
- ネスト実行が環境的に不可能なら、その旨と「ユーザーが make install 後に新しい sandbox で確認すべき手順」をサマリーに明記して done とする（blocked にはしない）
- unit test 通過だけで done にしない。E2E の実施結果（または不可能の根拠）を必ず報告に含める

## 実装ステップ

1. `internal/profile/profile.go` に `Service` struct と `GlobalConfig.Services` を追加。`profile_test.go` にパーステスト追加
2. `cmd/seki/main.go` に supervisor 実装（サービス起動 / readiness / reaping ループ / shutdown）。cmdNsExec の末尾を「services なし → 現行 syscall.Exec / あり → supervisor」に分岐
3. `cmdChild()` に services 有無の判定を追加し、宣言時のみ CLONE_NEWPID を付与（cmdNsExec 側の /proc remount とセット）。non-subuid パスに警告を追加
4. ビルド + unit test + vet
5. E2E（上記完了条件のとおり。timeout 同期実行）
6. `DESIGN.md` にサービス宣言セクションを追記（schema、Podman サンプル、PID namespace による道連れ保証の説明）
