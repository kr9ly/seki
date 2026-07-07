# seki を Mac で使う

> **⚠️ このアプローチは破棄された（2026-07）**
>
> 本ドキュメントの Apple container / seki-mac 方式（Linux VM 内で seki + Claude を動かす）は、
> 開発環境として成立しないと判断し破棄した。ワーキングツリーが常に共有 FS 上に置かれること、
> VM 内の構成管理が Mac 側と二重化すること、iOS ビルド・Safari 検証等の darwin ネイティブ
> 開発が射程外になることが理由。
>
> 後継は **darwin ネイティブバイナリ + Seatbelt (sandbox-exec) + 明示プロキシ** の
> darwin backend。設計は [DESIGN.md「macOS ネイティブ対応（darwin backend）」](../DESIGN.md#macos-ネイティブ対応darwin-backend) を参照。
> 以下は歴史的経緯として残す。

## 結論

seki のネットワーク隔離は Linux 固有機構の上に建っている:

| seki の依存 | 用途 | macOS での代替 |
|-------------|------|----------------|
| user / net / PID namespace | rootless sandbox | なし |
| iptables REDIRECT + SO_ORIGINAL_DST | sandbox 内の透過プロキシ | なし |
| slirp4netns | sandbox の外向きネットワーク | なし |
| SO_PEERCRED | UNIX ソケットのピア認証 | 別 API（LOCAL_PEERCRED） |

このため **macOS ネイティブの darwin バイナリは提供しない**（コンパイルも通らない）。
Mac では **Apple container の Container Machine（軽量 Linux VM）内で linux/arm64 バイナリを動かす**。

Apple container 同梱カーネルの config は確認済みで、seki の要求をすべて満たす:
`CONFIG_USER_NS=y` `CONFIG_NET_NS=y` `CONFIG_PID_NS=y` `CONFIG_TUN=y`
`CONFIG_NF_NAT=y` `CONFIG_IP_NF_NAT=y` `CONFIG_NETFILTER_XT_TARGET_REDIRECT=y`
`CONFIG_NF_CONNTRACK=y` `CONFIG_NFT_COMPAT=y`

## 要件

- Apple Silicon Mac
- macOS 26 以降（Apple container v1.0.0 の要件）
- [apple/container](https://github.com/apple/container) v1.0.0+

macOS 26 未満 / Intel Mac の場合は [Lima フォールバック](#lima-フォールバックmacos-26-未満--intel-mac) を参照。

## ワンコマンド起動（seki-mac）

手動セットアップの代わりに、[`scripts/seki-mac`](../scripts/seki-mac) を Mac に置けば
マシン作成・ミドルウェア投入・起動まで一発で通る:

```bash
curl -fsSL -o ~/.local/bin/seki-mac \
  https://github.com/kr9ly/seki/releases/latest/download/seki-mac
chmod +x ~/.local/bin/seki-mac

cd ~/projects/myapp
seki-mac              # sandbox 内で claude 起動（初回はマシン作成 + provision）
seki-mac watch        # 別ターミナルで監視 UI
seki-mac shell        # マシン内シェル
seki-mac provision    # ミドルウェア再投入（seki 更新時など）
```

初回はマシン作成 + apt + Node/Claude Code インストールで数分かかる。2 回目以降は即起動。
マシン名やリソースは `SEKI_MACHINE` / `SEKI_CPUS` / `SEKI_MEMORY` 環境変数で変えられる。
以下のセットアップ手順は、seki-mac が中でやっていることの手動版 + 解説である。

## ホストファイルへのアクセス

**sandbox 内から Mac のファイルは自由に読み書きできる。**

- Container Machine は Mac の `$HOME` を read-write で自動マウントする
  （マシン内でも同じ `/Users/<username>` パスで見える）
- seki の sandbox はネットワーク出口だけを制御し、ファイルシステムは制限しない。
  これは設計判断（DESIGN.md 参照）: 守るべきは情報の流出であって、ローカルファイルの
  破壊は git で復元できる。ファイルを読まれても、ネットワーク出口が塞がれていれば流出しない

つまり Mac 側のエディタで開いているリポジトリを、sandbox 内の Claude Code が
そのまま編集する。パス変換も同期も不要。
ただし共有されるのは `$HOME` 配下のみ（`seki-mac` は `$HOME` 外のディレクトリでの起動を拒否する）。

## セットアップ

### 1. Apple container のインストール

[apple/container の Releases](https://github.com/apple/container/releases) から installer pkg を取得してインストールし、システムサービスを起動する:

```bash
container system start
```

### 2. Container Machine の作成

```bash
container machine create ubuntu:24.04 --name seki-dev
container machine set -n seki-dev cpus=4 memory=8G
container machine run -n seki-dev        # インタラクティブシェルに入る
```

Container Machine は macOS 側のユーザー名とホームディレクトリを自動共有する。
リポジトリは Mac 側の `$HOME` に置いたまま、マシン内の `/Users/<username>` から見える。

### 3. マシン内ミドルウェアのインストール

マシン内で:

```bash
sudo apt update
sudo apt install -y slirp4netns iptables ca-certificates curl
```

| パッケージ | 必須度 | 用途 |
|-----------|--------|------|
| slirp4netns | **必須** | sandbox netns の外向きネットワーク |
| iptables | **必須** | sandbox 内の透過 REDIRECT ルール |
| uidmap | 任意 | サービス宣言機能でネスト Podman を使う場合のみ（`/etc/subuid` エントリも必要） |

**Ubuntu 24.04 の注意**: AppArmor が非特権 user namespace を制限している場合がある。
`seki exec` が namespace 作成で失敗したら:

```bash
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
# 永続化
echo 'kernel.apparmor_restrict_unprivileged_userns=0' | sudo tee /etc/sysctl.d/99-seki.conf
```

### 4. seki バイナリの導入

```bash
mkdir -p ~/.local/bin
curl -fsSL -o ~/.local/bin/seki \
  https://github.com/kr9ly/seki/releases/latest/download/seki-linux-arm64
chmod +x ~/.local/bin/seki
export PATH="$HOME/.local/bin:$PATH"   # .bashrc / .zshrc にも追記
```

バイナリは CGO なしの静的リンクなので、glibc バージョンを問わず動く。
検証するなら Releases の `SHA256SUMS` と照合する。

### 5. Claude Code のインストール

マシン内で通常どおりインストールする（Node.js 系のインストール手順に従う）。
認証プロファイルは sandbox 内で初回 `claude login` するだけでよい（DESIGN.md「プロファイル」参照）。

### 6. seki の設定

- 設定ファイル: `~/.config/seki/config.json`
- ルール追加: `seki rules add <match> --allow|--deny|--prompt [--tag <tag>] [--command]`
- コマンド承認レイヤーは Claude Code の hooks（PreToolUse → `seki hook pre-bash`）と連携する

設計と全体像は [DESIGN.md](../DESIGN.md) を参照。

### 7. 実行

```bash
# sandbox 内で Claude Code を起動
seki exec -- claude

# 別ターミナル（Mac 側でもう一つ container machine run -n seki-dev）で監視
seki watch
```

### 8. dev server への到達（ポートフォワードのチェーン）

sandbox 内で dev server を立てた場合、Mac のブラウザから届くまでに 2 段のチェーンがある:

```
Mac ブラウザ → ② Container Machine の IP → ① seki forward → sandbox 内 dev server
```

1. **sandbox → マシン**: sandbox 内で `seki forward <guest-port>` を実行。
   マシン側 localhost の空きポートに転送される（出力されたポート番号を控える）
2. **マシン → Mac**: `container machine inspect seki-dev` でマシンの IP を確認し、
   Mac 側から `http://<マシンIP>:<ホスト側ポート>` にアクセスする
   （vmnet ネットワーク上のマシン IP は macOS ホストから直接到達できる）

## 動作検証チェックリスト

このガイドは Linux (WSL2) 上で作成した。カーネル config の静的確認は済んでいるが、
**Mac 実機での実行検証は未実施**。初回セットアップ時に以下を順に確認すること:

```bash
# 1. 非特権 user namespace が作れるか
unshare -Un true && echo OK

# 2. tun デバイスがあるか（slirp4netns が必要とする）
ls -l /dev/net/tun

# 3. seki sandbox が起動するか
seki exec -- true && echo OK

# 4. sandbox 内から許可ドメインに疎通するか（ルール設定後）
seki exec -- curl -sS https://api.anthropic.com/ -o /dev/null -w '%{http_code}\n'
```

つまずいた場合の見どころ:

- 1 が失敗 → AppArmor 制限（手順 3 の sysctl）
- 2 が失敗 → `sudo mknod /dev/net/tun c 10 200`（カーネル自体は CONFIG_TUN=y）
- 3 が失敗 → `seki log` でエラー確認。slirp4netns / iptables の有無を疑う

## Lima フォールバック（macOS 26 未満 / Intel Mac）

Apple container が使えない環境では [Lima](https://lima-vm.io/) で同等の構成が組める:

```bash
brew install lima
limactl start template://ubuntu --name seki-dev
limactl shell seki-dev
```

以降はセットアップ手順 3〜8 と同じ。Intel Mac の場合はバイナリを
`seki-linux-amd64` に読み替える。Lima はデフォルトで `$HOME` を
読み取り専用マウントするので、書き込みが必要なら lima.yaml の `writable: true` を設定する。

## クロスコンパイル手順（開発者向け）

sqlite が modernc の pure-Go 実装のため CGO 不要。任意のホストからワンコマンドで出る:

```bash
make release
# → dist/seki-linux-arm64, dist/seki-linux-amd64, dist/SHA256SUMS
```

darwin ターゲットは冒頭の表のとおりコンパイル不能（`SO_PEERCRED`, `SOL_IP` 等が未定義）。
Mac 対応 = linux/arm64 バイナリ + Linux VM であって、darwin ビルドではない。
