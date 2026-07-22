# bridges — loopback アドレス族ブリッジ（darwin backend）

sandbox 内のツールが「v6 loopback（`::1`）で待つサーバー」を要求するのに、実サーバーが
`127.0.0.1` にしか listen していない（またはその逆）とき、seki がホスト側に TCP
フォワーダを立てて橋渡しする。sandbox の起動時に張られ、終了時に閉じる。

## 背景（実例: adb / 公式 android CLI）

- adb server は `127.0.0.1:5037` にのみ listen する
- 公式 `android` CLI は sandbox 内から `[::1]:5037` への接続を要求する
- darwin backend は netns を持たない（Seatbelt のみ）ので、ホスト側に
  `[::1]:5037 → 127.0.0.1:5037` のフォワーダを置けば解決する
  （socat での手動検証済み — 2026-07-22、NOTES.local.md 参照）

## 設定

`~/.config/seki/config.json`:

```json
{
  "bridges": [
    {
      "name": "adb",
      "match": "~/projects/my-android-app*",
      "listen": "[::1]:5037",
      "connect": "127.0.0.1:5037"
    }
  ]
}
```

- `match` は services と同じ glob（cwd に対して判定、`~` 展開あり）。省略で全セッション適用
- `listen` が既に埋まっている場合（別 sandbox の bridge か実サーバー）はスキップして
  通知のみ。エラーにはしない

## 制約

- **darwin backend 専用**。linux backend は netns 隔離のため guest の `::1` はホストと
  別物であり、この仕組みでは届かない（必要になったら sandbox 内フォワーダとして別設計）
- bridge はホストのネットワークスタックを共有する = **sandbox スコープではなくホスト
  グローバル**。先に bridge を張った sandbox が終了すると、まだ使っている兄弟 sandbox
  からも消える（次の sandbox 起動で再生成される）
- 転送先がいない場合、接続は accept 後に静かに閉じる（起動順は気にしなくてよいが、
  実サーバーの起動は別途必要 — adb なら `adb start-server`）
