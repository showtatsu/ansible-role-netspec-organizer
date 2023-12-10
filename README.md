# netspec-organizer : Ansible Role

現在のホストのネットワークインターフェースに設定されたIPアドレス情報を元に、
Ansible変数に記載したメタデータを検索し、マッチングを行い、
Ansible Factを更新する機能を提供するAnsible Roleです。

このRole自体にはターゲットホストの設定を更新する機能はありません。

このRoleから設定される `netspec` 変数を参考にして、
他のRoleでタスクを抽象化させることができます。

## Roleの目的

Ansibleで、ホストのネットワーク情報に応じて動的に設定を行うのは難易度が高いことです。

特にホストが接続されるネットワークにバリエーションがある場合、
どのNICでプロセスをListenさせるか、設定値に記載するアドレスを何にするか、などの処理を
汎用的に記載するのは容易ではありません。

例えば、下記のような要件です。

- `10.10.0.0/16`の範囲のIPアドレスを持つNICがいた場合、そのNICの所属するネットワークアドレスの先頭にあるGatewayに向けて`10.0.0.0/16`向けのルーティングテーブルを記載する
- `192.168.10.0/24`のネットワークに接続されたNICのIPアドレスにSSHDをBindする

他のRoleを開発するときに、これらの要件を比較的容易に達成できるようにするのがこのRoleの目的です。


# Role変数

`netspec_settings`および`netspec_override_settings`を使用して
ホストが接続されている周辺ネットワークの情報をRoleに提供してください。

その状態でRoleが読み込まれると、`netspec_interfaces`という名前の変数が設定されます。

### `netspec_settings` 設定値のサンプル

```
netspec_settings:
  network_1:
    match:
    - type: cidr
      value: "192.168.100.0/24"
    routes:
    - to: 192.168.0.0/24
      via: 1
    - to: 0.0.0.0/0
      via: -1
    dns_servers:
    - "8.8.8.8"
    - "8.8.4.4"
    dns_search:
    - "example.com"
```

## 設定値の説明

`netspec_settings` は、ネットワークに名前をつけて設定管理するための設定値で、
このRoleにおいて最も重要な変数です。

### netspec_settings.<ネットワーク名>

辞書型データでネットワークの情報を記載します。
ここに定義したネットワークに対して、各Interfaceが接続されているかどうかを、
InterfaceのIpアドレスを元に判定することになります。

以下、辞書データの各キーの説明です。

#### match - 検索条件

`match`キーは、インターフェースに設定されたIPアドレスにマッチする条件です。
条件を記載した **辞書データの配列** で記載します。

配列の各要素がマッチ条件を表し、それらがOR条件で適用されます。

マッチ条件には、CIDR形式(`type: cidr`)と、正規表現(`type: regex`)が使用できます。
記載した条件に適合するIPアドレスを持ったNICに対して、このネットワークが設定されていると判断されます。

```yaml
...
   match:
   - type: cidr
     value: 10.0.0.0/8
   - type: regex
     value: "^172\\.(20|22)\\."
```

#### routes - ルーティング情報

このネットワークに接続されているサーバが持っておくべきルーティングテーブルです。

ルーティング情報を表す **辞書データの配列** で記載します。

この項目については、複数のネットワークに接続されていると判定されたとき、すべてのネットワークに記載された値が有効です。

```yaml
    routes:
    - to: 192.168.0.0/16  # ルーティング先アドレス。CIDR形式で記載します。必須です
      via: 1  # ゲートウェイアドレス。IPアドレスまたは数値で記載します。必須です。数値記載の場合の詳細は別記
      metrics: 100  # メトリクス情報。数値で記載します。省略可能です
```

`via`はゲートウェイを表す値です。IPアドレスを直接記載することもできますが、
接続されたネットワークのネットワークアドレスからのオフセット値を表す数値も利用可能です。

例えば、NICのアドレスとプレフィックスサイズが `192.168.100.100/24`だったとして、
`match: {"type":"cidr", "value": "192.168.0.0/16"}` のネットワークはマッチしますが、
このネットワークに指定されたルーティング情報の`via`値が`1`の場合、ゲートウェイアドレスは`192.168.100.1`として自動解決されます。

マイナスの値を指定した場合、ブロードキャストアドレスからのオフセット値になります。
上記の条件で `via: -1` であれば、`192.168.100.254`として解決されます。

#### dns_servers - DNSサーバアドレス

このネットワークから利用するDNSサーバのアドレスです。
**IPアドレスを表す文字列を配列形式で** 指定します。

この項目については、複数のネットワークに接続されていると判定されたとき、すべてのネットワークに記載された値が有効です。

```yaml
    dns_servers:
    - "8.8.8.8"
    - "8.8.4.4"
```

#### dns_servers - DNSサーバアドレス

このネットワークから利用するDNSサーバでアドレスです。
**ドメインを表す文字列を配列形式で** 指定します。

この項目については、複数のネットワークに接続されていると判定されたとき、
すべてのネットワークに記載された値が有効です。

```yaml
    dns_search:
    - "example.com"
```

### netspec_override_settings

`netspec_override_settings` は、`netspec_settings`の設定値の一部を変更するための変数です。

他のRoleに組み込まれる際、Role側で`netspec_settings`を用いてデフォルトの設定値を提供しつつ、
細かい調整をRoleの利用者に行わせる場合に利用できます。

`netspec_override_settings`の書式は`netspec_settings`と同じですが、
`netspec_settings`の値とマージされる前提ですのでそれ自体に必須項目がありません。

`netspec_override_settings` から `netspec_settings` に対して定義がマージされる際のルールは下記の通りです。

- `netspec_settings`に対象のネットワーク自体が定義されていない場合は追加されます
- `netspec_settings`に対象のネットワークが定義されている場合、ネットワーク定義直下のキーでシャローコピーされます
    - `netspec_settings`側のネットワークに存在しないキーは追加されます
    - `netspec_settings`側のネットワークに存在するキーは置き換えられます

```yaml
netspec_settings:
  sample_net:
    match:
    - type: cidr
      value: "192.168.0.0/16"
    routes:
    - to: 192.168.0.0/16
      via: 1
    dns_servers:
    - "8.8.8.8"

netspec_override_settings:
  sample_net:
    routes:
    - to: 192.168.0.0/16
      via: 1
    - to: 172.20.100.0/24
      via: -1
    dns_search:
    - "net1.example.com"
  sample_net2:
    match:
    - type: cidr
      value: "192.168.200.0/24"
    routes:
    - to: 172.21.100.0/24
      via: -1
    dns_servers:
    - "1.1.1.1"
    dns_search:
    - "net2.example.com"
```

これらの値がマージされ、下記の定義がされたものとして処理されます。

```yaml
netspec_settings:
  sample_net:
    match:  # <-- overrideに定義されていないキーは維持されます
    - type: cidr
      value: "192.168.100.0/24"
    routes:  # <-- routesの値が置き換えられています (元のrouteの値は無効です)
    - to: 192.168.0.0/16 # 上書き前のルーティングテーブルが必要なら再掲する必要があります
      via: 1
    - to: 172.20.100.0/24
      via: -1
    dns_servers:  # <-- overrideに定義されていないキーは維持されます
    - "8.8.8.8"
    dns_search:  # <-- 定義されていなかったキーが値ごと追加されています
    - "net1.example.com"
  sample_net2: # 未定義であったネットワーク定義はそのまま追加されます
    match:
    - type: cidr
      value: "192.168.0.0/16"
    routes:
    - to: 172.21.100.0/24
      via: -1
    dns_servers:
    - "1.1.1.1"
    dns_search:
    - "net2.example.com"
```


## 追加されるFact値の説明

`netspec_interfaces`が追加されます。

これは、ホストが持つネットワークインターフェース情報（`lo`を除く）に、`netspec_settings`で定義したメタデータを追加したものです。
配列構造となっており、`ansible_interfaces`の値をコピーしたものに`netspec`のキーが追加され、
そこにマッチしたネットワークの情報を元にしたメタデータが設定されています。

## netspec_interfaces[].netspec

ネットワークインターフェースごとに、マッチしたネットワークの情報が`netspec`のエントリに追加されています。

### network_names

このNICにマッチしたネットワークの名前の一覧です。

### routing_table

`routes`に指定されていたルーティング情報です。
このNICに設定すべきルーティング情報の一覧が取得できます。


## `netspec_interfaces`に設定される変数のサンプル

```
"netspec_interfaces": [
  {
      **<ここにansible_interfacesの項目>,
      "netspec": {
          "dns_search": [
              "net1.example.com",
              "net2.example.com",
          ],
          "dns_servers": [
              "8.8.8.8",
              "8.8.4.4",
              "1.1.1.1"
          ],
          "interface": "ens192",
          "ipv4_default_route": null,
          "ipv6_default_route": null,
          "network_names": [
              "sample_net1",
              "sample_net2"
          ],
          "routing_table": [
              {
                  "gateway": "192.168.100.1",
                  "gateway_resolved": true,
                  "to": "192.168.0.0/16",
                  "via": "192.168.100.1"
              },
              {
                  "gateway": "192.168.100.254",
                  "gateway_resolved": true,
                  "to": "172.20.100.0/24",
                  "via": "192.168.100.254"
              },
              {
                  "gateway": "192.168.100.254",
                  "gateway_resolved": true,
                  "to": "172.21.100.0/24",
                  "via": "192.168.100.254"
              }
          ]
      },
  }
]
```
