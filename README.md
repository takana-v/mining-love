# mining-love
pythonで書かれたマイニングプールのプログラムです。  
報酬が直接マイナーに支払われるという特徴があります。

## 使い方
python3.7を使用してください。  
以下のモジュールが必要です。  

```
base58
tornado
zmq
コインのマイニングアルゴリズムのモジュール
```

PoolSetting.pyを編集します。  

```
HOST = '127.0.0.1' # 外部に公開するときは0.0.0.0
PORT_DIFF = [(3001,0.1)] # ポートと難易度のタプル
POOL_URL = 'test.mining.love'　# coinbaseにデータを埋め込みます
COIN_NAME = "bellcoin_regtest" # 下の表参照
FEE = "0" # 手数料(%)
FEE_TXOUT_SCRIPT = "17a914" + "2001320db3a2ea53a6ff91636c062eeb5aff3ae9" + "87"
BACKLOG = 8　# このままでいい
COIND = { # coindに合わせ適宜変更
      "coind_host": "127.0.0.1",
      "coind_rpcport": 19196,
      "coind_rpcuser": "user",
      "coind_rpcpassword": "pass",
      "coind_zmqport": 28334
      }
WEB_PORT = 8080 # webのポート nginxとか使って80,443ポートで公開するといい
WEB_EXPLORER_URL = "https://explorer.bellcoin.web4u.jp/block/" # エクスプローラーのURL（この後にblockhashが入る）
```
### FEE_TXOUT_SCRIPTについて
1.手数料などを受け取りたいアドレスを用意します。  
2.(p2pkhアドレスの場合)　以下のコードを実行

```
import base58
address = "" # 受け取りたいアドレス
print('\"1976a914\" + \"' + base58.b58decode_check(address).hex()[2:] + '\" + \"88ac\"')
```

(p2shアドレスの場合)　以下のコードを実行

```
import base58
address = "" # 受け取りたいアドレス
print('\"17a914\" + \"' + base58.b58decode_check(address).hex()[2:] + '\" + \"87\"')
```

表示された文字列がFEE_TXOUT_SCRIPTです。

coindのconfファイルを変更します。
（あくまでも一例、zmq関係はいる）

```
server=1
rpcallowip=127.0.0.1
rpcuser=user
rpcpassword=pass
rpcport=12345
zmqpubhashtx=tcp://127.0.0.1:23456
zmqpubhashblock=tcp://127.0.0.1:23456
```

## 対応コイン

| COIN_NAME | アルゴリズムのモジュール |
| ---- | ---- |
| bellcoin | https://github.com/bellcoin-electrum/bell_yespower_python3 |
| bellcoin_regtest | https://github.com/bellcoin-electrum/bell_yespower_python3 |

## コインの追加
PoolSetting.pyに以下の項目を追記してください。  

```
UNIT -> そのコインの単位
DIFF1_TARGET -> 難易度1の時のtarget（マイニングソフトのdebugオプションで確認できるかも）
PAYLOAD -> getblocktemplateするときのpayload(segwit対応するかどうか)
BLOCKTIME -> 1ブロックが何秒で生成されるか
P2PKH_PREF -> p2pkhアドレスのプレフィックス(アドレスをbase58.b58decode_check(addr).hex()した結果の最初の2文字)
P2SH_PREF -> p2shアドレスのプレフィックス(上と同じ　参考：https://en.bitcoin.it/wiki/List_of_address_prefixes)
```

mininglove.pyに以下の項目を追記してください。
(最初の方にあります)

```
elif MAIN_SETTING.COIN_NAME == "コイン名":
    from コインのマイニングアルゴリズムのモジュール import getPoWHash
    from PoolSetting import さっき追記した内容のクラス名 as COIN_SETTING
```
