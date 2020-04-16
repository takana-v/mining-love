class MAIN_SETTING:
    HOST = '127.0.0.1'
    PORT_DIFF = [(3001,0.1)]
    # 75byte以内で
    # ascii文字(1byte) 非ascii文字(3byte,utf-8)
    POOL_URL = 'test.mining.love'
    COIN_NAME = "bellcoin_regtest"
    # Feeの％,（1.5とか小数でもOK）,strで
    FEE = "0"
    # Fee受け取るためのscriptとか
    # txoutのTxout-script lengthとTxout-script合わせたもの（valueは要らない）
    FEE_TXOUT_SCRIPT = "17a914" + "2001320db3a2ea53a6ff91636c062eeb5aff3ae9" + "87"
    # acceptされていない接続要求を保持しておくMAXの値
    BACKLOG = 8
    COIND = {
        "coind_host": "127.0.0.1",
        "coind_rpcport": 19196,
        "coind_rpcuser": "user",
        "coind_rpcpassword": "pass",
        "coind_zmqport": 28334
        }
    WEB_PORT = 8080

class BELLCOIN:
    UNIT = "BELL"
    # BLOCK_VER = "00000005"
    DIFF1_TARGET = "0000ffff00000000000000000000000000000000000000000000000000000000"
    PAYLOAD = {"id":0, "method": "getblocktemplate", "params":[{"rules":["segwit"]}]}
    # blocktime [sec]
    BLOCKTIME = 60
    P2PKH_PREF = '19'
    P2SH_PREF = '55'
    WEB_EXPLORER_URL = "https://explorer.bellcoin.web4u.jp/block/"
    # WITNESS_RESERVED_VALUE = "0000000000000000000000000000000000000000000000000000000000000000"

class BELLCOIN_REGTEST(BELLCOIN):
    P2PKH_PREF = '6f'
    P2SH_PREF = 'c4'

class STANDARD_RETURN:
    OK = 0
    NOT_OK = 1
    FATAL_ERROR = 2
