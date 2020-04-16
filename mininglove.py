import binascii
import hashlib
from PoolSetting import STANDARD_RETURN, MAIN_SETTING
import asyncio
import socket
import json
import base58
import threading
import zmq
import secrets
import requests
import time
import datetime
from decimal import *
import re

import tornado.web
import tornado.websocket
from tornado.platform.asyncio import AsyncIOMainLoop
import os
import concurrent.futures


if MAIN_SETTING.COIN_NAME == "bellcoin":
    from bell_yespower import getPoWHash
    from PoolSetting import BELLCOIN as COIN_SETTING
elif MAIN_SETTING.COIN_NAME == "bellcoin_regtest":
    from bell_yespower import getPoWHash
    from PoolSetting import BELLCOIN_REGTEST as COIN_SETTING

from logging import getLogger, StreamHandler, DEBUG, Formatter

logger = getLogger(__name__)
handler = StreamHandler()
handler.setFormatter(Formatter("%(asctime)s [%(levelname)s] %(message)s"))
handler.setLevel(DEBUG)
logger.setLevel(DEBUG)
logger.addHandler(handler)
logger.propagate = False

settings_list = []
connections = {}
mainloop = asyncio.get_event_loop()
extranonce1 = []
notify_d = {}
cont_list = {}
web_list = {}
submitlog = []


coind_setting = MAIN_SETTING.COIND
rpc_url = f'http://{coind_setting["coind_host"]}:{coind_setting["coind_rpcport"]}'
rpc_auth = (coind_setting["coind_rpcuser"], coind_setting["coind_rpcpassword"])
headers = {'content-type': "application/json"}
payload = json.dumps(COIN_SETTING.PAYLOAD)

pool_name = binascii.hexlify(('/'+MAIN_SETTING.POOL_URL+'/').encode()).decode()
pool_name_opcode = hex(len(pool_name)//2)[2:].zfill(2)
cbscript_poolname = pool_name_opcode + pool_name

p2pkh_pref = COIN_SETTING.P2PKH_PREF
p2sh_pref = COIN_SETTING.P2SH_PREF


def get_exnonce():
    while True:
        exnonce = str(secrets.randbelow(99999999)).zfill(8)
        if exnonce not in extranonce1:
            extranonce1.append(exnonce)
            return exnonce

def submitblock(fd,block,id,blockhash):
    global submitlog
    logger.debug(block)
    payload = json.dumps({"id":0, "method": "submitblock", "params":[block]})
    res = requests.post(rpc_url,data=payload,headers=headers,auth=rpc_auth)
    result = json.loads(res.text)
    logger.debug(result)
    if result["result"] is None and result["error"] is None:
        # エラーがあるとresultに書いてある
        retdata = '{"error": null, "id": '+str(id)+', "result": true}\n'
        connections[fd]["send_list"].append(retdata)
        mainloop.add_writer(fd,send_cb,fd)
        submitlog.insert(0,blockhash)
        submitlog = submitlog[0:10]
    else:
        retdata = '{"error": "23", "id": '+str(id)+', "result": false}\n'
        connections[fd]["send_list"].append(retdata)
        mainloop.add_writer(fd,send_cb,fd)
    return

def zmq_check():
    global notify_d
    try:
        res = json.loads(requests.post(rpc_url,data=payload,headers=headers,auth=rpc_auth).text)
        if res["error"] is not None:
            raise Exception
    except Exception:
        logger.critical('zmq_check: getblocktemplate -> fail')
        # ループ外なので強制終了
        import os
        os._exit(1)

    res_bkup = hashlib.sha256(str(res).encode()).digest()
    txid_list = []
    txdata = ''
    for tx in res["result"]["transactions"]:
        txid_list.append(tx["txid"])
        txdata += tx["data"]

    if len(txid_list) == 0:
        merkle_branch = []
    else:
        merkle_branch = build_merkle_branch(txid_list)

    l_prevhash = bytes.fromhex(res["result"]["previousblockhash"])[::-1].hex()
    send_prevhash = ''
    for i in range(0,64,8):
        send_prevhash += bytes.fromhex(l_prevhash[i:i+8])[::-1].hex()

    # 8388608ブロックになるとbad-cb-heightでエラーが出ると思われる
    if res["result"]["height"] < 128:
        height_opcode = "01"
        height = bytes.fromhex(hex(res["result"]["height"])[2:].zfill(2))[::-1].hex()
    elif res["result"]["height"] < 32768:
        height_opcode = "02"
        height = bytes.fromhex(hex(res["result"]["height"])[2:].zfill(4))[::-1].hex()
    else:
        height_opcode = "03"
        height = bytes.fromhex(hex(res["result"]["height"])[2:].zfill(6))[::-1].hex()

    # height_opcodeのバイト数 + heightのバイト数 + opcodeのバイト数 + exnonce1(ry + exnonce2 + pool_name_opcode + pool_name
    coinbase_len = hex(1 + int(height_opcode,16) + 1 + 4 + 4 + 1 + int(pool_name_opcode,16))[2:].zfill(2)

    coinbasetx1 = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff'+coinbase_len+height_opcode+height+'08'
    coinbasetx2_1 = pool_name_opcode + pool_name + 'ffffffff'

    nbits = res["result"]["bits"]
    # int_diff = 26959535291011309493156476344723991336010898738574164086137773096960 / ( int(nbits[2:],16) * 2 **(8 *(int(nbits[0:2],16)-3)) )
    # prevhash ... coindそのままの値　header計算するときはこれを逆にする
    # send_prevhash ... この値をclientに送る
    # merkle_branch ... このままclientに
    # ntime ... このままclientに 計算するときは逆に
    # nbits .. このままclientに 計算するときは逆に
    if "default_witness_commitment" in res["result"]:
        op_r = res["result"]["default_witness_commitment"]
        coinbase_commitment = '0000000000000000' + hex(len(op_r) // 2)[2:] + op_r
    else:
        coinbase_commitment = ""

    notify_d = {
        "count": "1",
        "ver": hex(res["result"]["version"])[2:],
        "prevhash": res["result"]["previousblockhash"],
        "send_prevhash": send_prevhash,
        "merkle_branch": merkle_branch,
        "ntime": hex(res["result"]["curtime"])[2:],
        "nbits": nbits,
        "cb1": coinbasetx1,
        "cb2_1": coinbasetx2_1,
        "cb_cmt": coinbase_commitment,
        "txs": txdata,
        "txcount": len(txid_list),
        "coinbasevalue": res["result"]["coinbasevalue"],
        "solo": True
    }

    t2 = threading.Thread(target=change_diff)
    t2.setDaemon(True)
    t2.start()

    context = zmq.Context()
    z_socket = context.socket(zmq.SUB)
    z_socket.setsockopt(zmq.RCVHWM, 0)
    z_socket.setsockopt_string(zmq.SUBSCRIBE, "hashblock")
    z_socket.setsockopt_string(zmq.SUBSCRIBE, "hashtx")
    z_socket.connect(f'tcp://{coind_setting["coind_host"]}:{coind_setting["coind_zmqport"]}')

    while True:
        # 新しいblock or txが来たら
        _ = z_socket.recv_multipart()
        with threading.RLock():
            try:
                res = json.loads(requests.post(rpc_url,data=payload,headers=headers,auth=rpc_auth).text)
                if res["error"] is not None:
                    raise Exception
            except Exception:
                logger.warning("zmq_check(loop): getblocktemplate -> fail")
                continue

            # ブロックが進んだ時にcbtxの通知とnewblockの通知で二回noticeしないように
            res_sha256 = hashlib.sha256(str(res).encode()).digest()
            if res_sha256 == res_bkup:
                continue
            res_bkup = res_sha256

            txid_list = []
            txdata = ''
            for tx in res["result"]["transactions"]:
                txid_list.append(tx["txid"])
                txdata += tx["data"]

            if len(txid_list) == 0:
                merkle_branch = []
            else:
                merkle_branch = build_merkle_branch(txid_list)

            l_prevhash = bytes.fromhex(res["result"]["previousblockhash"])[::-1].hex()
            send_prevhash = ''
            for i in range(0,64,8):
                send_prevhash += bytes.fromhex(l_prevhash[i:i+8])[::-1].hex()

            if res["result"]["height"] < 128:
                height_opcode = "01"
                height = bytes.fromhex(hex(res["result"]["height"])[2:].zfill(2))[::-1].hex()
            elif res["result"]["height"] < 32768:
                height_opcode = "02"
                height = bytes.fromhex(hex(res["result"]["height"])[2:].zfill(4))[::-1].hex()
            else:
                height_opcode = "03"
                height = bytes.fromhex(hex(res["result"]["height"])[2:].zfill(6))[::-1].hex()

            # height_opcodeのバイト数 + heightのバイト数 + opcodeのバイト数 + exnonce1(ry + exnonce2 + pool_name_opcode + pool_name
            coinbase_len = hex(1 + int(height_opcode,16) + 1 + 4 + 4 + 1 + int(pool_name_opcode,16))[2:].zfill(2)

            nbits = res["result"]["bits"]
            # int_diff = 26959535291011309493156476344723991336010898738574164086137773096960 / ( int(nbits[2:],16) * 2 **(8 *(int(nbits[0:2],16)-3)) )
            coinbasetx1 = '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff'+coinbase_len+height_opcode+height+'08'


            # coinbasetx2_1 = pool_name_opcode + pool_name + 'ffffffff' + '01' + bytes.fromhex(hex(int(res["result"]["coinbasevalue"]))[2:].zfill(16))[::-1].hex()
            coinbasetx2_1 = pool_name_opcode + pool_name + 'ffffffff'

            if "default_witness_commitment" in res["result"]:
                op_r = res["result"]["default_witness_commitment"]
                coinbase_commitment = '0000000000000000' + hex(len(op_r) // 2)[2:] + op_r
            else:
                coinbase_commitment = ""

            count = hex(int(notify_d["count"],16)+1)[2:]
            notify_d = {
                "count":count,
                "ver": hex(res["result"]["version"])[2:],
                "prevhash": res["result"]["previousblockhash"],
                "send_prevhash": send_prevhash,
                "merkle_branch": merkle_branch,
                "ntime": hex(res["result"]["curtime"])[2:],
                "nbits": nbits,
                "cb1": coinbasetx1,
                "cb2_1": coinbasetx2_1,
                "cb_cmt":coinbase_commitment,
                "txs": txdata,
                "txcount": len(txid_list),
                "coinbasevalue": res["result"]["coinbasevalue"],
                "solo": False
            }

            txout = build_txout(res["result"]["coinbasevalue"],notify_d["cb_cmt"])

            if len(cont_list) < 2:
                notify_d["solo"] = True
                for fd in connections:
                    try:
                        hex_addr = connections[fd]["hex_address"]
                    except Exception:
                        continue
                    if "addr_flag" not in connections[fd]:
                        continue
                    if connections[fd]["addr_flag"] == 1:
                        if notify_d["cb_cmt"]:
                            coinbasetx2 = coinbasetx2_1 + '02' + bytes.fromhex(hex(int(res["result"]["coinbasevalue"]))[2:].zfill(16))[::-1].hex() + '1976a914' + hex_addr + '88ac' + notify_d["cb_cmt"] + '00000000'
                        else:
                            coinbasetx2 = coinbasetx2_1 + '01' + bytes.fromhex(hex(int(res["result"]["coinbasevalue"]))[2:].zfill(16))[::-1].hex() + '1976a914' + hex_addr + '88ac' +'00000000'
                    elif connections[fd]["addr_flag"] == 2:
                        if notify_d["cb_cmt"]:
                            coinbasetx2 = coinbasetx2_1 + '02' + bytes.fromhex(hex(int(res["result"]["coinbasevalue"]))[2:].zfill(16))[::-1].hex() + '17a914' + hex_addr + '87' + notify_d["cb_cmt"] + '00000000'
                        else:
                            coinbasetx2 = coinbasetx2_1 + '01' + bytes.fromhex(hex(int(res["result"]["coinbasevalue"]))[2:].zfill(16))[::-1].hex() + '17a914' + hex_addr + '87' + '00000000'
                    else:
                        continue
                    retdata = '{"params": ["'+count+'","'+notify_d["send_prevhash"]+'","'+notify_d["cb1"]+'","'+coinbasetx2+'",'+str(notify_d["merkle_branch"]).replace('\'','\"')+',"'+notify_d["ver"]+'","'+notify_d["nbits"]+'","'+notify_d["ntime"]+'",true], "id": null, "method": "mining.notify"}\n'
                    connections[fd]["send_list"].append(retdata)
                    mainloop.add_writer(fd,send_cb,fd)
                    connections[fd]["sharelog"] = []
            else:
                notify_d["cb2_2"] = txout
                for fd in connections:
                    retdata = '{"params": ["'+count+'","'+notify_d["send_prevhash"]+'","'+notify_d["cb1"]+'","'+coinbasetx2_1+txout+'",'+str(notify_d["merkle_branch"]).replace('\'','\"')+',"'+notify_d["ver"]+'","'+notify_d["nbits"]+'","'+notify_d["ntime"]+'",true], "id": null, "method": "mining.notify"}\n'
                    connections[fd]["send_list"].append(retdata)
                    mainloop.add_writer(fd,send_cb,fd)
                    connections[fd]["sharelog"] = []


def build_txout(coinbasevalue,cb_cmt):
    txout = ''
    if cb_cmt:
        txcount = 1
    else:
        txcount = 0
    rewards = 0
    for k in cont_list:
        # 0.01%まで見る
        w = cont_list[k].quantize(Decimal('0.0001'),rounding=ROUND_DOWN)
        if w == 0:
            continue
        reward = int((coinbasevalue * w * (100-Decimal(MAIN_SETTING.FEE)) / 100).quantize(Decimal('0'),rounding=ROUND_DOWN))
        rewards += reward
        if k[0] == '1':
            txout += bytes.fromhex(hex(reward)[2:].zfill(16))[::-1].hex() + '1976a914' + k[1:] + '88ac'
        elif k[0] == '2':
            txout += bytes.fromhex(hex(reward)[2:].zfill(16))[::-1].hex() + '17a914' + k[1:] + '87'
        txcount += 1
    fee = coinbasevalue - rewards
    if fee != 0:
        txout += bytes.fromhex(hex(fee)[2:].zfill(16))[::-1].hex() + MAIN_SETTING.FEE_TXOUT_SCRIPT
        txcount += 1
    # txoutとlocktimeあわせたのを返す
    logger.debug("build_txout: "+txout)
    if txcount < 253:
        if cb_cmt:
            return hex(txcount)[2:].zfill(2) + txout + cb_cmt +'00000000'
        else:
            return hex(txcount)[2:].zfill(2) + txout + '00000000'
    else:
        if cb_cmt:
            return 'fd'+ bytes.fromhex(hex(txcount)[2:].zfill(4)).hex() + txout + cb_cmt +'00000000'
        else:
            return 'fd'+ bytes.fromhex(hex(txcount)[2:].zfill(4)).hex() + txout + '00000000'


def build_merkle_root(coinbase_hash, merkle_branch):
    merkle_root = binascii.unhexlify(coinbase_hash)
    for h in merkle_branch:
        merkle_root = hashlib.sha256(hashlib.sha256(merkle_root + binascii.unhexlify(h)).digest()).digest()
    return binascii.hexlify(merkle_root).decode()

def build_merkle_branch(tx_list):
    # tx_listはcoinbasetxを除くブロックに含まれるべき全てのtxid(not txhash)のリスト（ビッグエンディアン）
    ret = []
    l_tx_list = []
    for txhash in tx_list:
        # リトルエンディアンのtx_listを作っていく
        l_tx_list.append(bytes.fromhex(txhash)[::-1].hex())

    while True:
        ret.append(l_tx_list[0])
        # list2は一時的な保管リスト
        # list2の中身を計算してlist1に入れていく
        l_tx_list2 = l_tx_list[1:]
        l_tx_list = []
        if len(l_tx_list2) == 0:
            # 0なら終了、leafのリストはret
            break
        for i in range(0,len(l_tx_list2),2):
            tx1 = l_tx_list2[i]
            try:
                tx2 = l_tx_list2[i+1]
            except Exception:
                # ペアが無い場合は自身を複製
                tx2 = tx1
            leaf = binascii.hexlify(hashlib.sha256(hashlib.sha256(binascii.unhexlify(tx1+tx2)).digest()).digest()).decode()
            l_tx_list.append(leaf)
    return ret

'''
def build_commitment(wtxid_list):
    # 必ずwtxid_listの長さは1以上
    res = [bytes.fromhex(COIN_SETTING.WITNESS_RESERVED_VALUE)[::-1].hex()]
    for w in wtxid_list:
        res.append(bytes.fromhex(w)[::-1].hex())
    while True:
        if len(res) == 1:
            break
        leaf_list = res
        res = []
        for i in range(0,len(leaf_list),2):
            tx1 = leaf_list[i]
            try:
                tx2 = leaf_list[i+1]
            except Exception:
                # ペアが無い場合は自身を複製
                tx2 = tx1
            res.append(binascii.hexlify(hashlib.sha256(hashlib.sha256(binascii.unhexlify(tx1+tx2)).digest()).digest()).decode())
    return binascii.hexlify(hashlib.sha256(hashlib.sha256(binascii.unhexlify(res[0]+COIN_SETTING.WITNESS_RESERVED_VALUE)).digest()).digest()).decode()
'''

'''
def get_hashrate(submithistory):
    # submithistoryのlenは2以上のこと！！！
    hashes_per_s = []
    for i in range(len(submithistory)):
        h1time, _ = submithistory[i]
        try:
            h2time, h2hash = submithistory[i+1]
            s,b = Decimal(int(h2hash,16)/(2**256-1)).as_integer_ratio()
            hashes_per_s.append(Decimal((b/s)/(h2time-h1time)).quantize(Decimal('0.001'),rounding=ROUND_HALF_UP))
        except Exception:
            break
    return Decimal(sum(hashes_per_s)/len(hashes_per_s)/2).quantize(Decimal('0.001'),rounding=ROUND_HALF_UP)
'''

def change_diff():
    global cont_list
    global web_list
    while True:
        tmp_cont_list = {}
        tmp_web_list = {}
        for c in connections:
            try:
                s_history = connections[c]["submithistory"]
                now_diff = connections[c]["diff"]
            except Exception:
                continue
            if len(s_history) < 3:
                continue
            ts1 = s_history[0]
            ts2 = s_history[-1]
            ts_diff = Decimal(str(ts2)) - Decimal(str(ts1))
            ts_count = len(s_history)
            try:
                tmp_s,tmp_b = Decimal(int(COIN_SETTING.DIFF1_TARGET,16) / Decimal(now_diff) / (2**256-1)).as_integer_ratio()
                # hashrate = Decimal(Decimal(str(tmp_b)) / Decimal(str(tmp_s)) / 2 * (ts_count-1) / ts_diff).quantize(Decimal('0'),rounding=ROUND_HALF_DOWN)
                hashrate = Decimal(Decimal(str(tmp_b)) / Decimal(str(tmp_s)) * (ts_count-1) / ts_diff).quantize(Decimal('0'),rounding=ROUND_HALF_DOWN)
            except:
                continue
            # 貢献度を計算
            # pdiff1のとき1秒に何回submitできるか
            co = (ts_count - 1) * Decimal(now_diff) / ts_diff
            # 初めの1文字はアドレス種類判別用
            if str(connections[c]["addr_flag"])+connections[c]["hex_address"] in tmp_cont_list:
                tmp_cont_list[str(connections[c]["addr_flag"])+connections[c]["hex_address"]] += co
            else:
                tmp_cont_list[str(connections[c]["addr_flag"])+connections[c]["hex_address"]] = co

            if ts_count == 0 or ts_count == 1:
                continue
            # diffが大きく変動しすぎないようにする
            m = Decimal(5 / Decimal(ts_diff/ts_count))
            if m > Decimal("1.3"):
                m = Decimal("1.3")
            elif m < Decimal("0.7"):
                m = Decimal("0.7")
            with threading.RLock():
                next_diff = Decimal(now_diff) * m
                retdata = '{"id":null,"method":"mining.set_difficulty","params":['+str(next_diff)+']}\n'
                if connections[c]["diff"] != now_diff:
                    # 接続が切れるのとdiff更新が運悪く重なるとreject祭りになる
                    continue
                connections[c]["diff"] = str(next_diff)
                connections[c]["submithistory"] = []
            connections[c]["send_list"].append(retdata)
            mainloop.add_writer(c,send_cb,c)
            # WEB用
            if connections[c]["address"] in tmp_web_list:
                if connections[c]["worker_name"] in tmp_web_list[connections[c]["address"]]:
                    tmp_web_list[connections[c]["address"]][connections[c]["worker_name"]] += hashrate
                else:
                    tmp_web_list[connections[c]["address"]][connections[c]["worker_name"]] = hashrate
            else:
                tmp_web_list[connections[c]["address"]] = {connections[c]["worker_name"]:hashrate}
        c = Decimal(str(sum([tmp_cont_list[k] for k in tmp_cont_list])))
        for k in tmp_cont_list:
            tmp_cont_list[k] /= c
        for addr in tmp_web_list:
            for w in tmp_web_list[addr]:
                if tmp_web_list[addr][w] < 1024:
                    tmp_web_list[addr][w] = str(tmp_web_list[addr][w])+'H/s'
                elif tmp_web_list[addr][w] < 1024**2:
                    tmp_web_list[addr][w] = str(tmp_web_list[addr][w]/1024)+'KH/s'
                elif tmp_web_list[addr][w] < 1024**3:
                    tmp_web_list[addr][w] = str(tmp_web_list[addr][w]/1024**2)+'MH/s'
                elif tmp_web_list[addr][w] < 1024**4:
                    tmp_web_list[addr][w] = str(tmp_web_list[addr][w]/1024**3)+'GH/s'
                else:
                    tmp_web_list[addr][w] = str(tmp_web_list[addr][w]/1024**4)+'TH/s'
        cont_list = tmp_cont_list
        web_list = tmp_web_list
        del tmp_cont_list
        if len(cont_list) == 0:
            with threading.RLock():
                logger.debug('change_diff_notice1')
                # データが更新されていなくてもdiff更新後なのでnotifyする
                if notify_d["ntime"] == hex(int(datetime.datetime.now().timestamp()))[2:]:
                    time.sleep(1)
                count = hex(int(notify_d["count"],16)+1)[2:]
                notify_d["count"] = count
                notify_d["ntime"] = hex(int(datetime.datetime.now().timestamp()))[2:]
                for fd in connections:
                    if "addr_flag" not in connections[fd]:
                        continue
                    if connections[fd]["addr_flag"] == 1:
                        if notify_d["cb_cmt"]:
                            coinbasetx2 = notify_d["cb2_1"] + '02' + bytes.fromhex(hex(int(notify_d["coinbasevalue"]))[2:].zfill(16))[::-1].hex() + '1976a914' + connections[fd]["hex_address"] + '88ac' + notify_d["cb_cmt"] + '00000000'
                        else:
                            coinbasetx2 = notify_d["cb2_1"] + '01' + bytes.fromhex(hex(int(notify_d["coinbasevalue"]))[2:].zfill(16))[::-1].hex() + '1976a914' + connections[fd]["hex_address"] + '88ac' + '00000000'
                    elif connections[fd]["addr_flag"] == 2:
                        if notify_d["cb_cmt"]:
                            coinbasetx2 = notify_d["cb2_1"] + '02' + bytes.fromhex(hex(int(notify_d["coinbasevalue"]))[2:].zfill(16))[::-1].hex() + '17a914' + connections[fd]["hex_address"] + '87' + notify_d["cb_cmt"] + '00000000'
                        else:
                            coinbasetx2 = notify_d["cb2_1"] + '01' + bytes.fromhex(hex(int(notify_d["coinbasevalue"]))[2:].zfill(16))[::-1].hex() + '17a914' + connections[fd]["hex_address"] + '87' + '00000000'
                    else:
                        continue
                    retdata = '{"params": ["'+notify_d["count"]+'","'+notify_d["send_prevhash"]+'","'+notify_d["cb1"]+'","'+coinbasetx2+'",'+str(notify_d["merkle_branch"]).replace('\'','\"')+',"'+notify_d["ver"]+'","'+notify_d["nbits"]+'","'+notify_d["ntime"]+'",true], "id": null, "method": "mining.notify"}\n'
                    connections[fd]["send_list"].append(retdata)
                    mainloop.add_writer(fd,send_cb,fd)
                    connections[fd]["sharelog"] = []
            time.sleep(120)
        else:
            with threading.RLock():
                logger.debug('change_diff_notice2')
                if notify_d["ntime"] == hex(int(datetime.datetime.now().timestamp()))[2:]:
                    time.sleep(1)
                count = hex(int(notify_d["count"],16)+1)[2:]
                notify_d["count"] = count
                notify_d["solo"] = False
                notify_d["ntime"] = hex(int(datetime.datetime.now().timestamp()))[2:]
                txout = build_txout(notify_d["coinbasevalue"],notify_d["cb_cmt"])
                notify_d["cb2_2"] = txout
                for fd in connections:
                    retdata = '{"params": ["'+notify_d["count"]+'","'+notify_d["send_prevhash"]+'","'+notify_d["cb1"]+'","'+notify_d["cb2_1"]+notify_d["cb2_2"]+'",'+str(notify_d["merkle_branch"]).replace('\'','\"')+',"'+notify_d["ver"]+'","'+notify_d["nbits"]+'","'+notify_d["ntime"]+'",true], "id": null, "method": "mining.notify"}\n'
                    connections[fd]["send_list"].append(retdata)
                    mainloop.add_writer(fd,send_cb,fd)
                    connections[fd]["sharelog"] = []
            time.sleep(120)


def accept_cb(s_socket,diff):
    client_socket, (client_addr, client_port) = s_socket.accept()
    logger.info(f'New client: {client_addr}:{client_port}')
    fd = client_socket.fileno()
    connections[fd] = {"socket":(client_socket, client_addr, client_port)}
    connections[fd]["send_list"] = []
    connections[fd]["submithistory"] = []
    connections[fd]["sharelog"] = []
    connections[fd]["diff"] = diff
    mainloop.add_reader(fd,recv_cb,fd)

def send_cb(fd):
    client_socket, client_addr, client_port = connections[fd]["socket"]
    if len(connections[fd]["send_list"]) == 0:
        mainloop.remove_writer(fd)
        return
    logger.debug(f'[{client_addr}:{client_port}] {connections[fd]["send_list"][0]}')
    send_len = client_socket.send(connections[fd]["send_list"][0].encode())
    if send_len == len(connections[fd]["send_list"][0]):
        connections[fd]["send_list"] = connections[fd]["send_list"][1:]
        return
    else:
        logger.info(f'[{client_addr}:{client_port}] write: send_len < data_len -> close')
        del connections[fd]
        mainloop.remove_writer(fd)
        mainloop.remove_reader(fd)
        client_socket.close()


def recv_cb(fd):
    client_socket, client_addr, client_port = connections[fd]["socket"]
    try:
        rawdata = client_socket.recv(1024).decode()
        if len(rawdata) == 0:
            raise Exception
    except Exception:
        logger.info(f'[{client_addr}:{client_port}] recv: error (connection lost) -> close')
        del connections[fd]
        mainloop.remove_writer(fd)
        mainloop.remove_reader(fd)
        client_socket.close()
        return
    # データが一部届かなかった場合用
    if "rawdata" in connections[fd]:
        rawdata += connections[fd]["rawdata"]
        del connections[fd]["rawdata"]
    if '\n' not in rawdata:
        if len(rawdata.encode()) > 1024:
            logger.info(f'[{client_addr}:{client_port}] recv: rawdata size error -> close')
            del connections[fd]
            mainloop.remove_writer(fd)
            mainloop.remove_reader(fd)
            client_socket.close()
            return
        else:
            connections[fd]["rawdata"] = rawdata
            return
    try:
        data = json.loads(rawdata)
        if "id" not in data:
            raise Exception
    except Exception:
        logger.info(f'[{client_addr}:{client_port}] recv: json decode error -> close')
        del connections[fd]
        mainloop.remove_writer(fd)
        mainloop.remove_reader(fd)
        client_socket.close()
        return

    logger.debug(str(data))

    if "method" not in data:
        return


    elif data["method"] == "mining.subscribe":
        if len(data["params"]) == 0:
            user_agent = 'unknown'
            logger.debug(f'[{client_addr}:{client_port}] subscribe: user_agent -> unknown, extranonce_req -> No')
        elif len(data["params"]) == 1:
            user_agent = str(data["params"][0])
            logger.debug(f'[{client_addr}:{client_port}] subscribe: user_agent -> {user_agent}, extranonce_req -> No')
        elif len(data["params"]) == 2:
            # 指定されたextranonceを使うようになるべく努力する(予定)
            user_agent = str(data["params"][0])
            logger.debug(f'[{client_addr}:{client_port}] subscribe: user_agent -> {user_agent}, extranonce_req -> Yes')

        exnonce = get_exnonce()
        connections[fd]["extranonce1"] = exnonce
        retdata = '{"id":'+str(data["id"])+' , "result": [ [ ["mining.set_difficulty", "deadbeefcafebabe0200000000000000"], ["mining.notify", "deadbeefcafebabe0200000000000000"]], "'+exnonce+'", 4], "error": null}\n'
        connections[fd]["send_list"].append(retdata)
        mainloop.add_writer(fd,send_cb,fd)
        return

    elif data["method"] == "mining.authorize":
        addr = str(data["params"][0])
        if '.' in addr:
            worker_name = addr.split('.',1)[1]
            addr = addr.split('.',1)[0]
            if re.fullmatch(r'\w+',worker_name) is None:
                retdata = '{"error": null, "id": '+str(data["id"])+', "result": false}\n'
                connections[fd]["send_list"].append(retdata)
                mainloop.add_writer(fd,send_cb,fd)
                return
            connections[fd]["worker_name"] = worker_name
        else:
            connections[fd]["worker_name"] = "-No name-"
        try:
            # segwitアドレスは弾かれます
            hexaddr = base58.b58decode_check(addr).hex()
            retdata = '{"error": null, "id": '+str(data["id"])+', "result": true}\n'
            connections[fd]["address"] = addr
            if hexaddr[0:2] == p2pkh_pref:
                # p2pkhなら1
                connections[fd]["addr_flag"] = 1
            elif hexaddr[0:2] == p2sh_pref:
                # p2shなら2
                connections[fd]["addr_flag"] = 2
            else:
                raise Exception
            connections[fd]["hex_address"] = hexaddr[2:]
        except Exception:
            # segwitaddress判定しない（minerの対応が必要になるため）
            retdata = '{"error": null, "id": '+str(data["id"])+', "result": false}\n'
        connections[fd]["send_list"].append(retdata)
        mainloop.add_writer(fd,send_cb,fd)

        if notify_d["solo"] == True:
            if "addr_flag" not in connections[fd]:
                return
            if connections[fd]["addr_flag"] == 1:
                if notify_d["cb_cmt"]:
                    coinbasetx2 = notify_d["cb2_1"] + '02' + bytes.fromhex(hex(int(notify_d["coinbasevalue"]))[2:].zfill(16))[::-1].hex() + '1976a914' + connections[fd]["hex_address"] + '88ac' + notify_d["cb_cmt"] + '00000000'
                else:
                    coinbasetx2 = notify_d["cb2_1"] + '01' + bytes.fromhex(hex(int(notify_d["coinbasevalue"]))[2:].zfill(16))[::-1].hex() + '1976a914' + connections[fd]["hex_address"] + '88ac' + '00000000'
            elif connections[fd]["addr_flag"] == 2:
                if notify_d["cb_cmt"]:
                    coinbasetx2 = notify_d["cb2_1"] + '02' + bytes.fromhex(hex(int(notify_d["coinbasevalue"]))[2:].zfill(16))[::-1].hex() + '17a914' + connections[fd]["hex_address"] + '87' + notify_d["cb_cmt"] + '00000000'
                else:
                    coinbasetx2 = notify_d["cb2_1"] + '01' + bytes.fromhex(hex(int(notify_d["coinbasevalue"]))[2:].zfill(16))[::-1].hex() + '17a914' + connections[fd]["hex_address"] + '87' + '00000000'
            else:
                return
            retdata = '{"params": ["'+notify_d["count"]+'","'+notify_d["send_prevhash"]+'","'+notify_d["cb1"]+'","'+coinbasetx2+'",'+str(notify_d["merkle_branch"]).replace('\'','\"')+',"'+notify_d["ver"]+'","'+notify_d["nbits"]+'","'+notify_d["ntime"]+'",true], "id": null, "method": "mining.notify"}\n'
        else:
            retdata = '{"params": ["'+notify_d["count"]+'","'+notify_d["send_prevhash"]+'","'+notify_d["cb1"]+'","'+notify_d["cb2_1"]+notify_d["cb2_2"]+'",'+str(notify_d["merkle_branch"]).replace('\'','\"')+',"'+notify_d["ver"]+'","'+notify_d["nbits"]+'","'+notify_d["ntime"]+'",true], "id": null, "method": "mining.notify"}\n'
        retdata2 = '{"id":null,"method":"mining.set_difficulty","params":['+str(connections[fd]["diff"])+']}\n'
        connections[fd]["send_list"].append(retdata2+retdata)
        mainloop.add_writer(fd,send_cb,fd)
        return

    elif data["method"] == "mining.submit":
        job_id = data["params"][1].lower()
        exnonce2 = data["params"][2].lower()
        ntime = bytes.fromhex(data["params"][3])[::-1].hex().lower()
        nonce = bytes.fromhex(data["params"][4])[::-1].hex().lower()
        try:
            notify_data = notify_d
            if job_id != notify_data["count"]:
                raise Exception
            if ntime != bytes.fromhex(notify_data["ntime"])[::-1].hex():
                raise Exception
        except Exception:
            retdata = '{"error": [21,"job not found"], "id": '+str(data["id"])+', "result": false}\n'
            connections[fd]["send_list"].append(retdata)
            mainloop.add_writer(fd,send_cb,fd)
            return

        sharedata = [exnonce2,ntime,nonce]
        if sharedata in connections[fd]["sharelog"]:
            retdata = '{"error": [22,"Duplicate share"], "id": '+str(data["id"])+', "result": false}\n'
            connections[fd]["send_list"].append(retdata)
            mainloop.add_writer(fd,send_cb,fd)
            return
        else:
            connections[fd]["sharelog"].append(sharedata)

        if notify_d["solo"] == True:
            try:
                if "addr_flag" not in connections[fd]:
                    raise Exception
                if connections[fd]["addr_flag"] == 1:
                    if notify_data["cb_cmt"]:
                        coinbasetx = notify_data["cb1"] + connections[fd]["extranonce1"] + exnonce2 + notify_d["cb2_1"] + '02' + bytes.fromhex(hex(int(notify_data["coinbasevalue"]))[2:].zfill(16))[::-1].hex() + '1976a914' + connections[fd]["hex_address"] + '88ac' + notify_data["cb_cmt"] + '00000000'
                    else:
                        coinbasetx = notify_data["cb1"] + connections[fd]["extranonce1"] + exnonce2 + notify_d["cb2_1"] + '01' + bytes.fromhex(hex(int(notify_data["coinbasevalue"]))[2:].zfill(16))[::-1].hex() + '1976a914' + connections[fd]["hex_address"] + '88ac' + '00000000'
                elif connections[fd]["addr_flag"] == 2:
                    if notify_data["cb_cmt"]:
                        coinbasetx = notify_data["cb1"] + connections[fd]["extranonce1"] + exnonce2 + notify_d["cb2_1"] + '02' + bytes.fromhex(hex(int(notify_data["coinbasevalue"]))[2:].zfill(16))[::-1].hex() + '17a914' + connections[fd]["hex_address"] + '87' + notify_data["cb_cmt"] + '00000000'
                    else:
                        coinbasetx = notify_data["cb1"] + connections[fd]["extranonce1"] + exnonce2 + notify_d["cb2_1"] + '01' + bytes.fromhex(hex(int(notify_data["coinbasevalue"]))[2:].zfill(16))[::-1].hex() + '17a914' + connections[fd]["hex_address"] + '87' + '00000000'
                else:
                    raise Exception
            except Exception:
                retdata = '{"error": [20,"unknown error"], "id": '+str(data["id"])+', "result": false}\n'
                connections[fd]["send_list"].append(retdata)
                mainloop.add_writer(fd,send_cb,fd)
                return
        else:
            coinbasetx = notify_data["cb1"] + connections[fd]["extranonce1"] + exnonce2 + notify_d["cb2_1"] + notify_d["cb2_2"]
        coinbase_hash = binascii.hexlify(hashlib.sha256(hashlib.sha256(binascii.unhexlify(coinbasetx)).digest()).digest()).decode()

        merkleroot = build_merkle_root(coinbase_hash,notify_data["merkle_branch"])
        header = bytes.fromhex(notify_data["ver"])[::-1].hex() + bytes.fromhex(notify_data["prevhash"])[::-1].hex() + merkleroot + ntime + bytes.fromhex(notify_data["nbits"])[::-1].hex() + nonce
        blockhash = getPoWHash(binascii.unhexlify(header))[::-1].hex()

        diff = Decimal(26959535291011309493156476344723991336010898738574164086137773096960 / (int(notify_data["nbits"][2:],16) * 2 **(8 *(int(notify_data["nbits"][0:2],16)-3))))

        pdiff = Decimal(26959535291011309493156476344723991336010898738574164086137773096960 / int(COIN_SETTING.DIFF1_TARGET,16)) * Decimal(connections[fd]["diff"])

        hashdiff = Decimal(26959535291011309493156476344723991336010898738574164086137773096960 / int(blockhash,16))

        if diff < hashdiff:
            # ブロック生成可能
            logger.info('submit ok')
            # TODO: キチンとtxcount出す
            logger.debug("cbtx:"+str(coinbasetx))
            logger.debug("header:"+str(header))
            logger.debug("txs:"+str(notify_data["txs"]))
            if notify_data["txcount"] + 1 < 253:
                block = header + hex(notify_data["txcount"]+1)[2:].zfill(2) + coinbasetx +notify_data["txs"]
            else:
                block = header + 'fd'+ bytes.fromhex(hex(notify_data["txcount"]+1)[2:].zfill(4)).hex() + coinbasetx +notify_data["txs"]
            connections[fd]["submithistory"].append(datetime.datetime.now().timestamp())
            threading.Thread(target=submitblock,args=(fd,block,data["id"],blockhash)).start()
        elif pdiff < hashdiff:
            # accept
            connections[fd]["submithistory"].append(datetime.datetime.now().timestamp())
            retdata = '{"error": null, "id": '+str(data["id"])+',"result": true}\n'
            connections[fd]["send_list"].append(retdata)
            mainloop.add_writer(fd,send_cb,fd)
            return
        else:
            retdata = '{"error": [23,"low difficulty share"], "id": '+str(data["id"])+', "result": false}\n'
            connections[fd]["send_list"].append(retdata)
            mainloop.add_writer(fd,send_cb,fd)
            return

    elif data["method"] == "mining.extranonce.subscribe":
        retdata = '{"error": null, "id": '+str(data["id"])+', "result": true}\n'
        connections[fd]["send_list"].append(retdata)
        mainloop.add_writer(fd,send_cb,fd)
        threading.Thread(target=notice_diff,args=(fd,)).start()
        return

    else:
        logger.info(f'[{client_addr}:{client_port}] recv: unknown method -> close')
        del connections[fd]
        mainloop.remove_writer(fd)
        mainloop.remove_reader(fd)
        client_socket.close()
        return

def notice_diff(fd):
    time.sleep(1)
    retdata = '{"id":null,"method":"mining.set_difficulty","params":['+str(connections[fd]["diff"])+']}\n'
    connections[fd]["send_list"].append(retdata)
    mainloop.add_writer(fd,send_cb,fd)
    return

def main():
    for i in range(len(MAIN_SETTING.PORT_DIFF)):
        host = MAIN_SETTING.HOST
        backlog = MAIN_SETTING.BACKLOG
        port,diff = MAIN_SETTING.PORT_DIFF[i]
        sockets = []

        if not 1023 < port < 65535:
            raise Exception('Port number is out of range')

        s_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s_socket.setblocking(False)
        s_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        s_socket.bind((host,port))
        s_socket.listen(backlog)
        mainloop.add_reader(s_socket.fileno(),accept_cb,s_socket,diff)

    t = threading.Thread(target=zmq_check)
    t.setDaemon(True)
    t.start()

    try:
        mainloop.run_forever()
    finally:
        mainloop.close()


class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('index.html')

class StatsHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('stats.html',workers=web_list,blocklog=submitlog,explorer_url=COIN_SETTING.WEB_EXPLORER_URL)

class GettingstartedHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('gs.html')

class NewsHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('news.html')
class ApiHandler(tornado.web.RequestHandler):
    def get(self):
        self.render('api.html')
class WorkersHandler(tornado.web.RequestHandler):
    def get(self):
        try:
            w_name = self.get_argument("addr")
            w_data = web_list[w_name]
            hexaddr = base58.b58decode_check(w_name).hex()
            if hexaddr[0:2] == p2pkh_pref:
                hexaddr_2 = "1"+hexaddr[2:]
            elif hexaddr[0:2] == p2sh_pref:
                hexaddr_2 = "2"+hexaddr[2:]
            else:
                raise Exception
            cont = notify_d["coinbasevalue"] * cont_list[hexaddr_2] / 10**8
        except Exception:
            raise tornado.web.HTTPError(404)
        self.render('workers.html',name=w_name,data=w_data,cont=cont,unit=COIN_SETTING.UNIT)


AsyncIOMainLoop().install()
application = tornado.web.Application([
        (r'/', MainHandler),
        (r'/stats', StatsHandler),
        (r'/getting_started', GettingstartedHandler),
        (r'/news',NewsHandler),
        (r'/api',ApiHandler),
        (r'/workers',WorkersHandler)
        ],
        template_path=os.path.join(os.getcwd(), 'templates'),
        static_path=os.path.join(os.getcwd(), 'static'),
)
application.listen(MAIN_SETTING.WEB_PORT)

if __name__ == '__main__':
    main()
