# -*- coding: utf-8 -*-
import json
from hashlib import blake2b
from base64 import b64encode
from datetime import datetime
import calendar

def hashbin(s):
    if not isinstance(s, bytes):
        s = s.encode('utf8')
    i = blake2b(digest_size=32)
    i.update(s)
    return i.digest()

def hash_blake(s):
    return b64encode(hashbin(s))


def str_to_timestamp(s):
    s = s[:19]
    dt = datetime.strptime(s, '%Y-%m-%d %H:%M:%S').timetuple()
    return int(calendar.timegm(dt))


def assemble_balance_payload(account):
    payload = {
        "exec": {
            "data": None,
            "code": "(coin.get-balance \"{}\")".format(account)
        }
    }
    signers = []

    nonce = datetime.utcnow()
    targe_nonce = str(nonce.strftime('%Y-%m-%d %H:%M:%S.%f UTC'))
    creation_time = str_to_timestamp(targe_nonce)
    meta = {
        "creationTime": creation_time,
        "ttl": 1800,
        "gasLimit": 1000,
        "chainId": "",
        "gasPrice": 1.0e-2,
        "sender": ""
    }

    cmd = {
        "networkId": "mainnet01",
        "payload": payload,
        "signers": signers,
        "meta": meta,
        "nonce": targe_nonce
    }
    cmd_str = json.dumps(cmd, separators=(',', ':'))
    hash_str = hash_blake(cmd_str)
    tx_hash = hash_str.decode().replace('+', '-').replace('/', '_').replace('=', '')

    raw_transaction = {
        "hash": tx_hash,
    }
    raw_transaction["sigs"] = []
    raw_transaction["cmd"] = json.dumps(cmd, separators=(',', ':'))
    return json.dumps(raw_transaction, separators=(',', ':'))


print(assemble_balance_payload("k:259e184f5c7cecf261063dd298e250b2303cf896a3d6705eedd35cc8b97cee9b"))