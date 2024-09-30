#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import hashlib
import base58


def sha256(inputs: bytes) -> bytes:
    sha = hashlib.sha256()
    sha.update(inputs)
    return sha.digest()


def ripemd160(inputs: bytes) -> bytes:
    rip = hashlib.new('ripemd160')
    rip.update(inputs)
    return rip.digest()


def base58_cksum(inputs: bytes) -> bytes:
    s1 = sha256(inputs)
    s2 = sha256(s1)
    checksum = s2[0:4]
    return checksum


def pubkey_to_p2sh_p2wpkh_addr(pubkey_compressed: bytes) -> bytes:
    """ Derives p2sh-segwit (p2sh p2wpkh) address from pubkey """
    pubkey_hash = sha256(pubkey_compressed)
    rip = ripemd160(pubkey_hash)
    redeem_script = b'\x00\x14' + rip  # 0x00: OP_0, 0x14: PushData
    redeem_hash = sha256(redeem_script)
    redeem_rip = ripemd160(redeem_hash)

    # Base-58 encoding with a checksum
    version = b'\x05'  # 0x05 for mainnet, 0xc4 for testnet
    checksum = base58_cksum(version + redeem_rip)
    address = base58.b58encode(version + redeem_rip + checksum)
    return address


pubkey = '03f028892bad7ed57d2fb57bf33081d5cfcf6f9ed3d3d7f159c2e2fff579dc341a'
addr_p2sh_segwit = pubkey_to_p2sh_p2wpkh_addr(bytes.fromhex(pubkey))
print("p2sh-segwit address", addr_p2sh_segwit)  # 3FyC6EYuxW22uj4CaEGjNCjxeg7gHyFeVv
