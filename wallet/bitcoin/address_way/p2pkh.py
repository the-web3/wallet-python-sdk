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


def pubkey_compressed_to_uncompressed(compressed_pubkey: bytes) -> bytes:
    assert len(compressed_pubkey) == 33
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    x = int.from_bytes(compressed_pubkey[1:33], byteorder='big')
    y_sq = (pow(x, 3, p) + 7) % p
    y = pow(y_sq, (p + 1) // 4, p)
    if compressed_pubkey[0] % 2 != y % 2:
        y = p - y
    y_bytes = y.to_bytes(32, byteorder='big')
    return b'\04' + compressed_pubkey[1:33] + y_bytes  # x + y


def pubkey_to_p2pkh_addr(pubkey: bytes, version: bytes) -> bytes:
    out1 = sha256(pubkey)
    out2 = ripemd160(out1)
    checksum = base58_cksum(version + out2)
    address = base58.b58encode(version + out2 + checksum)
    return address



pubkey = '03f028892bad7ed57d2fb57bf33081d5cfcf6f9ed3d3d7f159c2e2fff579dc341a'
pubkey_uncompressed = b''
pubkey_compressed = b''

if pubkey.startswith('04'):
    pubkey_uncompressed = bytes.fromhex(pubkey)
    if ord(bytearray.fromhex(pubkey[-2:])) % 2 == 0:
        pubkey_compressed_hex_str = '02' + pubkey[2:66]
    else:
        pubkey_compressed_hex_str = '03' + pubkey[2:66]
    pubkey_compressed = bytes.fromhex(pubkey_compressed_hex_str)
else:
    pubkey_uncompressed = pubkey_compressed_to_uncompressed(bytes.fromhex(pubkey))
    pubkey_compressed = bytes.fromhex(pubkey)


print("compressed public key =", pubkey_compressed.hex())
print("uncompressed public key =", pubkey_uncompressed.hex())
version = b'\x00'  # 0x00 for mainnet, 0x6f for testnet
addr_compressed = pubkey_to_p2pkh_addr(pubkey_compressed, version)
addr_uncompressed = pubkey_to_p2pkh_addr(pubkey_uncompressed, version)
print("address (uncompressed) = ", addr_uncompressed)  # 1424C2F4bC9JidNjjTUZCbUxv6Sa1Mt62x
print("address (compressed) = ", addr_compressed)  # 1J7mdg5rbQyUHENYdx39WVWK7fsLpEoXZy
