#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import hashlib
import ecdsa
import base58
from typing import Union
from ecdsa.ellipticcurve import PointJacobi

def scrub_input(hex_str_or_bytes: Union[str, bytes]) -> bytes:
    if isinstance(hex_str_or_bytes, str):
        hex_str_or_bytes = bytes.fromhex(hex_str_or_bytes)
    return hex_str_or_bytes


def gen_wif_key(private_key: Union[str, bytes], compressed_WIF: bool = False) -> bytes:
    private_key = scrub_input(private_key)

    # prepended mainnet version byte to private key
    mainnet_private_key = b'\x80' + private_key
    if compressed_WIF:
        mainnet_private_key = b'\x80' + private_key + b'\x01'

    # perform SHA-256 hash on the mainnet_private_key
    sha256 = hashlib.sha256()
    sha256.update(mainnet_private_key)
    hash = sha256.digest()

    # perform SHA-256 on the previous SHA-256 hash
    sha256 = hashlib.sha256()
    sha256.update(hash)
    hash = sha256.digest()

    # create a checksum using the first 4 bytes of the previous SHA-256 hash
    # append the 4 checksum bytes to the mainnet_private_key
    checksum = hash[:4]

    hash = mainnet_private_key + checksum

    # convert mainnet_private_key + checksum into base58 encoded string
    return base58.b58encode(hash)


def decode_wif(wif: str) -> bytes:
    compressed = False
    if wif.startswith('K') or wif.startswith('L'):
        compressed = True
    decoded = base58.b58decode(wif)
    if compressed:
        private_key = decoded[1:-5]  # [80 xxx 1 checksum]
    else:
        private_key = decoded[1:-4]  # [80 xxx checksum]
    return private_key


def derive_public_key(private_key: bytes, compressed: bool = False) -> bytes:
    Q: PointJacobi = int.from_bytes(private_key, byteorder='big') * ecdsa.curves.SECP256k1.generator
    xstr: bytes = Q.x().to_bytes(32, byteorder='big')
    ystr: bytes = Q.y().to_bytes(32, byteorder='big')
    if compressed:
        parity: int = Q.y() & 1
        return (2 + parity).to_bytes(1, byteorder='big') + xstr
    else:
        return b'\04' + xstr + ystr


prikey = bytearray.fromhex('1e99423a4ed27608a15a2616a2b0e9e52ced330ac530edcc32c8ffc6a526aedd')
uncompressed_pubkey = derive_public_key(prikey, False)
print("uncompressed public key =", uncompressed_pubkey.hex())
compressed_pubkey = derive_public_key(prikey, True)
print("compressed public key =", compressed_pubkey.hex())



prikey = '0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d'  # hex
wif = gen_wif_key(prikey)
print(wif)  # 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
wif_compressed = gen_wif_key(prikey, True)
print(wif_compressed)  # KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617

prikey = decode_wif('5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ')
print(prikey.hex())  # 0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d
