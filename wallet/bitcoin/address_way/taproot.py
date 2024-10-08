import bip39
import bech32
from bip32 import BIP32, HARDENED_INDEX
from hashlib import sha256
from ecdsa import SECP256k1, SigningKey
from bip32utils import BIP32Key, BIP32_HARDEN

def create_address(mnemonic):
    seed = bip39.phrase_to_seed(mnemonic)
    bip32_root_key = BIP32Key.fromEntropy(seed)
    path = "m/44'/0'/0'/0/0"
    key = bip32_root_key
    for level in path.split('/')[1:]:
        if level.endswith("'"):
            index = BIP32_HARDEN + int(level[:-1])
        else:
            index = int(level)
        key = key.ChildKey(index)
    address = key.Address()
    return address

def generate_taproot_address(mnemonic):
    seed = bip39.phrase_to_seed(mnemonic)
    bip32 = BIP32.from_seed(seed)
    path = "m/86'/0'/0'/0/0"
    child_key = bip32.get_privkey_from_path(path)
    private_key = SigningKey.from_string(child_key, curve=SECP256k1)
    public_key = private_key.get_verifying_key().to_string("compressed")
    tweak = sha256(b'TapTweak' + public_key[1:]).digest()
    tweaked_pubkey = bytearray(public_key)
    for i in range(32):
        tweaked_pubkey[1 + i] ^= tweak[i]
    witver = 1  # witness version for Taproot
    witprog = tweaked_pubkey[1:33]
    address = bech32.encode('bc', witver, witprog)
    return address


mnemonic = 'praise you muffin lion enable neck grocery crumble super myself license ghost'
taproot_address = generate_taproot_address(mnemonic)
print('Taproot Address:', taproot_address)