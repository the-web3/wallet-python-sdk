import bip

bip39_mnemonic = bip.Bip39Mnemonic()
mnemonic_phrase = bip39_mnemonic.generateMnemonic()
print(f"Generated mnemonic phrase: {mnemonic_phrase}")

mnemonic_12_phrase = bip39_mnemonic.mnemonicToEntropy(mnemonic_phrase)
print(f"create mnemonic phrase: {mnemonic_12_phrase.hex()}")

mnemonic_11_phrase = bip39_mnemonic.entropyToMnemonic(mnemonic_12_phrase)
print(f"create mnemonic phrase:", mnemonic_11_phrase)

ok = bip39_mnemonic.validateMnemonic(mnemonic_phrase)
print(f"validateMnemonic:", ok)

seed = bip39_mnemonic.mnemonicToSeed(mnemonic_phrase)
print(f"mnemonicToSeed:", seed.hex())