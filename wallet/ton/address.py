from ton_client.client import TonClient, DEVNET_BASE_URL
from ton_client.types import KeyPair, ClientConfig

# 初始化TON客户端
client = TonClient(config=ClientConfig(network=DEVNET_BASE_URL))



# 通过助记词生成密钥对
keys = client.crypto.mnemonic_derive_sign_keys("champion junior glimpse analyst plug jump entire barrel slight swim hidden remove")
print(keys)