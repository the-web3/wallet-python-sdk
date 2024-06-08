import hashlib
from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa.curves import Curve


class SchnorrSignObj:
    curve: Curve
    def __init__(self):
        # 椭圆曲线参数
        self.curve = SECP256k1

    def schnorr_sign(self, private_key, message):
        # 生成私钥和公钥
        signing_key = SigningKey.from_string(private_key, curve=self.curve)
        verifying_key = signing_key.get_verifying_key()

        # 生成随机数 r
        r = SigningKey.generate(curve=self.curve).privkey.secret_multiplier
        R = VerifyingKey.from_public_point(r * self.curve.generator, curve=self.curve)

        # 计算哈希 e
        e = hashlib.sha256(R.to_string() + verifying_key.to_string() + message).digest()
        e = int.from_bytes(e, 'big')

        # 计算签名 s
        s = (r + e * signing_key.privkey.secret_multiplier) % self.curve.order
        return R.to_string(), s.to_bytes(32, 'big')

    def schnorr_verify(self, public_key, message, signature):
        # 解析签名
        R = VerifyingKey.from_string(signature[0], curve=self.curve)
        s = int.from_bytes(signature[1], 'big')

        # 计算哈希 e
        e = hashlib.sha256(signature[0] + public_key.to_string() + message).digest()
        e = int.from_bytes(e, 'big')

        # 验证签名
        sG = VerifyingKey.from_public_point(s * self.curve.generator, curve=self.curve)
        ReP = VerifyingKey.from_public_point(R.pubkey.point + e * public_key.pubkey.point, curve=self.curve)
        return sG.to_string() == ReP.to_string()

