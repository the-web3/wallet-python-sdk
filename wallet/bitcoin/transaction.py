from bitcoinlib.transactions import Transaction
from bitcoinlib.keys import HDKey



class BtcTransaction:
    def __init__(self):
        pass

    def buildAndsignTx(self, input_list, output_list, private):
        tx = Transaction()
        for input in input_list:
            tx.add_input(input['previous_txid'], input['index'])
        for output in output_list:
            tx.add_output(output["address"], output["value"])
        tx.version = 2
        tx.locktime = 0
        tx_digest = tx.signature_hash()

        hdkey = HDKey()
        private_key = hdkey.private_hex()
        public_key = hdkey.public_hex()
        taproot_address = hdkey.address_taproot()

        print("Taproot 地址:", taproot_address)

        # 创建交易对象
        tx = Transaction.import_raw(r)

        # 对交易进行 Taproot 签名
        tx.sign(private_key, hash_type='SIGHASH_ALL', schnorr=True)

        # 导出签名后的交易
        signed_tx = tx.as_hex()
        with open('signed_tx.hex', 'w') as f:
            f.write(signed_tx)

        print("签名后的交易:", signed_tx)

