import Address
import ECDSA
import Tools

##### TEST #####

sk = "f94a840f1e1a901843a75dd07ffcc5c84478dc4f987797474c9393ac53ab55e6"
sk_int = int(sk, 16)
pk = Tools.calculate_compressed_pk(sk_int)
k = 123456789

txid = "b7994a0db2f373a29227e1d90da883c6ce1cb0dd2d6812e4558041ebbbcfa54b"
vout = "00000000"
amount = "983a000000000000"
version = "01000000"
address_send = Address.pk_to_btc_address(pk)
address_dest = "1HQ9JGeF1X3HWWJYF3cyYFBuQWpmb1hJkN"

unsigned_tx_a, unsigned_tx_b, unsigned_tx_c = Address.construct_unsigned_tx(txid, vout, address_send, address_dest,
                                                                            amount, version)

tx = Address.construct_signed_tx(unsigned_tx_a, unsigned_tx_b, unsigned_tx_c, sk_int, k)

print(tx)

test = "0100000001b7994a0db2f373a29227e1d90da883c6ce1cb0dd2d6812e4558041ebbbcfa54b000000006a473044022008f4f37e2d8f74e18c1b8fde2374d5f28402fb8ab7fd1cc5b786aa40851a70cb02201f40afd1627798ee8529095ca4b205498032315240ac322c9d8ff0f205a93a580121024aeaf55040fa16de37303d13ca1dde85f4ca9baa36e2963a27a1c0c1165fe2b1ffffffff01983a0000000000001976a914b3e2819b6262e0b1f19fc7229d75677f347c91ac88ac00000000"
print(test)

print(tx == test)