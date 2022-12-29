import base58

import Address
import Tools

address1 = "1HQ9JGeF1X3HWWJYF3cyYFBuQWpmb1hJkN"

locking = Address.create_1output_p2pkh(address1)

print(locking)
print("\n")

sk = "f94a840f1e1a901843a75dd07ffcc5c84478dc4f987797474c9393ac53ab55e6"
sk_int = int(sk, 16)
pk = Tools.calculate_compressed_pk(sk_int)

print(pk + "\n\n")

address2 = Address.pk_to_btc_address(pk)

print(address2)

locking2 = Address.create_1output_p2pkh(address2)

print(locking2 + "\n\n")

address_ouput = base58.b58encode_check(bytes.fromhex("00b3e2819b6262e0b1f19fc7229d75677f347c91ac")).decode()

print(address_ouput)