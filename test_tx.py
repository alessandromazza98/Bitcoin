import Address
import Bitcoin
import ECDSAUnit
import HDDerivation
import ToolsUnit

k = 75282383716026770851796771414193474962426130999119568701422782830663027711075

K = ECDSAUnit.multiply(k)

K_ser = HDDerivation.serP(K).hex()

address = "mmLPVXUMUTEJZNJKEMasfZQcQfwHCpnrF2"

# dati delle tx con cui ho ricevuto i sats
txid = "d98b1b09a5256e6501f988e9b16a4911e7f9c111d5154f24fbc9a5748d99158d"
txid_reverse = ToolsUnit.reverse_byte_order(txid)
vout = "00000000"
locking_script = Address.create_1output_p2pkh(address)
len_locking_script = ToolsUnit.calculate_varint(locking_script)

# dati della tx che sto per inviare
input_count = "01"
version = "01000000"
amount = ToolsUnit.reverse_byte_order(hex(1500000)[2:].rjust(16, "0"))  # 1506223 sats
sequence = "ffffffff"
output_count = "01"
locktime = "00000000"
sig_hash = "01000000"
sig_hash_type = "01"

tx_to_be_signed = version + input_count + txid_reverse + vout + len_locking_script + locking_script + sequence + output_count\
                  + amount + len_locking_script + locking_script + locktime + sig_hash

tx_hash = ToolsUnit.hash256(tx_to_be_signed)
tx_hash_int = int(tx_hash, 16)

r, s = ECDSAUnit.sign(k, tx_hash_int)

sign = ToolsUnit.encode_sign_DER(r, s)
sign = sign + sig_hash_type

unlocking_script = Bitcoin.script_sig(K_ser, sign)
len_unlocking_script = ToolsUnit.calculate_varint(unlocking_script)

tx_signed = version + input_count + txid_reverse + vout + len_unlocking_script + unlocking_script + sequence + output_count\
                  + amount + len_locking_script + locking_script + locktime

print(tx_signed)
