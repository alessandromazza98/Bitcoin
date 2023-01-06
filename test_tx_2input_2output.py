import Address
import Bitcoin
import ECDSAUnit
import HDDerivation
import ToolsUnit

# private key
k = 75282383716026770851796771414193474962426130999119568701422782830663027711075

# public key in (x,y) form
K = ECDSAUnit.multiply(k)
# public key in serialized compressed form
K_ser = HDDerivation.serP(K).hex()

# address derived from K_ser (P2PKH)
address = "mmLPVXUMUTEJZNJKEMasfZQcQfwHCpnrF2"

# dati della tx_0 in input
txid_0 = "ace67281b985bace4806437ad79d4db0276ab682d55b3bb19b74d28df2f8242b"
txid_0_reverse = ToolsUnit.reverse_byte_order(txid_0)
vout_0 = "00000000"
locking_script_0 = Address.create_1output_p2pkh(address)
len_locking_script_0 = ToolsUnit.calculate_varint(locking_script_0)
sequence_0 = "ffffffff"

# dati della tx_1 in input
txid_1 = "a10f28845e9c3c37e563adda4bc9a0bf45e545eb1a47e57ed60af60515f2b69f"
txid_1_reverse = ToolsUnit.reverse_byte_order(txid_1)
vout_1 = "00000000"
locking_script_1 = Address.create_1output_p2pkh(address)
len_locking_script_1 = ToolsUnit.calculate_varint(locking_script_1)
sequence_1 = "ffffffff"

# dati della tx in output
input_count = "02"
version = "01000000"
amount_0 = ToolsUnit.reverse_byte_order(hex(991657)[2:].rjust(16, "0"))
amount_1 = ToolsUnit.reverse_byte_order(hex(2000000)[2:].rjust(16, "0"))
output_count = "02"
locktime = "00000000"
sig_hash = "01000000"
sig_hash_type = "01"
locking_script = Address.create_1output_p2pkh(address)
len_locking_script = ToolsUnit.calculate_varint(locking_script)

# tx to be signed for input_0
tx_to_be_signed_x_input0 = version + input_count + txid_0_reverse + vout_0 + len_locking_script_0 + locking_script_0\
                           + sequence_0 + txid_1_reverse + vout_1 + "00"\
                           + sequence_1 + output_count + amount_0 + len_locking_script + locking_script\
                           + amount_1 + len_locking_script + locking_script + locktime + sig_hash

tx_hash_0 = ToolsUnit.hash256(tx_to_be_signed_x_input0)
tx_hash_0_int = int(tx_hash_0, 16)

r, s = ECDSAUnit.sign(k, tx_hash_0_int)

sign_0 = ToolsUnit.encode_sign_DER(r, s)

sign_0 = sign_0 + sig_hash_type  # append "01"

unlocking_script_0 = Bitcoin.script_sig(K_ser, sign_0)
len_unlocking_script_0 = ToolsUnit.calculate_varint(unlocking_script_0)

# tx to be signed for input 1
tx_to_be_signed_x_input1 = version + input_count + txid_0_reverse + vout_0 + "00"\
                           + sequence_0 + txid_1_reverse + vout_1 + len_locking_script_1 + locking_script_1\
                           + sequence_1 + output_count + amount_0 + len_locking_script + locking_script\
                           + amount_1 + len_locking_script + locking_script + locktime + sig_hash

tx_hash_1 = ToolsUnit.hash256(tx_to_be_signed_x_input1)
tx_hash_1_int = int(tx_hash_1, 16)

r, s = ECDSAUnit.sign(k, tx_hash_1_int)

sign_1 = ToolsUnit.encode_sign_DER(r, s)

sign_1 = sign_1 + sig_hash_type  # append "01"

unlocking_script_1 = Bitcoin.script_sig(K_ser, sign_1)
len_unlocking_script_1 = ToolsUnit.calculate_varint(unlocking_script_1)

# tx signed, ready to be sent to the Bitcoin network
tx_signed = version + input_count + txid_0_reverse + vout_0 + len_unlocking_script_0 + unlocking_script_0 + sequence_0\
            + txid_1_reverse + vout_1 + len_unlocking_script_1 + unlocking_script_1 + sequence_1 + output_count\
            + amount_0 + len_locking_script + locking_script + amount_1 + len_locking_script + locking_script\
            + locktime

print(tx_signed)
