import BIP350
import Schnorr
import ToolsUnit

# privkey1 and pubkey1 - from address
privkey1 = 115062707324911670947436473822948305952960242165803084361225582276718195358086
pubkey1_point = Schnorr.multiply(privkey1)
pubkey1 = Schnorr.ser256_schnorr(pubkey1_point)  # bytes

# addr_from = BIP350.encode_addr_bech32m(pubkey1)
addr_from = BIP350.encode_addr_bech32m(pubkey1, "False")
# tb1pr8ja6wp3wzwzpt9ervw6jsd9nchlpsfa7k7qyrygj3g3srlpxxyqjwv8av

# privkey2 and pubkey2 - to address
privkey2 = 75282383716026770851796771414193474962426130999119568701422782830663027711075
pubkey2_point = Schnorr.multiply(privkey2)
pubkey2 = Schnorr.ser256_schnorr(pubkey2_point)  # bytes

# addr_to= BIP350.encode_addr_bech32m(pubkey1)
addr_to = BIP350.encode_addr_bech32m(pubkey2, "False")
# tb1pkqy6q5qlhejfdcgvv47dqnt468nqzl82am5kqz374e6ddpxllxfqm6hpzj


# ----------
# I'll create a tx spending from 1 inputs (P2TR) derived from addr_from and sending to addr_to
# ----------

# data for the tx that sent me 0.00991456 BTC (taproot)
txid = "23168058d8701d5c2c738500fc7261e313511f333db1fc93f74bb935b9fd7458"
txid_reverse = ToolsUnit.reverse_byte_order(txid)
vout = "00000000"  # 0
amount_received = ToolsUnit.reverse_byte_order(hex(991456)[2:].rjust(16, "0"))  # 991456 sats = 0.00991456 BTC
locking_script_input = BIP350.create_witness_locking_script(addr_from, "False")  # 512019e5dd3831709c20acb91b1da941a59e2ff0c13df5bc020c889451180fe13188
len_locking_script_input = ToolsUnit.calculate_varint(locking_script_input)


# data for the tx I want to create
marker = "00"
flag = "01"
input_count = "01"
version = "01000000"
amount_to_send = ToolsUnit.reverse_byte_order(hex(990000)[2:].rjust(16, "0"))  # 990000 sats = 0.0099 BTC
sequence = "ffffffff"
output_count = "01"
locking_script_dest = BIP350.create_witness_locking_script(addr_to, "False")  # 5120b009a0501fbe6496e10c657cd04d75d1e6017ceaeee9600a3eae74d684dff992
len_locking_script_dest = ToolsUnit.calculate_varint(locking_script_dest)
locktime = "00000000"
sig_hash_type = "00000000"  # SIGHASH_ALL_TAPROOT 00
sig_hash_type_1bytes = "00"  # SIGHASH_ALL_TAPROOT 00


# ----------
# CONSTRUCTING SIGHASH x INPUT (taproot)
# ----------

hash_type = bytes.fromhex(sig_hash_type_1bytes)
nversion = bytes.fromhex(version)
nlocktime = bytes.fromhex(locktime)

# sha_prevouts (32) = SHA256(serialization of all input outpoints)
sha_prevouts = Schnorr.hash_sha256(bytes.fromhex(txid_reverse + vout))

# sha_amounts (32): the SHA256 of the serialization of all spent output amounts
sha_amounts = Schnorr.hash_sha256(bytes.fromhex(amount_received))

# sha_scriptpubkeys (32): the SHA256 of all spent outputs' scriptPubKeys, serialized as script inside CTxOut
sha_scriptpubkeys = Schnorr.hash_sha256(bytes.fromhex(len_locking_script_input + locking_script_input))

# sha_sequences (32): the SHA256 of the serialization of all input nSequence.
sha_sequences = Schnorr.hash_sha256(bytes.fromhex(sequence))

# sha_outputs (32): the SHA256 of the serialization of all outputs in CTxOut format.
sha_outputs = Schnorr.hash_sha256(bytes.fromhex(amount_to_send + len_locking_script_dest + locking_script_dest))

# spend_type (1): equal to (ext_flag * 2) + annex_present, where annex_present is 0 if no annex is present,
# or 1 otherwise (the original witness stack has two or more witness elements,
# and the first byte of the last element is 0x50)
spend_type = bytes.fromhex("00")

# input_index (4): index of this input in the transaction input vector. Index of the first input is 0
input_index = bytes.fromhex("00000000")

sig_to_hash = b'\x00' + hash_type + nversion + nlocktime + sha_prevouts + sha_amounts + sha_scriptpubkeys + sha_sequences\
    + sha_outputs + spend_type + input_index  # first element is b'\x00' which is epoch 0

sighash = Schnorr.tagged_hash("TapSighash", sig_to_hash)


# ----------
# SIGNING
# ----------

sig = Schnorr.sign_schnorr(private_key_int=privkey1, msg_hash_bytes=sighash)


# ----------
# CONSTRUCTING WITNESS
# ----------
witness_count = "01"  # sig
r, s = sig
sig_hex = r.hex() + s.hex()
witness_sig_size = ToolsUnit.calculate_varint(sig_hex)

witness = witness_count + witness_sig_size + sig_hex

# ----------
# TX READY
# ----------

tx = version + marker + flag + input_count + txid_reverse + vout + "00" + sequence\
    + output_count + amount_to_send + len_locking_script_dest + locking_script_dest\
    + witness + locktime

print(tx)
