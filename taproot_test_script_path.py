import BIP350
import Schnorr
import ToolsUnit

'''
Il senso di questo test è il seguente:
Testare una spesa P2TR tramite script path

1. Creare l'address taproot corretto
2. Inviarsi dei fondi a tale address creato al punto 1
3. Spendere questi fondi verso un nuovo indirizzo

Vedasi iPad per schema grafico
'''

LEAF_VER = b'\xc0'

# internal private and public key
d = 18968816317819169306095104891728354025797295648084455976845396390496379316944
P_point = Schnorr.multiply(d)
if P_point[1] % 2 != 0:
    d = Schnorr.n - d
    P_point = Schnorr.multiply(d)
P = Schnorr.ser256_schnorr(P_point)

# s1
k1 = 78931426514357468882601520915645133116503184441831846482294115903507660427950
P1_point = Schnorr.multiply(k1)
if P1_point[1] % 2 != 0:
    k1 = Schnorr.n - k1
    P1_point = Schnorr.multiply(k1)
P1 = Schnorr.ser256_schnorr(P1_point)
s1_hex = "20" + P1.hex() + "ac"  # 20 = 32 in esadecimale ed è la lunghezza della pubkey | ac = OP_CHECKSIG
s1_len_hex = ToolsUnit.calculate_varint(s1_hex)
tap_leaf_s1 = Schnorr.tagged_hash("TapLeaf", LEAF_VER + bytes.fromhex(s1_len_hex + s1_hex))

# s2
k2 = 53223457762164509281563914254149592059900713682793766747801624337469509007268
P2_point = Schnorr.multiply(k2)
if P2_point[1] % 2 != 0:
    k2 = Schnorr.n - k2
    P2_point = Schnorr.multiply(k2)
P2 = Schnorr.ser256_schnorr(P2_point)
s2_hex = "20" + P2.hex() + "ac"  # 20 = 32 in esadecimale ed è la lunghezza della pubkey | ac = OP_CHECKSIG
s2_len_hex = ToolsUnit.calculate_varint(s2_hex)
tap_leaf_s2 = Schnorr.tagged_hash("TapLeaf", LEAF_VER + bytes.fromhex(s2_len_hex + s2_hex))

# s3
k3 = 48034867036800174573932088253129938072033279788016841632941291149515077395801
P3_point = Schnorr.multiply(k3)
if P3_point[1] % 2 != 0:
    k3 = Schnorr.n - k3
    P3_point = Schnorr.multiply(k3)
P3 = Schnorr.ser256_schnorr(P3_point)
s3_hex = "20" + P3.hex() + "ac"  # 20 = 32 in esadecimale ed è la lunghezza della pubkey | ac = OP_CHECKSIG
s3_len_hex = ToolsUnit.calculate_varint(s3_hex)
tap_leaf_s3 = Schnorr.tagged_hash("TapLeaf", LEAF_VER + bytes.fromhex(s3_len_hex + s3_hex))

# tagged branch s1s2
tap_branch_s1s2 = Schnorr.tagged_hash("TapBranch", b''.join(sorted([tap_leaf_s1, tap_leaf_s2])))

# tagged branch s1s2s3
tap_branch_s1s2s3 = Schnorr.tagged_hash("TapBranch", b''.join(sorted([tap_branch_s1s2, tap_leaf_s3])))

# tap tweak t
t = Schnorr.tagged_hash("TapTweak", P + tap_branch_s1s2s3)
t_int = Schnorr.int_from_bytes(t)

# taproot pubkey Q = P + tG
Q_point = Schnorr.add(P_point, Schnorr.multiply(t_int))
Q = Schnorr.ser256_schnorr(Q_point)

# address_from
addr_from = BIP350.encode_addr_bech32m(Q, "False")  # tb1p4mxklg32p85ukf9qrgep3lkhuqhu9lj5qwcnatec2c0gma2790rqgutkdg

# ----------
# I'll create a tx spending from addr_from to addr_to using script path S1
# ----------

# create addr_to
kto = 106223809955248159900714945014279058380174181497200169336538554075749085215638
Pto_point = Schnorr.multiply(kto)
if Pto_point[1] % 2 != 0:
    kto = Schnorr.n - k1
    Pto_point = Schnorr.multiply(kto)
Pto = Schnorr.ser256_schnorr(Pto_point)
addr_to = BIP350.encode_addr_bech32m(Pto, "False")  # tb1pvhc33fd40y2vx2j8tx9hu338chxwpdy4s09lhm2mpmgee7mvwlkqd0cj2t

# data for the tx that sent me 0.00009644 BTC (taproot)
txid = "bc9cba8dbdb6f35db1db856d440f3db5cd672cfcf5312539a8eb6c1319e6dda2"
txid_reverse = ToolsUnit.reverse_byte_order(txid)
vout = "00000000"  # 0
amount_received = ToolsUnit.reverse_byte_order(hex(9644)[2:].rjust(16, "0"))  # 9644 sats = 0.00009644 BTC
locking_script_input = BIP350.create_witness_locking_script(addr_from, "False")
len_locking_script_input = ToolsUnit.calculate_varint(locking_script_input)

# data for the tx I want to create
marker = "00"
flag = "01"
input_count = "01"
version = "01000000"
amount_to_send = ToolsUnit.reverse_byte_order(hex(9000)[2:].rjust(16, "0"))  # 9644 sats = 0.00009644 BTC
sequence = "ffffffff"
output_count = "01"
locking_script_dest = BIP350.create_witness_locking_script(addr_to, "False")
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
spend_type = bytes.fromhex("02")  # script path -> ext_flag = 1

# input_index (4): index of this input in the transaction input vector. Index of the first input is 0
input_index = bytes.fromhex("00000000")  # there is only 1 input in this tx I'm constructing

# We use SCRIPT PATH, so we have to add
# 1. tapleaf_hash of the script I am using to spend this UTXO
# 2. b'\x00' which is key_version, representing the current version of public keys in the
#            tapscript signature opcode execution
# 3. codesep_pos = the opcode position of the last executed OP_CODESEPARATOR before the currently executed
#                  signature opcode, with the value in little endian (or 0xffffffff if none executed).
scrip_path_used = tap_leaf_s1 + b'\x00' + bytes.fromhex("ffffffff")

sig_to_hash = b'\x00' + hash_type + nversion + nlocktime + sha_prevouts + sha_amounts + sha_scriptpubkeys + sha_sequences\
              + sha_outputs + spend_type + input_index + scrip_path_used  # first element is b'\x00' which is epoch 0

sighash = Schnorr.tagged_hash("TapSighash", sig_to_hash)

# ----------
# SIGNING w/ k1 - SCRIPT PATH -> S1
# ----------

sig = Schnorr.sign_schnorr(private_key_int=k1, msg_hash_bytes=sighash)

# ----------
# CONSTRUCTING WITNESS
# ----------
witness_count = "03"  # [Stack element(s) satisfying TapScript_S1]
#                       [TapScript_S1]
#                       [Controlblock c]

r, s = sig
sig_hex = r.hex() + s.hex()
witness_sig_size = ToolsUnit.calculate_varint(sig_hex)


if Q_point[1] % 2 != 0:
    parity_bit = b'\x01'
else:
    parity_bit = b'\x00'

# control block:
# Its first byte stores the leaf version (#3) (top 7 bits) and the sign bit (#6) (bottom bit).
# The next 32 bytes store the (X coordinate only, because x-only key) of the internal public key (#4)
# Every block of 32 bytes after that encodes a component of the Merkle path (#5) connecting the leaf
# to the root (and then, the tweak), going in bottom-up direction.
control_block = bytes([LEAF_VER[0] + parity_bit[0]]) + P + tap_leaf_s2 + tap_leaf_s3
len_control_block = ToolsUnit.calculate_varint(control_block.hex())

witness = witness_count + witness_sig_size + sig_hex + s1_len_hex + s1_hex + len_control_block + control_block.hex()


# ----------
# TX READY
# ----------

tx = version + marker + flag + input_count + txid_reverse + vout + "00" + sequence\
    + output_count + amount_to_send + len_locking_script_dest + locking_script_dest\
    + witness + locktime

print(tx)
