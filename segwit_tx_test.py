import BIP173
import ECDSAUnit
import HDDerivation
import ToolsUnit

# order of the elliptic curve
n = 115792089237316195423570985008687907852837564279074904382605163141518161494337

# generate a random k (private key), between 0 and (n-1).
k = 58378730072472222993614750577384691242803919056318591792313519292467644999177

# generate the public key K
K = ECDSAUnit.multiply(k)

# serialize in compressed form K. Kser is a bytes type
Kser = HDDerivation.serP(K)

# hash160 Kser
Khash160 = ToolsUnit.hash160(Kser)

# generate a P2WPKH addr. addr is a str type
addr = BIP173.encode_addr_bech32(Khash160, "False")
print(addr)

# ----------
# I'll create a tx spending from addr and sending to addr (same addr, in cycle)
# ----------

# data for the tx that sent me ~0.015 bitcoin
txid = "ee76f0c914cdd2b221c4a3ebdf611e262e8147b0969b9d43d9f989729ab5f666"
txid_reverse = ToolsUnit.reverse_byte_order(txid)
vout = "01000000"  # 1
amount_received = ToolsUnit.reverse_byte_order(hex(1554809)[2:].rjust(16, "0"))  # 1554809 sats = 0.015 BTC

# data for the tx I want to create
marker = "00"
flag = "01"
input_count = "01"
version = "01000000"
amount_to_send = ToolsUnit.reverse_byte_order(hex(1500000)[2:].rjust(16, "0"))  # 1500000 sats = 0.015 BTC
sequence = "ffffffff"
output_count = "01"
locking_script = BIP173.create_witness_locking_script(addr, "False")
len_locking_script = ToolsUnit.calculate_varint(locking_script)
locktime = "00000000"
sig_hash_type = "01000000"
sig_hash_type_2bytes = "01"

# scriptCode
scriptCode = BIP173.create_witness_script_code_P2WPKH(addr, "False")

# hashPrevouts = hash256^2(txid_reverse + vout of all inputs)
hashPrevouts = ToolsUnit.hash256(txid_reverse + vout)

# hashSequence =  hash256^2(sequence of all inputs)
hashSequence = ToolsUnit.hash256(sequence)

# hashOutputs =  hash256^2(outputs_amount + len_locking script + locking_script of all outputs)
hashOutputs = ToolsUnit.hash256(amount_to_send + len_locking_script + locking_script)

# outpoint = txid_reverse + vout of the input I am signing
outpoint = txid_reverse + vout

# ----------
# SIGNING
# ----------

# tx to be signed
tx_to_be_hashed = version + hashPrevouts + hashSequence + outpoint + scriptCode + amount_received + sequence\
    + hashOutputs + locktime + sig_hash_type

# hashing
sigHash = ToolsUnit.hash256(tx_to_be_hashed)

# converting sigHash in int to be signed
sigHash_int = int(sigHash, 16)

# signing
r, s = ECDSAUnit.sign(k, sigHash_int)

# encoding in DER
sig_der = ToolsUnit.encode_sign_DER(r, s)

# append sighashtype_2bytes
sig_der = sig_der + sig_hash_type_2bytes

# ----------
# WITNESS DATA
# ----------

witness_count = "02"  # dersig and pkhash
witness_sig_size = ToolsUnit.calculate_varint(sig_der)
Kser_size = ToolsUnit.calculate_varint(Kser.hex())

witness = witness_count + witness_sig_size + sig_der + Kser_size + Kser.hex()

# ----------
# TX READY
# ----------

tx = version + marker + flag + input_count + txid_reverse + vout + "00" + sequence\
    + output_count + amount_to_send + len_locking_script + locking_script + witness + locktime

print(tx)
