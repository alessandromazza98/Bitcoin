import Address
import BIP173
import Bitcoin
import ECDSAUnit
import HDDerivation
import ToolsUnit

"""
Bene! Adesso se proprio vogliamo fare i fiki:

1. fare una tx P2WPKH che spende da due input (derivanti rispettivamente da P2WPKH e 1 P2PKH)
"""


# private key (int)
k0 = 58378730072472222993614750577384691242803919056318591792313519292467644999177
k1 = 75282383716026770851796771414193474962426130999119568701422782830663027711075
kdest = 109126534092984758174112867139394478193162733443899929891975271021497119625542

# public key K (int, int)
K0 = ToolsUnit.calculate_pk(k0)
K1 = ToolsUnit.calculate_pk(k1)
Kdest = ToolsUnit.calculate_pk(kdest)

# serialize K (bytes)
K0ser = HDDerivation.serP(K0)
K1ser = HDDerivation.serP(K1)
Kdest_ser = HDDerivation.serP(Kdest)

# generate the destination address (w/ kdest)
addr_dest = BIP173.encode_addr_bech32(ToolsUnit.hash160(Kdest_ser), "False")
# tb1qrh8xz8ul5hp50vqx5vmkt2ljk3mpdqyuvxlgnr


# ----------
# I'll create a tx spending from 2 inputs (P2WPKH & P2PKH) and sending to addr_dest
# ----------

# data for the tx that sent me 0.015 bitcoin (segwit)
txid0 = "6a19b85084ba4cd83d343eb31218bb64f059a79f30dd4161f08cd8febfedf8f5"
txid0_reverse = ToolsUnit.reverse_byte_order(txid0)
vout0 = "00000000"  # 0
amount0_received = ToolsUnit.reverse_byte_order(hex(1500000)[2:].rjust(16, "0"))  # 1500000 sats = 0.015 BTC
addr_input0 = BIP173.encode_addr_bech32(ToolsUnit.hash160(K0ser), "False")
locking_script_input0 = BIP173.create_witness_locking_script(addr_input0, "False")
len_locking_script_input0 = ToolsUnit.calculate_varint(locking_script_input0)

# data for the tx that sent me 0.02 bitcoin (non-segwit)
txid1 = "09d78347432859addf23cc4e6e21b8fa81f52471fe3c99f053e0dce94ec63ef8"
txid1_reverse = ToolsUnit.reverse_byte_order(txid1)
vout1 = "01000000"  # 1
amount1_received = ToolsUnit.reverse_byte_order(hex(2000000)[2:].rjust(16, "0"))  # 2000000 sats = 0.02 BTC
addr_input1 = Address.pk_to_btc_address(K1ser.hex(), "6F")
locking_script_input1 = Address.create_1output_p2pkh(addr_input1)
len_locking_script_input1 = ToolsUnit.calculate_varint(locking_script_input1)

# data for the tx I want to create
marker = "00"
flag = "01"
input_count = "02"
version = "01000000"
amount_to_send = ToolsUnit.reverse_byte_order(hex(3400000)[2:].rjust(16, "0"))  # 3400000 sats = 0.034 BTC
sequence = "ffffffff"
output_count = "01"
locking_script_dest = BIP173.create_witness_locking_script(addr_dest, "False")
len_locking_script_dest = ToolsUnit.calculate_varint(locking_script_dest)
locktime = "00000000"
sig_hash_type = "01000000"
sig_hash_type_2bytes = "01"


# ----------
# SIGNING INPUT 0 (segwit)
# ----------

# scriptCode
scriptCode = BIP173.create_witness_script_code_P2WPKH(addr_input0, "False")

# hashPrevouts = hash256^2(txid_reverse + vout of all inputs)
hashPrevouts = ToolsUnit.hash256(txid0_reverse + vout0 + txid1_reverse + vout1)

# hashSequence =  hash256^2(sequence of all inputs)
hashSequence = ToolsUnit.hash256(sequence + sequence)

# hashOutputs =  hash256^2(outputs_amount + len_locking script + locking_script of all outputs)
hashOutputs = ToolsUnit.hash256(amount_to_send + len_locking_script_dest + locking_script_dest)

# outpoint = txid_reverse + vout of the input I am signing
outpoint = txid0_reverse + vout0

# tx to be signed for input 0 (segwit)
tx_to_be_hashed0 = version + hashPrevouts + hashSequence + outpoint + scriptCode + amount0_received + sequence\
    + hashOutputs + locktime + sig_hash_type

# hashing
sigHash0 = ToolsUnit.hash256(tx_to_be_hashed0)

# converting sigHash in int to be signed
sigHash0_int = int(sigHash0, 16)

# signing
r0, s0 = ECDSAUnit.sign(k0, sigHash0_int)

# encoding in DER
sig0_der = ToolsUnit.encode_sign_DER(r0, s0)

# append sighashtype_2bytes
sig0_der = sig0_der + sig_hash_type_2bytes


# ----------
# SIGNING INPUT 1 (non-segwit)
# ----------

# tx to be signed
tx_to_be_hashed1 = version + input_count + txid0_reverse + vout0 + "00" + sequence\
    + txid1_reverse + vout1 + len_locking_script_input1 + locking_script_input1 + sequence\
    + output_count + amount_to_send + len_locking_script_dest + locking_script_dest + locktime + sig_hash_type

# hashing
sigHash1 = ToolsUnit.hash256(tx_to_be_hashed1)

# converting sigHash in int to be signed
sigHash1_int = int(sigHash1, 16)

# signing
r1, s1 = ECDSAUnit.sign(k1, sigHash1_int)

# encoding in DER
sig1_der = ToolsUnit.encode_sign_DER(r1, s1)

# append sighashtype_2bytes
sig1_der = sig1_der + sig_hash_type_2bytes

unlocking_script_input1 = Bitcoin.script_sig(K1ser.hex(), sig1_der)
len_unlocking_script_input1 = ToolsUnit.calculate_varint(unlocking_script_input1)


# ----------
# WITNESS DATA for INPUT 0
# ----------

witness0_count = "02"  # dersig and pkhash
witness0_sig_size = ToolsUnit.calculate_varint(sig0_der)
K0ser_size = ToolsUnit.calculate_varint(K0ser.hex())


# ----------
# WITNESS DATA for INPUT 1 (non-segwit) -> just "00"
# ----------

witness1_count = "00"


# ----------
# WITNESS DATA COMPLETE
# ----------

witness = witness0_count + witness0_sig_size + sig0_der + K0ser_size + K0ser.hex() + witness1_count


# ----------
# TX READY
# ----------

tx = version + marker + flag + input_count + txid0_reverse + vout0 + "00" + sequence\
    + txid1_reverse + vout1 + len_unlocking_script_input1 + unlocking_script_input1 + sequence\
    + output_count + amount_to_send + len_locking_script_dest + locking_script_dest\
    + witness + locktime

print(tx)
