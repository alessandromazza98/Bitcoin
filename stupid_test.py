import ToolsUnit

tx = "02000000000101ec8bcacceaedf0cce46a1d5c1d74a2b034c65e291c53b80b424040fef4f6c7920100000000feffffff0211f802aa00000000160014863436c49c3de9aabdb25fd9b5649927b332a3d379b91700000000001600142435d239c6731ee567d0afc1ab354fc077ed53880247304402201096c2ea2a3edcd0114a5081a153354337dadc97cce2e24742c882c074c1e77402201de46b48de73fe57c4e020fbccfa77a679db3efcf4ee7ae60edb656784b54010012103b30d1544bbedffeafae045cec73deaf75a7919718d31c4dbd063104016e030fc47da2400"

version = tx[:8]
marker = tx[8:10]
flag = tx[10:12]
input_count = tx[12:14]
txid_reverse = tx[14:78]
vout = tx[78:86]
len_unlocking_script = tx[86:88]  # uguale a "00"
unlocking_script = tx[88:int(len_unlocking_script, 16)*2+88]
sequence = tx[88:96]
output_count = tx[96:98]
amount1 = tx[98:114]
len_locking_script1 = tx[114:116]  # uguale a "16"
locking_script1 = tx[116:116+int(len_locking_script1, 16)*2]
amount2 = tx[160:176]
len_locking_script2 = tx[176:178]  # uguale a "16"
locking_script2 = tx[178:178+int(len_locking_script2, 16)*2]
witness_count = tx[222:224]
len_witness1 = tx[224:226]
witness1 = tx[226:226+int(len_witness1, 16)*2]
len_witness2 = tx[368:370]
witness2 = tx[370:370+int(len_witness2, 16)*2]
locktime = tx[370+int(len_witness2, 16)*2:]

print("version: " + version)
print("marker: " + marker)
print("flag: " + flag)
print("input count: " + input_count)
print("txid_reverse: " + txid_reverse)
print("vout: " + vout)
print("unlocking script size: " + len_unlocking_script)
print("unlocking script: " + unlocking_script)
print("sequence: " + sequence)
print("output count: " + output_count)
print("amount 1: " + amount1 )
print("locking script 1 size: " + len_locking_script1)
print("locking script 1: " + locking_script1)
print("amount 2: " + amount2)
print("locking script 2 size: " + len_locking_script2)
print("locking script 2: " + locking_script2)
print("witness count: " + witness_count)
print("witness 1 size: " + len_witness1)
print("witness 1: " + witness1)
print("witness 2 size: " + len_witness2)
print("witness 2: " + witness2)
print("locktime: " + locktime)

print("\n------------------------------\n")

print(witness1)
print(witness1[:int("47",16)*2])

test = "87b16bf5c5e43bf1dbd69440556f4f5a1430b5fd87"
print(ToolsUnit.calculate_varint(test))