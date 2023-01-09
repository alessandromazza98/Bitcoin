import ToolsUnit

tx = "0100000000010166f6b59a7289f9d9439d9b96b047812e261e61dfeba3c421b2d2cd14c9f076ee0100000000ffffffff0160e31600000000001600142435d239c6731ee567d0afc1ab354fc077ed538802483045022100fe34179f2bc32f4e50c92b8f69863b1b269f37034cb147b5a4c26bde998227a402207547b5ea83b23f5df6c3c0f99c406b44652c3f913fb511a4997c10e661693386012103ec8cd523f250452125005123c47460c1945f4b8662a05b90818a3761d7e104d700000000"

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
witness_count = tx[160:162]
len_witness1 = tx[162:164]
witness1 = tx[164:164+int(len_witness1, 16)*2]
len_witness2 = tx[164+int(len_witness1, 16)*2:164+int(len_witness1, 16)*2+2]
witness2 = tx[164+int(len_witness1, 16)*2+2:164+int(len_witness1, 16)*2+2+int(len_witness2, 16)*2]
locktime = tx[164+int(len_witness1, 16)*2+2+int(len_witness2, 16)*2:]

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
print("witness count: " + witness_count)
print("witness 1 size: " + len_witness1)
print("witness 1: " + witness1)
print("witness 2 size: " + len_witness2)
print("witness 2: " + witness2)
print("locktime: " + locktime)

