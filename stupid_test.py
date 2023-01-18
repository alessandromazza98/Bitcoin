tx = "010000000001015874fdb935b94bf793fcb13d331f5113e36172fc0085732c5c1d70d8588016230000000000ffffffff01301b0f0000000000225120b009a0501fbe6496e10c657cd04d75d1e6017ceaeee9600a3eae74d684dff9920140b1688dea05bfa7d75ddf94f6de12aee0931ecc6f530f6c659c67e23a66961330b330a6d6a760865d950523335125120fc26227023c2692f8e04ea84548e56d0600000000"

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
witness_count = tx[116+int(len_locking_script1, 16)*2:116+int(len_locking_script1, 16)*2+2]
len_witness1 = tx[116+int(len_locking_script1, 16)*2+2:116+int(len_locking_script1, 16)*2+2+2]
witness1 = tx[116+int(len_locking_script1, 16)*2+2+2:116+int(len_locking_script1, 16)*2+2+2+int(len_witness1, 16)*2]
locktime = tx[-8:]

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
print("locktime: " + locktime)

# 5120b009a0501fbe6496e10c657cd04d75d1e6017ceaeee9600a3eae74d684dff992
