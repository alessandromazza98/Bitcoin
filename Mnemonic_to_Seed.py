from mnemonic import Mnemonic
import ECDSAUnit
import HDDerivation

language = "english"
nmemo = Mnemonic(language)

words = "series panther mango type skin humor coach require old dash endorse salon"

seed = nmemo.to_seed(words, passphrase="")

print(seed)

k_master, c_master = HDDerivation.master_key_generation(seed)
xpriv = k_master, c_master
xpriv_ser = HDDerivation.ser_extended_priv_keys(k_master, c_master, 0, 0, master_key='True', mainnet='False')

K_master = ECDSAUnit.multiply(k_master)
xpub_ser = HDDerivation.ser_extended_pub_keys(K_master, c_master, 0, 0, master_key='True', mainnet='False')

print(xpriv_ser.decode())
print(xpub_ser.decode())
print()

k_44h_1h, c_44h_1h = HDDerivation.CKDpriv(HDDerivation.CKDpriv(xpriv, 44+2**31), 1+2**31)
xpriv_44h_1h = k_44h_1h, c_44h_1h
K_44h_1h = ECDSAUnit.multiply(k_44h_1h)
K_ser_44h_1h = HDDerivation.serP(K_44h_1h)

k_44h_1h_0h, c_44h_1h_0h = HDDerivation.CKDpriv(xpriv_44h_1h, 2**31)
xpriv_44h_1h_0h = k_44h_1h_0h, c_44h_1h_0h

xpriv_ser_44h_1h_0h = HDDerivation.ser_extended_priv_keys(k_44h_1h_0h, c_44h_1h_0h, 2**31, 3, K_ser_44h_1h, mainnet='False')

K_44h_1h_0h = ECDSAUnit.multiply(k_44h_1h_0h)

xpub_ser_44h_1h_0h = HDDerivation.ser_extended_pub_keys(K_44h_1h_0h, c_44h_1h_0h, 2**31, 3, K_ser_44h_1h, mainnet='False')

print(xpriv_ser_44h_1h_0h.decode())
print(xpub_ser_44h_1h_0h.decode())
print()

# Mi serve address m/44'/1'/0'/0/0
xpriv_44h_1h_0h_0 = HDDerivation.CKDpriv(xpriv_44h_1h_0h, 0)
k_44h_1h_0h_0, c_44h_1h_0h_0 = xpriv_44h_1h_0h_0
K_44h_1h_0h_0 = ECDSAUnit.multiply(k_44h_1h_0h_0)

xpriv_44h_1h_0h_0_0 = HDDerivation.CKDpriv(xpriv_44h_1h_0h_0, 0)
k_44h_1h_0h_0_0, c_44h_1h_0h_0_0 = xpriv_44h_1h_0h_0_0
print(k_44h_1h_0h_0_0)
