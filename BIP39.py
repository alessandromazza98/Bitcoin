import hashlib


# From a mnemonic generates a 512 bit seed following BIP-39
def to_seed(words: str, passphrase="") -> bytes:
    iterations = 2048
    passphrase = "mnemonic" + passphrase

    return hashlib.pbkdf2_hmac('sha512', words.encode("utf-8"), passphrase.encode("utf-8"), iterations)
