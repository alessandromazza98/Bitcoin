import secrets
from hashlib import sha256

random = secrets.randbelow(2**512)

ran_hex = hex(random)[2:]

s = sha256(bytes.fromhex(ran_hex)).hexdigest()

print(s)
