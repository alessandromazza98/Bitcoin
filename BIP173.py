import bech32

script = "0014751e76e8199196d454941c45d1b3a323f1433bd6"
p = "751e76e8199196d454941c45d1b3a323f1433bd6"
w_v = 0
hrp = "bc"

spk = bytes.fromhex(script)


# Create an address bech32 segwit (native segwit)
# Input wit_program (20 or 32 bytes type) & mainnet (str) to check if it's mainnet for hrp
# Outputs the bech32 addr as a string (hex)
def encode_addr_bech32(wit_program, mainnet="True"):
    if mainnet == "True":
        hrp = "bc"
    else:
        hrp = "tc"

    wit_version = 0

    return bech32.encode(hrp, wit_version, wit_program)


# Decode an address beh32 (native segwit)
# Input a bech32 addr (str) & mainnet check (str) for hrp
# Output wit_version (str) and wit_program (str as hex)
def decode_addr_bech32(addr, mainnet="True"):
    if mainnet == "True":
        hrp = "bc"
    else:
        hrp = "tc"

    wit_version, wit_program_int = bech32.decode(hrp, addr)

    wit_program = ""
    for i in wit_program_int:
        wit_program += hex(i)[2:]

    return wit_version, wit_program


addr = encode_addr_bech32(bytes.fromhex(p))
w_ver, w_prog = decode_addr_bech32(addr)
print(addr)
print(w_ver)
print(w_prog)