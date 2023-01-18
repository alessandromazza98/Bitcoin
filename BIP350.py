import Bech32
import ToolsUnit


# Create an address bech32m segwit (native segwit w/ v1)
# Input wit_program (32 bytes type) & mainnet (str) to check if it's mainnet for hrp
# Outputs the bech32m addr as a string (hex)
def encode_addr_bech32m(wit_program, mainnet="True"):
    if mainnet == "True":
        hrp = "bc"
    else:
        hrp = "tb"

    wit_version = 1  # version 1

    return Bech32.encode(hrp, wit_version, wit_program)


# Decode an address beh32m (native segwit w/ v1)
# Input a bech32m addr (str) & mainnet check (str) for hrp
# Output wit_version (int) and wit_program (str as hex)
def decode_addr_bech32m(addr, mainnet="True"):
    if mainnet == "True":
        hrp = "bc"
    else:
        hrp = "tb"

    wit_version, wit_program_int = Bech32.decode(hrp, addr)

    wit_program = ""
    for i in wit_program_int:
        wit_program += hex(i)[2:].rjust(2, "0")

    return wit_version, wit_program


# Create witness locking script
# Input an addr (str) & mainnet check (str) for hrp
# Output the locking script
def create_witness_locking_script(addr, mainnet="True"):
    version, program = decode_addr_bech32m(addr, mainnet)
    version += 50  # da v1 a v16 sono codificati come 0x51 -> 0x86
    version = str(version).rjust(2, "0")
    len_program = ToolsUnit.calculate_varint(program)
    return version + len_program + program
