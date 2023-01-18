import Bech32
import ToolsUnit


# Create an address bech32 segwit (native segwit)
# Input wit_program (20 or 32 bytes type) & mainnet (str) to check if it's mainnet for hrp
# Outputs the bech32 addr as a string (hex)
def encode_addr_bech32(wit_program, mainnet="True"):
    if mainnet == "True":
        hrp = "bc"
    else:
        hrp = "tb"

    wit_version = 0

    return Bech32.encode(hrp, wit_version, wit_program)


# Decode an address beh32 (native segwit)
# Input a bech32 addr (str) & mainnet check (str) for hrp
# Output wit_version (int) and wit_program (str as hex)
def decode_addr_bech32(addr, mainnet="True"):
    if mainnet == "True":
        hrp = "bc"
    else:
        hrp = "tb"

    wit_version, wit_program_int = Bech32.decode(hrp, addr)

    wit_program = ""
    for i in wit_program_int:
        wit_program += hex(i)[2:].rjust(2, "0")

    return wit_version, wit_program


# Create witness scriptCode for P2WPKH
# Input an addr (str) & mainnet check (str) for hrp
# Output the scriptCode to be signed
def create_witness_script_code_P2WPKH(addr, mainnet="True"):
    _, wit_program = decode_addr_bech32(addr, mainnet)
    wit_program = wit_program.rjust(40, "0")
    len_wit_program = ToolsUnit.calculate_varint(wit_program)
    dup = "76"
    hash160 = "a9"
    equalverify = "88"
    checksig = "ac"
    result = dup + hash160 + len_wit_program + wit_program + equalverify + checksig
    len_result = ToolsUnit.calculate_varint(result)
    return len_result + result


# Create witness scriptCode for P2WSH
# Input an addr (str) & mainnet check (str) for hrp
# Output the scriptCode to be signed
def create_witness_script_code_P2WSH(addr, mainnet="True"):
    _, wit_program = decode_addr_bech32(addr, mainnet)
    wit_program = wit_program.rjust(64, "0")
    len_wit_program = ToolsUnit.calculate_varint(wit_program)
    dup = "76"
    hash160 = "a9"
    equalverify = "88"
    checksig = "ac"
    result = dup + hash160 + len_wit_program + wit_program + equalverify + checksig
    len_result = ToolsUnit.calculate_varint(result)
    return len_result + result


# Create witness locking script
# Input an addr (str) & mainnet check (str) for hrp
# Output the locking script
def create_witness_locking_script(addr, mainnet="True"):
    version, program = decode_addr_bech32(addr, mainnet)
    version = str(version).rjust(2, "0")
    len_program = ToolsUnit.calculate_varint(program)
    return version + len_program + program


if __name__ == '__main__':
    script = "0014751e76e8199196d454941c45d1b3a323f1433bd6"
    p = "751e76e8199196d454941c45d1b3a323f1433bd6"
    w_v = 0
    hrp = "bc"

    spk = bytes.fromhex(script)

    addr = encode_addr_bech32(bytes.fromhex(p))
    w_ver, w_prog = decode_addr_bech32(addr)
    print(addr)
    print(w_ver)
    print(w_prog)

    loc_scri = create_witness_script_code_P2WPKH(addr)
    print(loc_scri)
