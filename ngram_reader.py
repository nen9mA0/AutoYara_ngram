import sys
import getopt
import os
import pickle
import capstone

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

# hashing  now use type 1 for speed
# type1   with prefix
#  -------------------- 1 Byte --------------------- ------- 2 Byte -------                     -------------------- Last Byte --------------------
# | 1bit | 4bit           | 3bit                    | 5bit         | 3bit  |   nbit            | 2bit          | 2bit      | 2bit      | 2bit      |
# |   0  | length of insn | length of prefix+opcode | prefix group | reg   |   prefix + opcode | operand_num   | op1 type  | op2 type  | op3-type  |
# type2   without prefix
#  -------------------- 1 Byte ---------------------                   -------------------- Last Byte --------------------
# | 1bit | 4bit                    | 3bit           | nbit            | 2bit          | 2bit      | 2bit      | 2bit      |
# |   1  | length of prefix+opcode | reg            | prefix + opcode | operand_num   | op1 type  | op2 type  | op3-type  |

def ParseSlice(slice):
    end = len(slice)
    i = 0
    begin = 0
    while i < end:
        begin = i
        disasm_lst = []
        insn_size = (slice[i] >> 3) & 0xf
        opfix_size = slice[i] & 0x7
        i += 1

        prefix_group = (slice[i] >> 3) & 0x1f
        reg = slice[i] & 0x7
        i += 1

        disasm_lst.extend(slice[i:i+opfix_size])
        i += opfix_size

        if insn_size-opfix_size > 0:
            disasm_lst.append(reg<<3)       # push modrm
            for j in range(insn_size-opfix_size-1):
                disasm_lst.append(0)

        # operand
        ops = slice[i]
        op_num = ops >> 6
        op_types = []
        for j in range(op_num):
            if ops & 0x3 != 0:
                op_type = ops&0x3
                if op_type == 1:
                    op_types.append("reg")
                elif op_type == 2:
                    op_types.append("mem")
                elif op_type == 3:
                    op_types.append("imm")
            else:
                raise ValueError("")
            ops = ops >> 2
        i += 1

        disasm_code = bytes(disasm_lst)
        decode = cs.disasm(disasm_code, 0)
        num = 0
        flag = False
        for insn in decode:
            flag = True
            if num != 0:
                break
            mystr = insn.mnemonic + " "
            mystr += " ".join(op_types[::-1])
            print(mystr)
            num += 1
        if not flag:
            print("%s :  Disassemble Error" %slice[begin:i].hex())
    if i != end:
        raise ValueError("%s : Parsing Result Not Equal" %slice[begin:i].hex())


if __name__ == "__main__":
    opts, args = getopt.getopt(sys.argv[1:], "i:b:l:fs")
    display_file = False
    display_size = False
    begin = 0
    length = 0
    for opt, value in opts:
        if opt == "-i":
            infile = value
        elif opt == "-b":
            begin = int(value, 10)
        elif opt == "-l":
            length = int(value, 10)
        elif opt == "-f":
            display_file = True
        elif opt == "-s":
            display_size = True

    if not os.path.exists(infile):
        raise ValueError("infile not exist: %s" %infile)

    with open(infile, "rb") as f:
        hash_dict = pickle.load(f)

    if display_file:
        print("files:")
        for file in hash_dict["files"]:
            print(file)

    if display_size:
        print("Total File Numbers: %d" %(len(hash_dict["files"])))

    print("total")
    total = hash_dict["total"]
    print(total)

    # for debug check
    mysum = 0
    for i in hash_dict["data"]:
        mysum += hash_dict["data"][i]

    if mysum != total:
        raise ValueError("")

    num = 0
    if length == 0:
        length = len(hash_dict["data"])
    if begin+length > len(hash_dict["data"]):
        length = len(hash_dict["data"]) - begin

    end = begin + length
    for slice in hash_dict["data"]:
        if num>=begin and num<end:
            # decode = cs.disasm(hash_dict["data"][slice], 0)
            # for insn in decode:
            #     mystr = insn.mnemonic + " " + insn.op_str
            #     print(mystr)
            # print("")
            print("===== %d =====" %hash_dict["data"][slice])
            ParseSlice(slice)
            print("")
            num += 1
        else:
            pass