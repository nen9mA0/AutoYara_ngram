import sys
import getopt
import os
import pickle
import capstone

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
debug = False
collision_check = False
if debug or collision_check:
    cs.detail = True

# [Duplicate] old format, see comment in load.py
# hashing  now use type 1 for speed
# type1   with prefix
#  -------------------- 1 Byte --------------------- ------- 2 Byte -------                     -------------------- Last Byte --------------------
# | 1bit | 4bit           | 3bit                    | 5bit         | 3bit  |   nbit            | 2bit          | 2bit      | 2bit      | 2bit      |
# |   0  | length of insn | length of prefix+opcode | prefix group | reg   |   prefix + opcode | operand_num   | op1 type  | op2 type  | op3-type  |
# type2   without prefix
#  -------------------- 1 Byte ---------------------                   -------------------- Last Byte --------------------
# | 1bit | 4bit                    | 3bit           | nbit            | 2bit          | 2bit      | 2bit      | 2bit      |
# |   1  | length of prefix+opcode | reg            | prefix + opcode | operand_num   | op1 type  | op2 type  | op3-type  |
# def ParseSlice(slice):
#     end = len(slice)
#     i = 0
#     begin = 0
#     while i < end:
#         begin = i
#         disasm_lst = []
#         insn_size = (slice[i] >> 3) & 0xf
#         opfix_size = slice[i] & 0x7
#         i += 1

#         prefix_group = (slice[i] >> 3) & 0x1f
#         reg = slice[i] & 0x7
#         i += 1

#         disasm_lst.extend(slice[i:i+opfix_size])
#         i += opfix_size

#         if insn_size-opfix_size > 0:
#             disasm_lst.append(reg<<3)       # push modrm
#             for j in range(insn_size-opfix_size-1):
#                 disasm_lst.append(0)

#         # operand
#         ops = slice[i]
#         # op_num = ops >> 6
#         op_types = []
#         for j in range(4):
#             if ops & 0x3 != 0:
#                 op_type = ops&0x3
#                 if op_type == 1:
#                     op_types.append("reg")
#                 elif op_type == 2:
#                     op_types.append("mem")
#                 elif op_type == 3:
#                     op_types.append("imm")
#             else:
#                 if len(op_types) > 0:
#                     raise ValueError("")
#             ops = ops >> 2
#         i += 1

#         disasm_code = bytes(disasm_lst)
#         decode = cs.disasm(disasm_code, 0)
#         num = 0
#         flag = False
#         for insn in decode:
#             flag = True
#             if num != 0:
#                 break
#             mystr = insn.mnemonic + " "
#             mystr += " ".join(op_types[::-1])
#             print(mystr)
#             num += 1
#         if not flag:
#             print("%s :  Disassemble Error" %slice[begin:i].hex())
#     if i != end:
#         raise ValueError("%s : Parsing Result Not Equal" %slice[begin:i].hex())

# New format
#  -------------------- 1 Byte --------------------- ------------- 1 Byte -------------- ----- n Byte ------ -------------------- 1 Byte ------------------- -- [optional] n Byte --
# | 1bit | 4bit           | 3bit                    |     4bit     |        4bit        |        nbit       | 2bit      | 2bit      | 2bit      | 2bit      |         n bit         |
# |   0  | length of insn | length of prefix+opcode | prefix group | length of mnemonic |   prefix + opcode | op1 type  | op2 type  | op3 type  | op4 type  |        mnemonic       |
def ParseSlice(slice, slice_bytes=None, slient_check=False, collision_dict=None):
    end = len(slice)
    i = 0
    begin = 0
    result = []
    while i < end:
        begin = i
        disasm_lst = []
        insn_size = (slice[i] >> 3) & 0xf
        opfix_size = slice[i] & 0x7
        i += 1

        mnemonic_len = slice[i] & 0x0f
        prefix_group = slice[i] >> 4
        i += 1

        disasm_lst.extend(slice[i:i+opfix_size])
        i += opfix_size

        # operand
        ops = slice[i]
        # op_num = ops >> 6
        op_types = []
        for j in range(4):
            if ops & 0x3 != 0:
                op_type = ops&0x3
                if op_type == 1:
                    op_types.append("reg")
                elif op_type == 2:
                    op_types.append("mem")
                elif op_type == 3:
                    op_types.append("imm")
            else:
                if len(op_types) > 0:
                    raise ValueError("")
            ops = ops >> 2
        i += 1

        if mnemonic_len < 15:
            mnemonic = slice[i:i+mnemonic_len].decode("ascii")
            i += mnemonic_len
        else:
            index = i + mnemonic_len
            while slice[index] != 0:
                index += 1
            mnemonic = slice[i:index].decode("ascii")
            i = index + 1

        mystr = mnemonic + " "
        mystr += " ".join(op_types[::-1])
        if not slient_check:
            print(mystr)

        if debug or collision_check:
            result.append(mystr)

    if i != end:
        raise ValueError("%s : Parsing Result Not Equal" %slice[begin:i].hex())


    if collision_check:
        tmp = " ".join(result)
        tmp_hash = hash(tmp)
        if not tmp_hash in collision_dict:
            collision_dict[tmp_hash] = (tmp, [slice])
        else:
            tmp, slice_lst = collision_dict[tmp_hash]
            if not slice in slice_lst:
                slice_lst.append(slice)

    if debug:
        for slice_byte in slice_bytes:
            decode = cs.disasm(slice_byte, 0)
            flag = False
            disasm_insn = []
            disasm_str = []
            for insn in decode:
                flag = True
                insn_op_type = []
                for i in insn.operands:
                    if i.type == capstone.x86.X86_OP_REG:
                        insn_op_type.append("reg")
                    elif i.type == capstone.x86.X86_OP_MEM:
                        insn_op_type.append("mem")
                    elif i.type == capstone.x86.X86_OP_IMM:
                        insn_op_type.append("imm")
                    else:
                        raise ValueError("")
                mystr = insn.mnemonic + " " + " ".join(insn_op_type)
                disasm_insn.append(insn)
                disasm_str.append(mystr)
            if len(disasm_str) != len(result):
                raise ValueError("")
            for i in range(len(result)):
                if result[i] != disasm_str[i]:
                    raise ValueError("")
            if not flag:
                print("%s :  Disassemble Error" %slice[begin:i].hex())
        print("check %d slice_bytes" %len(slice_bytes))

    return collision_dict



if __name__ == "__main__":
    opts, args = getopt.getopt(sys.argv[1:], "i:b:l:fs")
    display_file = False
    display_size = True
    slient_check = False
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
            slient_check = True

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

    if debug:
        mysum = 0
        for i in hash_dict["data"]:
            mysum += hash_dict["data"][i][0]

        if mysum != total:
            raise ValueError("")

    num = 0
    if length == 0:
        length = len(hash_dict["data"])
    if begin+length > len(hash_dict["data"]):
        length = len(hash_dict["data"]) - begin

    end = begin + length

    if collision_check:
        collision_dict = {}
    else:
        collision_dict = None
    for slice in hash_dict["data"]:
        if num>=begin and num<end:
            # decode = cs.disasm(hash_dict["data"][slice], 0)
            # for insn in decode:
            #     mystr = insn.mnemonic + " " + insn.op_str
            #     print(mystr)
            # print("")

            if not (debug or collision_check):
                if not slient_check:
                    print("===== %d =====" %hash_dict["data"][slice])
                ParseSlice(slice, slient_check=slient_check)
            else:
                if not slient_check:
                    print("===== %d =====" %hash_dict["data"][slice][0])
                ParseSlice(slice, slice_bytes=hash_dict["data"][slice][1], slient_check=slient_check, collision_dict=collision_dict)
            if not slient_check:
                print("")
            num += 1
        else:
            pass

    if collision_check:
        print("== COLLISION ==")
        for tmp_hash in collision_dict:
            tmp, slice_lst = collision_dict[tmp_hash]
            if len(slice_lst) > 1:
                print(tmp)
                for slice in slice_lst:
                    print(slice)