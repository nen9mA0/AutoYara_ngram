import sys
import getopt
import os
import pickle
import capstone
import binascii

cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
cs.detail = True
debug = False
collision_check = False
use_zero_padding = True
smooth = True
smooth_gram = 2
n = 4

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

# New format 20221215
# 新hash格式，之前居然没发现这个length of insn是个大bug
#  -------------------- 1 Byte -------------------- ------------- 1 Byte -------------- ----- n Byte ------ -------------------- 1 Byte ------------------- -- [optional] n Byte --
# |        5bit          | 3bit                    |     4bit     |        4bit        |        nbit       | 2bit      | 2bit      | 2bit      | 2bit      |         n bit         |
# |  length of mnemonic  | length of prefix+opcode | prefix group |    0(preserved)    |   prefix + opcode | op1 type  | op2 type  | op3 type  | op4 type  |        mnemonic       |
def ParseSlice(slice, slice_bytes=None, slient_check=False, collision_dict=None):
    end = len(slice)
    i = 0
    begin = 0
    result = []
    while i < end:
        begin = i
        disasm_lst = []
        mnemonic_len = (slice[i] >> 3) & 0x1f
        opfix_size = slice[i] & 0x7
        i += 1

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

        mnemonic = slice[i:i+mnemonic_len].decode("ascii")
        i += mnemonic_len

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


def HashInsn(slice):
    ret = b""
    # checksum = self.HashBytes(slice)

    # for debug
    slice_bytes = b""
    for insn in slice:
        myhash = []
        opcode_size = 1             # for add 
                                    # 00 /r	ADD r/m8, r8	MR	Valid	Valid	Add r8 to r/m8.
        for i in range(len(insn.opcode)-1, -1, -1):
            if insn.opcode[i] != 0:
                opcode_size = i+1
                break
        prefix_group = 0
        prefix_size = 0
        for i in range(len(insn.prefix)):
            if insn.prefix[i] != 0:
                prefix_group |= 1<<i
                prefix_size += 1
        opfix_size = opcode_size + prefix_size

        mnemonic_len = len(insn.mnemonic) & 0x1f
        myhash.append( (mnemonic_len<<3) | opfix_size )

        tmp_byte = prefix_group << 4
        myhash.append(tmp_byte)

        if prefix_size > 0:
            for i in range(len(insn.prefix)):
                if insn.prefix[i] != 0:
                    myhash.append(insn.prefix[i])
        myhash.extend(insn.opcode[:opcode_size])

        ops = 0
        op_num = 0
        for i in insn.operands:
            ops = ops << 2
            op_num += 1
            if i.type == capstone.x86.X86_OP_REG:
                op_type = 1
            elif i.type == capstone.x86.X86_OP_MEM:
                op_type = 2
            elif i.type == capstone.x86.X86_OP_IMM:
                op_type = 3
            else:
                raise ValueError("")
            ops |= op_type
        if op_num > 4:
            raise ValueError("")

        for num in range(op_num, 4):
            ops = ops << 2
        myhash.append(ops)

        tmp_byte = bytes(insn.mnemonic, "ascii")
        if len(tmp_byte) != mnemonic_len:
            raise ValueError("Length different after encode")
        ret += bytes(myhash) + tmp_byte

        # for debug
        slice_bytes += insn.bytes

    return ret, slice_bytes


if __name__ == "__main__":
    opts, args = getopt.getopt(sys.argv[1:], "i:b:l:fsa")
    display_file = False
    display_size = False
    slient_check = False
    interactive = False
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
        elif opt == "-a":
            interactive = True

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

    if interactive:
        while True:
            bytes_raw = input("> ")
            if 'q' in bytes_raw:
                break
            bytes_rule = binascii.a2b_hex( bytes_raw.replace(' ', '') )
            ori_bytes_len = len(bytes_rule)
            if use_zero_padding:
                bytes_rule += b"\x00\x00\x00\x00\x00\x00\x00"   # duplicated: we pad 6 bytes for fixing the last jump opcode
                                                                # don't do this because we don't know the operand of these jmp
            ori_insn = []
            try:
                decode = cs.disasm(bytes_rule, 0)
            except Exception as e:
                print(e)
            decode_len = 0
            for insn in decode:
                ori_insn.append(insn)
                decode_len += insn.size
                if decode_len >= ori_bytes_len:
                    break

            tmp_data = hash_dict["data"]
            insn_hash, index = HashInsn(ori_insn)
            if insn_hash in tmp_data:
                num, total = tmp_data[insn_hash]
            elif smooth:            # n-gram laplace smoothing
                print("use smooth")
                num = 1
                flag = False
                for j in range(n-2, smooth_gram-2, -1):
                    new_hash = insn_hash[index[j]]
                    if new_hash in hash_dict["every_total"][j]:
                        total = hash_dict["every_total"][j][new_hash]
                        flag = True
                        # add to hash for speeding
                        tmp_data[insn_hash] = (num, total)
                        print("find in %d-gram" %(j+1))
                        break
                if not flag:
                    if smooth_gram >= 0:
                        num = 0
                        total = 1
                    else:
                        total = hash_dict["total"]
            else:
                num = 0
                total = 1
            print("num: %d   total: %d" %(num, total))

    else:
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