import capstone

# TODO
# 目前hash算法还有有一个问题：因为capstone没有指示opcode长度的字段，所以在处理opcode的时候，是从后往前，直到遇到第一个不是00的opcode，把这之前的全部当做opcode
# 但有这几种情况会遇到问题
# * 00          add     目前这种情况算是解决了，因为opcode至少有一位，所以可以忽略这种情况
# * 0F 00       好几条   目前这种情况并没有解决，但靠着mnemonic可以做到唯一的hash寻址，因此暂时没有错误
# * 0F 38 00    pshufb  同上

# build reverse dict for searching opcode
def GenRevHandleDict():
    handle_dict = {
        b"\x40": ("inc", 5),
        b"\x48": ("dec", 5),
        b"\x50": ("push", 5),
        b"\x58": ("pop", 5),
        b"\x90": ("xchg", 5),
        b"\xb0": ("mov", 5),
        b"\xb8": ("mov", 5),
        b"\x0f\xc8": ("bswap", 13)
    }
    cvt_dict = {}
    for opcode in handle_dict:
        mnemonic, mask = handle_dict[opcode]
        expand_index = mask // 8
        expand_opcode = opcode[expand_index]
        expand_shift = 8 - (mask % 8)
        expand_mask = (0xff >> expand_shift) << expand_shift
        # ugly but I think it can fit more situations, brute force
        for i in range(256):
            if i & expand_mask == opcode[expand_index]:
                new_opcode = opcode[:expand_index] + bytes([i]) + opcode[expand_index+1:]
                cvt_dict[new_opcode] = (mnemonic, opcode)
    return cvt_dict

# ==== Global Variable ====
opcode_cvt_dict = GenRevHandleDict()
# =========================


def HashInsn(slice, debug=False):
    ret = b""
    # checksum = self.HashBytes(slice)

    # for debug
    slice_bytes = b""

    for insn in slice:
        myhash = []

        opcode_size = 1
        opcode_lst = insn.opcode
        if opcode_lst[0] == 0x0f:
            if opcode_lst[1] == 0x38 or opcode_lst[1] == 0x3a:
                opcode_size = 3
            else:
                opcode_size = 2

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

        # handle srm encoding in opcode
        handle_srm = False
        opcode_bytes = bytes(insn.opcode[:opcode_size])
        if opcode_bytes in opcode_cvt_dict:
            cvt_mnemonic, cvt_opcode = opcode_cvt_dict[opcode_bytes]
            if cvt_mnemonic == insn.mnemonic[-len(cvt_mnemonic):]:
                handle_srm = True
        if handle_srm:
            myhash.extend(list(cvt_opcode))
        else:
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

        mnemonic_bytes = bytes(insn.mnemonic, "ascii")
        if len(mnemonic_bytes) != mnemonic_len:
            raise ValueError("Length different after encode")
        ret += bytes(myhash) + mnemonic_bytes

        # for debug
        if debug:
            slice_bytes += insn.bytes

    return ret, slice_bytes


class NGramDict(object):
    def __init__(self):
        self.dict = {}

    def __contains__(self, name):
        return name in self.dict

    def __getitem__(self, name):
        return self.dict[name]

    def __setitem__(self, name, value):
        self.dict[name] = value


class NGramSlice(object):
    def __init__(self, ngram):
        self.ngd = NGramDict()
        self.total = 0
        self.length = ngram
        # self.mnemonic_map = {}

    def Slicer(self, insn_lst, debug=False):
        for i in range(len(insn_lst)-self.length+1):
            insn_hash, slice_bytes = self.Hash(insn_lst[i:i+self.length])
            # insn_hash = int.from_bytes(insn_hash, "little")
            if debug:
                if not insn_hash in self.ngd:
                    self.ngd[insn_hash] = (1, [slice_bytes])
                else:
                    n, old_lst = self.ngd[insn_hash]
                    n += 1
                    old_lst.append(slice_bytes)
                    self.ngd[insn_hash] = (n, old_lst) 
            else:
                if not insn_hash in self.ngd:
                    self.ngd[insn_hash] = 1
                else:
                    self.ngd[insn_hash] += 1
            self.total += 1
        return self.ngd

    # To prevent collision
    def HashBytes(self, slice):
        checksum = 0
        for insn in slice:
            for byte in insn.bytes:
                checksum = (checksum + byte) % 256
        return checksum 

    # 旧的哈希格式，存在几个问题：
    #   * 无法确定reg字段是否真的作为opcode
    #   * 实践中发现有部分指令使用了整个modrm字段来区分指令，即prefix/opcode/reg是完全相同的，仅mod或rm是不同的，如vmx系列指令
    # hashing  now use type 1 for speed
    # type1   with prefix
    #  -------------------- 1 Byte --------------------- ------- 2 Byte -------                     ------------------ Last Byte ------------------
    # | 1bit | 4bit           | 3bit                    | 5bit         | 3bit  |   nbit            | 2bit      | 2bit      | 2bit      | 2bit      |
    # |   0  | length of insn | length of prefix+opcode | prefix group | reg   |   prefix + opcode | op1 type  | op2 type  | op3 type  | op4 type  |
    # type2   without prefix
    #  -------------------- 1 Byte ---------------------                   -------------------- Last Byte --------------------
    # | 1bit | 4bit                    | 3bit           | nbit            | 2bit          | 2bit      | 2bit      | 2bit      |
    # |   1  | length of prefix+opcode | reg            | prefix + opcode | operand_num   | op1 type  | op2 type  | op3-type  |
    # def Hash(self, slice):
    #     myhash = []
    #     # checksum = self.HashBytes(slice)

    #     # for debug
    #     slice_bytes = b""
    #     for insn in slice:
    #         opcode_size = 1             # for add 
    #                                     # 00 /r	ADD r/m8, r8	MR	Valid	Valid	Add r8 to r/m8.
    #         for i in range(len(insn.opcode)-1, -1, -1):
    #             if insn.opcode[i] != 0:
    #                 opcode_size = i+1
    #                 break
    #         prefix_group = 0
    #         prefix_size = 0
    #         for i in range(len(insn.prefix)):
    #             if insn.prefix[i] != 0:
    #                 prefix_group |= 1<<i
    #                 prefix_size += 1
    #         opfix_size = opcode_size + prefix_size
    #         insn_size = len(insn.bytes)
    #         hash_type = 0               # here we use hash type 1
    #         insn_size |= (hash_type << 4)

    #         myhash.append( (insn_size<<3) | opfix_size )

    #         reg = (insn.modrm >> 3) & 0x7
    #         myhash.append(prefix_group << 3 | reg)

    #         if prefix_size > 0:
    #             for i in range(len(insn.prefix)):
    #                 if insn.prefix[i] != 0:
    #                     myhash.append(insn.prefix[i])
    #         myhash.extend(insn.opcode[:opcode_size])

    #         ops = 0
    #         op_num = 0
    #         for i in insn.operands:
    #             ops = ops << 2
    #             op_num += 1
    #             if i.type == capstone.x86.X86_OP_REG:
    #                 op_type = 1
    #             elif i.type == capstone.x86.X86_OP_MEM:
    #                 op_type = 2
    #             elif i.type == capstone.x86.X86_OP_IMM:
    #                 op_type = 3
    #             else:
    #                 raise ValueError("")
    #             ops |= op_type
    #         if op_num > 4:
    #             raise ValueError("")

    #         for num in range(op_num, 4):
    #             ops = ops << 2

    #         myhash.append(ops)

    #         # for debug
    #         slice_bytes += insn.bytes

    #     return bytes(myhash), slice_bytes


    # (DUPLICATE)新hash格式
    # * 直接在最后加上mnemonic，这样直接不用modrm这位了（说实话我觉得这个解决方案很ugly，但是先将就着用吧，总比再解析XED规则每次都放到一个大表里比较要好）
    #  -------------------- 1 Byte --------------------- ------------- 1 Byte -------------- ----- n Byte ------ -------------------- 1 Byte ------------------- -- [optional] n Byte --
    # | 1bit | 4bit           | 3bit                    |     4bit     |        4bit        |        nbit       | 2bit      | 2bit      | 2bit      | 2bit      |         n bit         |
    # |   0  | length of insn | length of prefix+opcode | prefix group | length of mnemonic |   prefix + opcode | op1 type  | op2 type  | op3 type  | op4 type  |        mnemonic       |



    # 新hash格式，之前居然没发现这个length of insn是个大bug
    #  -------------------- 1 Byte -------------------- ------------- 1 Byte -------------- ----- n Byte ------ -------------------- 1 Byte ------------------- -- [optional] n Byte --
    # |        5bit          | 3bit                    |     4bit     |        4bit        |        nbit       | 2bit      | 2bit      | 2bit      | 2bit      |         n bit         |
    # |  length of mnemonic  | length of prefix+opcode | prefix group |    0(preserved)    |   prefix + opcode | op1 type  | op2 type  | op3 type  | op4 type  |        mnemonic       |

    def Hash(self, slice):
        return HashInsn(slice)


# check
# 没法自动化检测所有的dup能否正确转换，因为现在的hash算法已经无法直接从hash还原为指令了（原来其实也不算完全可以）
# 这里只能手动check

if __name__ == "__main__":
    check_asm = []
    check_asm.append(b"\x50\x66\x53")   # push eax  push bx
    check_asm.append(b"\x50\x53")   # push eax  push ebx

    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    cs.detail = True

    for asm in check_asm:
        try:
            decode = cs.disasm(asm, 0)
            myslice = []
            for insn in decode:
                myslice.append(insn)

            insn_hash = HashInsn(myslice)
            print(insn_hash[0])
            print(insn_hash[0].hex())
            print("")
        except Exception as e:
            raise ValueError("")