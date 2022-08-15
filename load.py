import sys
import getopt
import os
import pickle
import capstone

suffix = ".asmdump"

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
    length = 4
    def __init__(self):
        self.ngd = NGramDict()
        self.total = 0
        # self.mnemonic_map = {}

    def Slicer(self, insn_lst):
        for i in range(len(insn_lst)-self.length+1):
            insn_hash, slice_bytes = self.Hash(insn_lst[i:i+self.length])
            # insn_hash = int.from_bytes(insn_hash, "little")
            if not insn_hash in self.ngd:
                # self.ngd[insn_hash] = slice_bytes
                self.ngd[insn_hash] = 1
            else:
                self.ngd[insn_hash] += 1
                # if slice_bytes != self.ngd[insn_hash]:
                #     raise ValueError("")
                # self.ngd[insn_hash] += slice_bytes
            self.total += 1
        return self.ngd

    # To prevent collision
    def HashBytes(self, slice):
        checksum = 0
        for insn in slice:
            for byte in insn.bytes:
                checksum = (checksum + byte) % 256
        return checksum 

    # hashing  now use type 1 for speed
    # type1   with prefix
    #  -------------------- 1 Byte --------------------- ------- 2 Byte -------                     -------------------- Last Byte --------------------
    # | 1bit | 4bit           | 3bit                    | 5bit         | 3bit  |   nbit            | 2bit          | 2bit      | 2bit      | 2bit      |
    # |   0  | length of insn | length of prefix+opcode | prefix group | reg   |   prefix + opcode | operand_num   | op1 type  | op2 type  | op3-type  |
    # type2   without prefix
    #  -------------------- 1 Byte ---------------------                   -------------------- Last Byte --------------------
    # | 1bit | 4bit                    | 3bit           | nbit            | 2bit          | 2bit      | 2bit      | 2bit      |
    # |   1  | length of prefix+opcode | reg            | prefix + opcode | operand_num   | op1 type  | op2 type  | op3-type  |
    def Hash(self, slice):
        myhash = []
        # checksum = self.HashBytes(slice)

        # for debug
        slice_bytes = b""
        for insn in slice:
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
            insn_size = len(insn.bytes)

            myhash.append( (insn_size<<3) | opfix_size )

            reg = (insn.modrm >> 3) & 0x7
            myhash.append(prefix_group << 3 | reg)

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
            if op_num > 3:
                raise ValueError("")

            ops = ops | (op_num << 6 )

            myhash.append(ops)

            # for debug
            slice_bytes += insn.bytes

        return bytes(myhash), slice_bytes



def ConcatBytes(disasm_dict):
    func_bytes = {}
    for addr in disasm_dict:
        tmp = b""
        for op in disasm_dict[addr]:
            tmp += op["bytes"]
        func_bytes[addr] = tmp
    return func_bytes


if __name__ == "__main__":
    opts, args = getopt.getopt(sys.argv[1:], "i:d:")
    for opt, value in opts:
        if opt == "-i":
            infile = value
        elif opt == "-d":
            outfile = value

    if not os.path.exists(infile):
        raise ValueError("infile not exist: %s" %infile)
    else:
        file_lst = []
        if os.path.isdir(infile):
            old_dir = os.getcwd()
            os.chdir(infile)
            for file in os.listdir():
                if file.endswith(suffix):
                    file_lst.append( os.path.join(infile, file) )
            os.chdir(old_dir)
        else:
            file_lst.append(infile)
    if not os.path.exists(outfile):
        print("Database not exist, Create")
    else:
        print("Are you sure to overwrite %s ? (y/n)" %outfile)
        while True:
            a = input()
            if a == 'y':
                break
            elif a == 'n':
                exit(0)

    # infile = "..\\test\\ftp.dump"

    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    cs.detail = True
    ngs = NGramSlice()

    file_num = 1
    for file in file_lst:
        print("%06d: Loading %s" %(file_num, file))

        with open(file, "rb") as f:
            disasm_dict = pickle.load(f)

        func_bytes = ConcatBytes(disasm_dict["disasm"])
        baddr = disasm_dict["addr"]

        for addr in func_bytes:
            insn_lst = []
            decode = cs.disasm(func_bytes[addr], baddr)
            for insn in decode:
                insn_lst.append(insn)
            ngs.Slicer(insn_lst)
        file_num += 1

    database = {}
    database["files"] = file_lst
    database["data"] = ngs.ngd.dict
    database["total"] = ngs.total

    with open(outfile, "wb") as f:
        pickle.dump(database, f)