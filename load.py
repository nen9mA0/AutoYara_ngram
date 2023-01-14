import sys
import getopt
import os
import pickle

from ngram_slice import *

suffix = ".asmdump"
debug = False

def ConcatBytes(disasm_dict):
    func_bytes = {}
    for addr in disasm_dict:
        tmp = b""
        for op in disasm_dict[addr]:
            tmp += op["bytes"]
        func_bytes[addr] = tmp
    return func_bytes


allow_arch = []
arch_lst = []
if __name__ == "__main__":
    opts, args = getopt.getopt(sys.argv[1:], "i:d:n:a:")
    for opt, value in opts:
        if opt == "-i":
            infile = value
        elif opt == "-d":
            outfile = value
        elif opt == "-n":
            ngram = int(value, 10)
        elif opt == "-a":
            arch_lst = value.split()

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

    if len(arch_lst):
        allow_arch.extend(arch_lst)

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

    if ngram < 0:
        raise ValueError("Invalid N: %d" %ngram)

    # infile = "..\\test\\ftp.dump"

    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    cs.detail = True
    ngs = NGramSlice(ngram)

    file_num = 1
    for file in file_lst:
        print("%06d: Loading %s" %(file_num, file))

        with open(file, "rb") as f:
            disasm_dict = pickle.load(f)

        tmp = disasm_dict["arch"]
        if tmp:
            flag = False
            for arch in allow_arch:
                if arch in tmp:
                    flag = True
            if not flag:
                print("file: %s not in allow arch" %file)
                continue

        func_bytes = ConcatBytes(disasm_dict["disasm"])
        baddr = disasm_dict["addr"]

        for addr in func_bytes:
            insn_lst = []
            decode = cs.disasm(func_bytes[addr], baddr)
            for insn in decode:
                insn_lst.append(insn)
            ngs.Slicer(insn_lst, debug)
        file_num += 1

    database = {}
    database["files"] = file_lst
    database["data"] = ngs.ngd.dict
    database["total"] = ngs.total

    with open(outfile, "wb") as f:
        pickle.dump(database, f)