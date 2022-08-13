import sys
import getopt
import os
import pickle
import capstone

suffix = ".asmdump"

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
        if opt == "-d":
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

    # infile = "..\\test\\ftp.dump"

    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    cs.detail = True
    for file in file_lst:
        with open(file, "rb") as f:
            disasm_dict = pickle.load(f)

        func_bytes = ConcatBytes(disasm_dict["disasm"])
        baddr = disasm_dict["addr"]

        for addr in func_bytes:
            decode = cs.disasm(func_bytes[addr], baddr)
            for insn in decode:
                pass
