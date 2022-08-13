import sys
import os
import getopt
import r2pipe
import pickle
import json

def SavedName(disasmj):
    # save_name = ["offset", "bytes"]
    ops = []
    for op in disasmj["ops"]:
        asm_dict = {}
        asm_dict["offset"] = op["offset"]
        asm_dict["bytes"] = bytes.fromhex(op["bytes"])
        ops.append(asm_dict)
    return ops

if __name__ == "__main__":
    opts, args = getopt.getopt(sys.argv[1:], "i:o:")
    for opt, value in opts:
        if opt == "-i":
            infile = value
        elif opt == "-o":
            outfile = value

    if not os.path.exists(infile):
        raise ValueError("infile not exist: %s" %infile)
    if len(outfile) <= 0:
        raise ValueError("outfile not specify: %s" %outfile)
    # if not os.path.exists(outfile):
    #     raise ValueError("outfile not exist: %s" %outfile)

    disasm_dict = {}

    r2 = r2pipe.open(infile)
    r2.cmd('aaaa')
    test = r2.cmd("\n")
    func_lst = r2.cmdj("aflj")            # evaluates JSONs and returns an object
    for func in func_lst:
        tmp = {}
        disasmj = r2.cmdj("pdfj @ %d" %func["offset"])
        ops = SavedName(disasmj)
        disasm_dict[func["offset"]] = ops

    info = r2.cmdj("ij")
    file = {}
    file["name"] = info["core"]["file"]
    file["addr"] = info["bin"]["baddr"]
    file["disasm"] = disasm_dict

    r2.quit()


    with open(outfile, "wb") as f:
        pickle.dump(file, f)