import os
import sys
import getopt
import pickle

from ngram_slice import *


def CvtSlice(slice, opcode_cvt_dict):
    new_slice = b""
    end = len(slice)
    i = 0
    begin = 0
    while i < end:
        begin = i
        mnemonic_len = (slice[i] >> 3) & 0x1f
        opfix_size = slice[i] & 0x7
        i += 1

        prefix_group = slice[i] >> 4
        prefix_num = 0
        for j in range(4):
            if prefix_group & 1:
                prefix_num += 1
            prefix_group = prefix_group >> 1
        i += 1

        # didn't match target opcode
        opcode = slice[i+prefix_num:i+opfix_size]
        if not opcode in opcode_cvt_dict:
            i += opfix_size+1+mnemonic_len
            new_slice += slice[begin:i]
            continue
        else:
            cvt_mnemonic, cvt_opcode = opcode_cvt_dict[opcode]
            i += opfix_size
            i += 1
            mnemonic = slice[i:i+mnemonic_len].decode("ascii")
            i += mnemonic_len
            # 这边加上对mnemonic范围的限定是因为mnemonic实际上是包括如lock一类的prefix的
            if cvt_mnemonic == mnemonic[-len(cvt_mnemonic):]:
                # match a target insn
                tmp_slice = slice[begin:i]
                if len(cvt_opcode) != opfix_size-prefix_num:
                    raise ValueError("")
                tmp_slice = tmp_slice[:2+prefix_num] + cvt_opcode + tmp_slice[2+opfix_size:]
                new_slice += tmp_slice
            else:
                new_slice += slice[begin:i]

    if i != end:
        raise ValueError("%s : Parsing Result Not Equal" %slice[begin:i].hex())

    return new_slice



infile = "I:\\Project\\auto_yara\\ngram\\database\\database\\1gram_database.pkl"
if __name__ == "__main__":
    # opts, args = getopt.getopt(sys.argv[1:], "i:")
    # for opt, value in opts:
    #     if opt == "-i":
    #         infile = value

    if not os.path.exists(infile):
        raise ValueError("infile not exist: %s" %infile)
    else:
        pass

    # for opcode in opcode_cvt_dict:
    #     print(opcode.hex(), opcode_cvt_dict[opcode])

    with open(infile, "rb") as f:
        database = pickle.load(f)

    if not "dup_data" in database:
        database["dup_data"] = {}
    if not "dup_data_origin" in database:
        database["dup_data_origin"] = {}

    flag = False
    for insn_hash in list(database["data"].keys()):
        new_insn_hash = CvtSlice(insn_hash, opcode_cvt_dict)
        if new_insn_hash == insn_hash:
            continue
        else:
            flag = True
            if new_insn_hash in database["data"]:
                if not new_insn_hash in database["dup_data_origin"]:
                    database["dup_data_origin"][new_insn_hash] = database["data"][new_insn_hash]
                database["data"][new_insn_hash] += database["data"][insn_hash]
                database["dup_data"][insn_hash] = database["data"][insn_hash]
            else:
                if not new_insn_hash in database["dup_data_origin"]:
                    database["dup_data_origin"][new_insn_hash] = database["data"][insn_hash]
                database["data"][new_insn_hash] = database["data"][insn_hash]
                database["dup_data"][insn_hash] = database["data"][insn_hash]

    if flag:
        for dup_insn_hash in database["dup_data"]:
            if dup_insn_hash in database["data"]:
                del database["data"][dup_insn_hash]

        mysum = 0
        for insn_hash in database["data"]:
            mysum += database["data"][insn_hash]
        if mysum != database["total"]:
            raise ValueError("number of insn check failed")

        print("Are you sure to overwrite %s ? (y/n)" %infile)
        while True:
            a = input()
            if a == 'y':
                break
            elif a == 'n':
                exit(0)

        with open(infile, "wb") as f:
            pickle.dump(database, f)
    else:
        print("Nothing in database will be changed")