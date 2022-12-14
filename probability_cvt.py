import sys
import getopt
import os
import pickle

def ParseSliceLength(slice):
    end = len(slice)
    i = 0
    begin = 0
    result = []
    while i < end:
        begin = i
        insn_size = (slice[i] >> 3) & 0xf
        opfix_size = slice[i] & 0x7
        i += 1

        mnemonic_len = slice[i] & 0x0f
        prefix_group = slice[i] >> 4
        i += 1
        i += opfix_size

        # operand
        i += 1

        if mnemonic_len < 15:
            i += mnemonic_len
        else:
            index = i + mnemonic_len
            while slice[index] != 0:
                index += 1
            i = index + 1
        result.append(i)

    if i != end:
        raise ValueError("%s : Parsing Result Not Equal" %slice[begin:i].hex())

    return result

if __name__ == "__main__":
    opts, args = getopt.getopt(sys.argv[1:], "i:o:")
    for opt, value in opts:
        if opt == "-i":
            infile = value
        elif opt == "-o":
            outfile = value

    if not os.path.exists(infile):
        raise ValueError("infile not exist: %s" %infile)


    with open(infile, "rb") as f:
        tmp_database = pickle.load(f)

    database = {}
    database["total"] = [ tmp_database["total"] ]
    database["data"] = {}
    database["every_total"] = None
    # get the first element, ugly code but I don't know why I can't work with iter() and next() in dict_keys type
    for key in tmp_database["data"].keys():
        n = len(ParseSliceLength(key))
        break

    hash_dict = [{} for i in range(n-1)]
    for key in tmp_database["data"].keys():
        result = ParseSliceLength(key)
        for i in range(n-1):
            end_index = result[i]
            new_key = key[:end_index]
            if not new_key in hash_dict[i]:
                hash_dict[i][new_key] = 0
            hash_dict[i][new_key] += tmp_database["data"][key]
    database["every_total"] = hash_dict

    for key in tmp_database["data"].keys():
        result = ParseSliceLength(key)
        end_index = result[n-2]
        new_key = key[:end_index]

        num = tmp_database["data"][key]
        if n != 1:
            total = hash_dict[n-2][new_key]
        else:
            total = num
        if num > total:
            raise ValueError("")
        database["data"][key] = (num, total)

    with open(outfile, 'wb') as f:
        pickle.dump(database, f)