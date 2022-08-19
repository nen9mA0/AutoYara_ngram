import sys
import getopt
import os
import pickle

if __name__ == "__main__":
    opts, args = getopt.getopt(sys.argv[1:], "i:o:n:")
    display_file = False
    ngram = -1
    for opt, value in opts:
        if opt == "-i":
            infile = value
        elif opt == "-o":
            outfile = value
        elif opt == "-n":
            ngram = int(value, 10)

    if not os.path.exists(infile):
        raise ValueError("infile not exist: %s" %infile)
    if os.path.exists(outfile):
        print("New Database Exists, Overwrite? (Y/N)")
        while True:
            a = input()
            if a[0] == "Y":
                break
            elif a[0] == "N":
                exit()

    if ngram < 0:
        raise ValueError("Invalid N: %d" %ngram)

    with open(infile, "rb") as f:
        old_database = pickle.load(f)

    old_data = old_database["data"]

    new_database = {}
    new_database["files"] = old_database["files"]
    new_database["data"] = {}
    new_data = new_database["data"]

    total = 0
    for myhash in old_data:
        i = 0
        end = len(myhash)
        for n in range(ngram):
            hash_size = myhash[i] & 0x7
            hash_size += 3
            i += hash_size
            if i >= end:
                raise ValueError("Ngram parameter %d equal or greater than original database" %ngram)
        new_hash = myhash[:i]
        if not new_hash in new_data:
            new_data[new_hash] = old_data[myhash]
        else:
            new_data[new_hash] += old_data[myhash]
        total += old_data[myhash]

    if total != old_database["total"]:
        raise ValueError("New Total %d Not Equal To Old Total %d" %(total, old_database["total"]))
    new_database["total"] = total

    with open(outfile, "wb") as f:
        pickle.dump(new_database, f)
