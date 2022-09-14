import pickle

with open("../database/1gram/database.pkl", "rb") as f:
    gram_dict = pickle.load(f)

total_ins = gram_dict["total"]
gram_data = gram_dict["data"]

total_length = 0
for myhash in gram_data:
    insn_size = (myhash[0] >> 3) & 0xf
    total_length += insn_size * gram_data[myhash]

print(total_length / total_ins)