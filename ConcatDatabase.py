import pickle
import os

database_lst = [
    "../databases/database0.pkl",
    "../databases/database1.pkl",
    "../databases/database2.pkl",
    "../databases/database3.pkl",
    "../databases/database4.pkl",
    "../databases/database5.pkl",
    "../databases/database6.pkl",
    "../databases/database7.pkl",
    "../databases/database8.pkl",
    "../databases/database9.pkl",
]

out_database = "../databases/database.pkl"
out_database = os.path.abspath(out_database)


def Check(database):
    mysum = 0
    for addr in database["data"]:
        mysum += database["data"][addr]
    if mysum != database["total"]:
        raise ValueError("")

def PrintStat(database):
    print("total dumps: %d" %len(database["files"]))
    print("total ins:   %d" %database["total"])
    print("total data:  %d" %(len(database["data"])))

final_database = None
if os.path.exists(out_database):
    with open(out_database, "rb") as f:
        final_database = pickle.load(f)

for database in database_lst:
    database_path = os.path.abspath(database)
    print("Handling %s" %database_path)
    if not os.path.exists(database_path):
        print("%s not found" %database_path)
        continue
    if final_database != None:
        if database_path in final_database["database_lst"]:
            print("%s has been loaded" %database_path)
            continue
        else:
            with open(database_path, "rb") as f:
                new_database = pickle.load(f)

            for addr in new_database["data"]:
                if addr in final_database["data"]:
                    final_database["data"][addr] += new_database["data"][addr]
                else:
                    final_database["data"][addr] = new_database["data"][addr]
            final_database["files"].extend(new_database["files"])
            final_database["total"] += new_database["total"]
            final_database["database_lst"].append(database_path)
            PrintStat(final_database)
    else:
        with open(database_path, "rb") as f:
            final_database = pickle.load(f)
        final_database["database_lst"] = [database_path]
        PrintStat(final_database)

with open(out_database, "wb") as f:
    pickle.dump(final_database, f)