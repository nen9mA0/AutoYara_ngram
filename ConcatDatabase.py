import pickle
import os

# database_lst = [
#     "../databases/database0.pkl",
#     "../databases/database1.pkl",
#     "../databases/database2.pkl",
#     "../databases/database3.pkl",
#     "../databases/database4.pkl",
#     "../databases/database5.pkl",
#     "../databases/database6.pkl",
#     "../databases/database7.pkl",
#     "../databases/database8.pkl",
#     "../databases/database9.pkl",
# ]

dump_folder = "/home/lishijia/autoyara/dump/sample_split"

out_database_path = "/home/lishijia/autoyara/ngram_database/database"
out_database_path = os.path.abspath(out_database_path)

database_name = "%dgram_database.pkl"

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


print("dump folder: %s" %dump_folder)
myfolder = os.listdir(dump_folder)
print("Folders:")
print(myfolder)
print("Continue?")
a = input()
if "q" in a:
    exit()

index = 0
for i in range(1, 5):
    a = input()
    # find exist database
    final_database = None
    out_database = os.path.join(out_database_path, database_name%i)
    if os.path.exists(out_database):
        with open(out_database, "rb") as f:
            final_database = pickle.load(f)

    # find target databases
    database_lst = []
    flag = False
    for folder in myfolder:
        subdatabase_path = os.path.join(dump_folder, folder, database_name%i)
        if os.path.exists(subdatabase_path):
            # print(subdatabase_path)
            database_lst.append(subdatabase_path)
        else:
            flag = True
    if flag:
        print("Cannot find %s" %subdatabase_path)
        print("Concat %d databases" %index)
        exit()

    # Do concat
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
        index += 1
