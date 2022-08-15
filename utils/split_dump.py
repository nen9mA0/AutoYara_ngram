from ast import dump
import sys
import os
import getopt
import shutil

suffix = ".asmdump"

def help():
    print("python split_folder.py -i infolder -d dump_folder [-l split_length -p name_prefix]")
    print("infolder:     folder of samples")
    print("dump_folder:    folder of output, must be a folder that not exist")
    print("split_length: number of samples in every subdirectory in outfolder")
    print("name_prefix:  the prefix name of every subdirectory in outfolder")

def WriteMakefile(lines, outfolder, sub_dir_name):
    new_lines = []
    for line in lines:
        if line.find("DUMP_FOLDER =") != -1:
            index = line.find("=")
            new_line = line[:index] + "= " + os.path.join(outfolder, sub_dir_name) + "\n"
            new_line = new_line.replace("\\", "/")         # convert to posix path
        else:
            new_line = line
        new_lines.append(new_line)

    makefile_path = os.path.join(outfolder, sub_dir_name, "makefile")
    with open(makefile_path, "w") as f:
        f.writelines(new_lines)


if __name__ == "__main__":
    opts, args = getopt.getopt(sys.argv[1:], "i:d:l:p:h")
    split_length = 1000
    name_prefix = "Group"
    dump_folder = ""
    for opt, value in opts:
        if opt == "-i":
            infolder = value
        elif opt == "-d":
            dump_folder = value
        elif opt == "-l":
            split_length = int(value, 10)
        elif opt == "-p":
            name_prefix = value
        elif opt == "-h":
            help()
            exit()

    infolder = os.path.abspath(infolder)

    if not os.path.exists(infolder):
        if not os.path.isdir(infolder):
            raise ValueError("infolder not exist: %s" %infolder)

    if not os.path.exists(dump_folder):
        os.mkdir(dump_folder)
    else:
        raise ValueError("dump_folder exist %s" %dump_folder)

    with open("makefile_template.txt") as f:
        lines = f.readlines()

    old_dir = os.getcwd()
    os.chdir(infolder)

    out_dir = dump_folder
    current_out_subdir = None
    num = 0
    group_num = 1

    for file in os.listdir():
        if file.endswith(suffix):
            if current_out_subdir == None or num >= split_length:
                sub_dir_name = name_prefix + "%d"%group_num
                group_num += 1
                current_out_subdir = os.path.join(out_dir, sub_dir_name)
                os.mkdir(current_out_subdir)
                WriteMakefile(lines, out_dir, sub_dir_name)
                num = 0
            shutil.copy(os.path.join(infolder, file), current_out_subdir)
            num += 1

    os.chdir(old_dir)