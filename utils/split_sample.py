from ast import dump
import sys
import os
import getopt
import shutil

suffix = ".exe"

def help():
    print("python split_folder.py -i infolder -o outfolder [-d dump_folder -l split_length -p name_prefix]")
    print("infolder:     folder of samples")
    print("outfolder:    folder of output, must be a folder that not exist")
    print("dumpfolder:   folder of dump files, by default we use the folder in makefile_template")
    print("split_length: number of samples in every subdirectory in outfolder")
    print("name_prefix:  the prefix name of every subdirectory in outfolder")

def WriteMakefile(lines, outfolder, dump_folder, sub_dir_name):
    new_lines = []
    for line in lines:
        if line.find("TARGET_FOLDER =") != -1:
            index = line.find("=")
            new_line = line[:index] + "= " + os.path.join(outfolder, sub_dir_name) + "\n"
            new_line = new_line.replace("\\", "/")         # convert to posix path
        elif line.find("DUMP_FOLDER =") != -1:
            if dump_folder != "":
                index = line.find("=")
                new_line = line[:index] + "= " + os.path.join(dump_folder, sub_dir_name) + "\n"
            else:
                new_line = line[:-1] + "/%s\n" %sub_dir_name
            new_line = new_line.replace("\\", "/")
        else:
            new_line = line
        new_lines.append(new_line)

    makefile_path = os.path.join(outfolder, sub_dir_name, "makefile")
    with open(makefile_path, "w") as f:
        f.writelines(new_lines)


if __name__ == "__main__":
    opts, args = getopt.getopt(sys.argv[1:], "i:o:d:l:p:h")
    split_length = 1000
    name_prefix = "Group"
    dump_folder = ""
    for opt, value in opts:
        if opt == "-i":
            infolder = value
        elif opt == "-o":
            outfolder = value
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
    outfolder = os.path.abspath(outfolder)
    if dump_folder != "":
        dump_folder = os.path.abspath(dump_folder)

    if not os.path.exists(infolder):
        if not os.path.isdir(infolder):
            raise ValueError("infolder not exist: %s" %infolder)

    if not os.path.exists(outfolder):
        os.mkdir(outfolder)
    else:
        raise ValueError("outfolder exist %s" %outfolder)

    with open("makefile_template.txt") as f:
        lines = f.readlines()

    old_dir = os.getcwd()
    os.chdir(infolder)

    out_dir = outfolder
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
                WriteMakefile(lines, out_dir, dump_folder, sub_dir_name)

                dump_subdir = os.path.join(dump_folder, sub_dir_name)
                if not (os.path.exists(dump_subdir) and os.path.isdir(dump_subdir)):
                    os.mkdir(dump_subdir)
                num = 0
            shutil.copy(os.path.join(infolder, file), current_out_subdir)
            num += 1

    os.chdir(old_dir)