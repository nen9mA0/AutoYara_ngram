import os
import sys
import getopt

suffix = ".EXE"
change = ".exe"

if __name__ == "__main__":
    opts, args = getopt.getopt(sys.argv[1:], "i:")
    for opt, value in opts:
        if opt == "-i":
            infolder = value

    if not os.path.exists(infolder):
        raise ValueError("infolder not exist: %s" %infolder)
    elif not os.path.isdir(infolder):
        raise ValueError("infolder is not dir: %s" %infolder)
    else:
        file_lst = []
        old_dir = os.getcwd()
        os.chdir(infolder)
        for file in os.listdir():
            if file.endswith(suffix):
                path = os.path.abspath(file)
                path_dir = os.path.dirname(path)
                new_filename = file[:-4] + ".exe"
                os.rename(path, os.path.join(path_dir, new_filename))
        os.chdir(old_dir)