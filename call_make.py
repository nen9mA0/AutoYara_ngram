import os
import sys
import subprocess as sp
import getopt

multi_process = True
dump_folder = "/home/lishijia/autoyara/dump/sample_split"
# myfolder = [
#            "acprotect",
#            "armadillo",
#            "aspack",
#            "asprotect",
#            "beroexepacker",
#            "enigma",
#            "fsg",
#            "jdpack",
#            "kkrunchy",
#            "mew",
#            "molebox",
#            "mpress",
#            "neolite",
#            "obsidium",
#            "Packman",
#            "pecompact",
#            "pelock",
#            "petite",
#            "themida",
#            "upx",
#            "winlicense",
#            "winupack",
#            "zprotect"
#        ]

myfolder = os.listdir(dump_folder)
print("Folders:")
print(myfolder)
print("Continue?")
# a = input()
# if "q" in a:
  #   exit()

pipe_lst = []
ret_lst = []
if __name__ == "__main__":
    opts, args = getopt.getopt(sys.argv[1:], "n:")
    for opt, value in opts:
        if opt == '-n':
            num = int(value)

    for folder in myfolder:
        # cmd = "make -j8 -k MYSUBDIR=%s" %folder
        # cmd = "make debug -k MYSUBDIR=%s" %folder
        cmd = "make build_table -k MYSUBDIR=%s NUM=%d" %(folder, num)
        sub_dir = os.path.join(dump_folder, folder)
        if not os.path.exists(sub_dir):
            os.mkdir(sub_dir)
        print(cmd)
        if multi_process:
            # p = sp.Popen(cmd.split(), stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE)
            p = sp.Popen(cmd.split())
            pipe_lst.append( (p, cmd) )
        else:
            os.system(cmd)
        # input()

    if multi_process:
        for p, cmd in pipe_lst:
            p.wait()
            ret_lst.append( (p.returncode, cmd) )
        for ret, cmd in ret_lst:
            print("%s : retcode %d" %(cmd, ret))

