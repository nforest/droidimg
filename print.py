from __future__ import print_function

import os
import sys

log_file = sys.stderr
sym_file = sys.stdout

def print_log(*args):
    global log_file

    if log_file is None:
        return
    print("".join(map(str,args)), file=log_file)

def print_sym(*args):
    global sym_file

    if sym_file is None:
        return
    print("".join(map(str,args)), file=sym_file)
