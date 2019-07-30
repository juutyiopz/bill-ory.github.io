#!/usr/bin/python
from __future__ import print_function

import struct
import os
import sys

def generate_array_by_file(filename):
    basename = os.path.basename(filename)
    if basename.find(".") != -1:
        basename = basename[:basename.find(".")]
    arr_name = basename + "_arrar"
    print("unsigned char " + arr_name + "[] = {", end="\n")


    fp = open(filename, 'rb')
    content_str = fp.read()
    cnt = 0
    for v in content_str:
        end_str = ","
        if (cnt + 1) % 16 == 0:
            end_str = ",\n"
            
        print("0x%02x"%ord(v), end = end_str)
        cnt = cnt + 1
    print("};\n")
    print("unsigned char *get_" + arr_name + "(unsigned int *len)")
    print("{")
    print("    *len = sizeof(" + arr_name + ");")
    print("    return " + arr_name + ";")
    print("}")

def main():
    generate_array_by_file(sys.argv[1])

if __name__ == "__main__":
    main()
