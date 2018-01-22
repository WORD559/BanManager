##Config reader

import os

def read(config_file):
    f = open(config_file,"r")
    data = f.read()
    f.close()
    lines = [line for line in data.split("\n") if "=" in line]
    for line in lines:
        if "#" in line:
            lines[lines.index(line)] = line[:line.index("#")] # strip comments
    d = dict([[val.strip(" ") for val in line.split("=")] for line in lines])
    return d
