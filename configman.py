##Config reader

import os

# Error for if a config file can't be opened
class ConfigError(Exception):
    pass

def read(config_file):
    try:
        f = open(config_file,"r")
    except:
        raise ConfigError
    data = f.read()
    f.close()
    lines = [line for line in data.split("\n") if "=" in line]
    for line in lines:
        if "#" in line:
            lines[lines.index(line)] = line[:line.index("#")] # strip comments
    d = dict([[val.strip(" ") for val in line.split("=")] for line in lines])
    return d

def write(config_file,d):
    data = d.items()
    d = "\n".join([" = ".join([str(x) for x in line]) for line in data])
    f = open(config_file,"w")
    f.write(d)
    f.close()
