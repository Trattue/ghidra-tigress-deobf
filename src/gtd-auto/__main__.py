import argparse
import re
import subprocess
import os
import tomllib
from pathlib import Path

from gtd.config import Config


# /opt/homebrew/Caskroom/ghidra/11.1.1-20240614/ghidra_11.1.1_PUBLIC/
def auto_main():
    p = argparse.ArgumentParser()
    p.add_argument("dir")
    p.add_argument("ghidra_install_dir")
    args = p.parse_args()
    print("THIS SCRIPT WILL PERFORM DESTRUCTIVE OPERATIONS:")
    print(
        "- create files in the samples/ and plugins/ directories (may overwrite old versions)"
    )
    print("- uninstall your old generated Tigress plugins from your Ghidra directory")
    print("- modify the Ghidra project in the plugins/ghidra directory")
    print("- possibly more stuff we forgot to mention here...")
    input("PRESS ENTER TO CONTINUE\n")

    # Step 1: Config files -> processor specs
    gen_processor_specs(args.dir)
    # Step 2: Compile processor specs to plugins
    compile_plugins(args.ghidra_install_dir)
    for file in os.scandir(args.dir):
        if file.is_file and file.name.endswith(".toml"):
            with open(file.path, mode="rb") as f:
                toml_config = tomllib.load(f)
                for vm in toml_config["virtual_machines"]:
                    config = Config.parse(vm)
                    # Step 3: Plugins -> pseudo code files
                    plugin_stuff(args.dir, config, args.ghidra_install_dir)
                    # Step 4: Pseudo code -> C files
                    fix_c_files(config, args.dir)


##############################
# CONFIGS -> PROCESSOR SPECS #
#############################
def gen_processor_specs(config_dir: str):
    for file in os.scandir(config_dir):
        if file.is_file and file.name.endswith(".toml"):
            gen_processor_spec(file.path)


def gen_processor_spec(config_path: str):
    # Use docker since a dependency of angr doesn't support ARM...
    subprocess.call(f"./run_docker.sh main {config_path}", shell=True)


##############################
# PROCESSOR SPECS -> PLUGINS #
##############################
def compile_plugins(ghidra_dir: str):
    # remoce old plugins from Ghidra extension folder
    subprocess.call(f"rm -r {ghidra_dir}/Ghidra/Extensions/tigress-*/", shell=True)
    dirs = [f.path for f in os.scandir("plugins/") if f.is_dir]
    for d in dirs:
        # assuming dir to start with plugin/
        if d[8:].startswith("tigress-"):
            compile_plugin(d, ghidra_dir)


def compile_plugin(plugin_dir: str, ghidra_dir: str):
    subprocess.call(
        f"cd {plugin_dir}; gradle -PGHIDRA_INSTALL_DIR={ghidra_dir}",
        shell=True,
    )
    # install plugin to Ghidra extendion folder
    subprocess.call(
        f"unzip '{plugin_dir}/dist/*.zip' -d {ghidra_dir}Ghidra/Extensions/", shell=True
    )


################################
# PLUGINS -> PSEUDO CODE FILES #
################################


def plugin_stuff(config_dir: str, config: Config, ghidra_dir: str):
    sample = f"{Path(config_dir).as_posix()}/{config.vm_name}"
    subprocess.call(
        f"{ghidra_dir}support/analyzeHeadless samples/ghidra ghidra -import {sample} -processor tigressvm-{config.vm_name}:LE:64 -loader BinaryLoader -preScript DisableCoff.java -postScript Export.java",
        shell=True,
    )


##########################
# PSEUDO CODE -> C FILES #
##########################
def fix_c_files(config: Config, config_dir: str):
    input = f"{Path(config_dir).as_posix()}/{config.vm_name}.dec"
    output = f"{Path(config_dir).as_posix()}/{config.vm_name}.dec.c"
    fix_c_file(input, output, config)


C_FIX = """#define vm /*nothing*/
#define halt_baddata() /*nothing*/
typedef unsigned long long ulonglong;
typedef long long longlong;
typedef unsigned int uint;
"""


def fix_c_file(input_path: str, output_path: str, config: Config):
    if not Path(input_path).exists():
        return
    with open(input_path, "r") as i:
        with open(output_path, "w+") as o:
            # C FIX
            # some macros and definitions known to be needed
            o.write(C_FIX)

            # CONCATS
            # generate macros for every concat macro Ghidra uses in this file
            i.seek(0)
            concats: set[str] = set()
            params: dict[int, str] = dict()
            for i_line in i:
                concat = re.findall("CONCAT\\d*", i_line)
                concats = concats.union(concat)
                # PARAMS
                x = re.search("(.*)in_internal(\\d+)", i_line)
                if x != None:
                    type = x.group(1).lstrip()
                    pos = int(x.group(2))
                    if params.get(pos - 1) == None:
                        params[pos - 1] = type

            for concat in concats:
                c = concat.removeprefix("CONCAT")
                first = int(c[0])
                second = int(c[1:])
                # we assume that first + second is the size of the result's data type...
                # we additionally assume that a data type of that size is defined by
                # Ghidra
                o.write(
                    f"#define {concat}(x, y) ((undefined{first + second})(x) << {second * 8}) | (y)\n"
                )
            o.write("///////\n")

            i.seek(0)
            # FUNCTIONS, part 1
            functions: dict[int, str] = {}
            for f in config.functions:
                functions[f.address] = f.name
            for i_line in i:
                # PARAMS, part 2
                x = re.search("(void \\w+\\()void(\\))", i_line)
                if x != None:
                    o.write(f"{x.group(1)}")
                    for p in sorted(params.keys()):
                        if p != 0:
                            o.write(", ")
                        o.write(f"{params[p]}in_internal{p + 1}")
                    o.write(f"{x.group(2)}\n")
                    continue
                x = re.search("(.*)in_internal(\\d+)", i_line)
                if x != None and params.get(int(x.group(2)) - 1) != None:
                    del params[int(x.group(2)) - 1]
                    continue

                # ASTRUCT
                # initialize astruct so the compiler doesn't complain
                # we assume the struct definition to be as follows, and to only occur
                # one time per function: astruct *fooo;
                x = re.search("astruct \\*\\w*;", i_line)
                if x != None:
                    o.write("astruct locals = {0};\n")
                    (_, b) = x.span()
                    o.write(f"{i_line[:b-1]} = &locals{i_line[b-1:]}")
                    continue

                # FUNCTIONS, part 2
                x = re.findall("func_0x\\d{8}", i_line)
                if len(x) > 0:
                    for f in x:
                        addr = int(f[5:], base=16)
                        i_line = i_line.replace(f, functions[addr])

                o.write(i_line)
