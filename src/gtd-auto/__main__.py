import argparse
import os
import re
import subprocess
import tomllib
from pathlib import Path

from gtd.config import Config


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
    dir = Path(args.dir)
    ghidra_dir = Path(args.ghidra_install_dir)
    gen_processor_specs(dir)
    # Step 2: Compile processor specs to plugins
    compile_plugins(ghidra_dir)
    # Remove old Ghidra project
    subprocess.call(
        f"rm -r ./samples/ghidra && mkdir ./samples/ghidra", shell=True
    )
    for file in os.scandir(dir):
        if file.is_file and file.name.endswith(".toml"):
            with open(file.path, mode="rb") as f:
                toml_config = tomllib.load(f)
                for vm in toml_config["virtual_machines"]:
                    config = Config.parse(vm)
                    # Step 3: Plugins -> pseudo code files
                    func_ret_sizes: dict[int, int] = {}
                    plugin_stuff(dir, config, ghidra_dir, func_ret_sizes)
                    # Step 4: Pseudo code -> C files
                    fix_c_files(config, dir, func_ret_sizes)


##############################
# CONFIGS -> PROCESSOR SPECS #
#############################
def gen_processor_specs(config_dir: Path):
    # Delete old plugins
    subprocess.call(f"rm -r plugins/tigress-*", shell=True)

    for file in config_dir.iterdir():
        if file.is_file and file.name.endswith(".toml"):
            gen_processor_spec(file)


def gen_processor_spec(config_path: Path):
    # Use docker since a dependency of angr doesn't support ARM...
    subprocess.call(f"./run_docker.sh poetry run main {config_path}", shell=True)


##############################
# PROCESSOR SPECS -> PLUGINS #
##############################
def compile_plugins(ghidra_dir: Path):
    # remove old plugins from Ghidra extension folder
    subprocess.call(
        f"rm -r {ghidra_dir.joinpath("Ghidra/Extensions/tigress-*/")}", shell=True
    )
    dirs = [f for f in Path("plugins/").iterdir() if f.is_dir]
    for d in dirs:
        # assuming dir to start with plugin/
        if d.name.startswith("tigress-"):
            compile_plugin(d, ghidra_dir)


def compile_plugin(plugin_dir: Path, ghidra_dir: Path):
    subprocess.call(
        f"cd {plugin_dir}; gradle -PGHIDRA_INSTALL_DIR={ghidra_dir}",
        shell=True,
    )
    # install plugin to Ghidra extension folder
    subprocess.call(
        f"unzip '{plugin_dir.joinpath("dist/*.zip")}' -d {ghidra_dir.joinpath("Ghidra/Extensions/")}",
        shell=True,
    )


################################
# PLUGINS -> PSEUDO CODE FILES #
################################
def plugin_stuff(
        config_dir: Path, config: Config, ghidra_dir: Path,
        func_ret_sizes: dict[int, int]
):
    sample = f"{config_dir.joinpath(config.vm_name)}"
    p = subprocess.run(
        f"{ghidra_dir.joinpath("support/analyzeHeadless samples/ghidra")} ghidra -import {sample} -processor tigressvm-{config.vm_name}:LE:64 -loader BinaryLoader -preScript DisableCoff.java -postScript Export.java",
        shell=True,
        capture_output=True,
        text=True,
    )
    print(p.stdout)
    x = re.findall("CALL (0x\\w+) retsize: (\\d+|UNKNOWN)", p.stdout)
    for f in x:
        func_addr = int(f[0], base=16)
        if f[1] == "UNKNOWN":
            func_ret_sizes[func_addr] = 0
        else:
            func_ret_sizes[func_addr] = int(f[1])
    # Remove old Ghidra project
    subprocess.call(
        f"mv ./samples/*.dec {config_dir}", shell=True
    )


##########################
# PSEUDO CODE -> C FILES #
##########################
def fix_c_files(config: Config, config_dir: Path, func_ret_sizes: dict[int, int]):
    input = config_dir.joinpath(f"{config.vm_name}.dec")
    output = config_dir.joinpath(f"{config.vm_name}.dec.c")
    fix_c_file(input, output, config, func_ret_sizes)


C_FIX = """#define vm /*nothing*/
#define halt_baddata() /*nothing*/
typedef unsigned long long ulonglong;
typedef long long longlong;
typedef unsigned int uint;
typedef unsigned char byte;
typedef unsigned long long undefined8;
"""


def fix_c_file(
        input_path: Path, output_path: Path, config: Config,
        func_ret_sizes: dict[int, int]
):
    if not input_path.exists():
        return
    with input_path.open("r") as i:
        print(f"{input_path}")
        with output_path.open("w+") as o:
            print(f"{output_path}")
            # C FIX
            # some macros and definitions known to be needed
            o.write(C_FIX)

            # CONCATS
            # generate macros for every concat macro Ghidra uses in this file
            i.seek(0)
            concats: set[str] = set()
            # params: dict[int, str] = dict()
            for i_line in i:
                concat = re.findall("CONCAT\\d*", i_line)
                concats = concats.union(concat)

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

            # FUNCTIONS, part 1
            # Resolve function names
            functions: dict[int, str] = {}
            for f in config.functions:
                functions[f.address] = f.name
            # FUNCTIONS, part 2
            # Generate extern definitions
            for f in func_ret_sizes:
                ret_size = func_ret_sizes[f]
                ret_type = "void"
                match ret_size:
                    case 1:
                        ret_type = "unsigned char"
                    case 2:
                        ret_type = "unsigned short"
                    case 4:
                        ret_type = "unsigned int"
                    case 8:
                        ret_type = "unsigned long long"
                o.write(f"extern {ret_type} {functions[f]}();\n")
            o.write("///////\n")

            i.seek(0)
            for i_line in i:
                # ASTRUCT
                # initialize astruct so the compiler doesn't complain
                # we assume the struct definition to be as follows, and to only occur
                # one time per function: astruct *fooo;
                x = re.search("astruct \\*\\w*;", i_line)
                if x is not None:
                    o.write("astruct locals = {0};\n")
                    (_, b) = x.span()
                    o.write(f"{i_line[:b - 1]} = &locals{i_line[b - 1:]}")
                    continue

                # FUNCTIONS, part 3
                # Rename functions to their names
                x = re.findall("func_0x\\d{8}", i_line)
                if len(x) > 0:
                    for f in x:
                        addr = int(f[5:], base=16)
                        i_line = i_line.replace(f, functions[addr])

                o.write(i_line)
