import argparse
import re
import subprocess
import os


def cfix_main():
    p = argparse.ArgumentParser()
    p.add_argument("input_c")
    p.add_argument("output_c")
    args = p.parse_args()
    fix_c_file(args.input_c, args.output_c)


C_FIX = """#define vm /*nothing*/
#define halt_baddata() /*nothing*/
typedef unsigned long long ulonglong;
"""


def fix_c_file(input_path: str, output_path: str):
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
                o.write(i_line)


# /opt/homebrew/Caskroom/ghidra/11.1.1-20240614/ghidra_11.1.1_PUBLIC/
def plugin_main():
    p = argparse.ArgumentParser()
    p.add_argument("ghidra_install_dir")
    args = p.parse_args()
    ghidra = args.ghidra_install_dir

    dirs = [f.path for f in os.scandir("plugins/") if f.is_dir]
    for dir in dirs:
        # assuming dir to start with plugin/
        if dir[8:].startswith("tigress-"):
            subprocess.call(
                f"cd {dir}; gradle -PGHIDRA_INSTALL_DIR={ghidra}",
                shell=True,
            )
