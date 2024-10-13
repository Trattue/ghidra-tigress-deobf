import subprocess
from pathlib import Path

samples = [
    ("sample.c", "fib", "sample_obf_fib.dec.c", "sample_obf_fib",
     "sample_sobf_fib.dec.c", "sample_sobf_fib"),
    ("sample.c", "xtea", "sample_obf_xtea.dec.c", "sample_obf_xtea",
     "sample_sobf_xtea.dec.c", "sample_sobf_xtea"),
    # ("sample.c", "interact", "sample_obf_interact.dec.c", "sample_obf_interact",
    #  "sample_sobf_interact.dec.c", "sample_sobf_interact"),
]

imports = ""
# imports = """#include <stdint.h>
# #include <stdio.h>
# #include <stdlib.h>
#
# """

folder = Path("./samples/custom")
tmp = folder.joinpath("./tmp.c")
tmp.touch()
evaluation = Path("./evaluation")
main_fib = evaluation.joinpath("main_fib.c")
main_fib_obf = evaluation.joinpath("main_fib_obf.c")
main_xtea = evaluation.joinpath("main_xtea.c")
main_xtea_obf = evaluation.joinpath("main_xtea_obf.c")

compiled = []

# CREATE BINARIES

# FIB
sample = samples[0]
# Test file for original
original = folder.joinpath(f"{sample[0]}")
compiled_original = evaluation.joinpath(f"{sample[0]}-fib.out")
with tmp.open("w") as tmp_f:
    with original.open("r") as f:
        content = f.read().split("int main() {}")[0]
        tmp_f.write(content)
    with main_fib.open("r") as f:
        tmp_f.write(f.read())
subprocess.run(["gcc", "-o", compiled_original.as_posix(), tmp.as_posix()])
# Test file for obf .dec.c
obf_dec = folder.joinpath(f"{sample[2]}")
compiled_obf_dec = evaluation.joinpath(f"{sample[2]}.out")
with tmp.open("w") as tmp_f:
    tmp_f.write(imports)
    with obf_dec.open("r") as f:
        content = f.read()
        tmp_f.write(content)
    with main_fib_obf.open("r") as f:
        tmp_f.write(f.read())
subprocess.run(["gcc", "-o", compiled_obf_dec.as_posix(), tmp.as_posix()])
# Test file for sobf .dec.c
sobf_dec = folder.joinpath(f"{sample[4]}")
compiled_sobf_dec = evaluation.joinpath(f"{sample[4]}.out")
with tmp.open("w") as tmp_f:
    tmp_f.write(imports)
    with sobf_dec.open("r") as f:
        content = f.read()
        tmp_f.write(content)
    with main_fib_obf.open("r") as f:
        content = f.read().replace("sample_obf_fib", "sample_sobf_fib")
        tmp_f.write(content)
subprocess.run(["gcc", "-o", compiled_sobf_dec.as_posix(), tmp.as_posix()])
compiled.append((compiled_original, compiled_obf_dec, compiled_sobf_dec))

# XTEA
sample = samples[1]
# Test file for original
original = folder.joinpath(f"{sample[0]}")
compiled_original = evaluation.joinpath(f"{sample[0]}-xtea.out")
with tmp.open("w") as tmp_f:
    with original.open("r") as f:
        content = f.read().split("int main() {}")[0]
        tmp_f.write(content)
    with main_xtea.open("r") as f:
        tmp_f.write(f.read())
subprocess.run(["gcc", "-o", compiled_original.as_posix(), tmp.as_posix()])
# Test file for obf .dec.c
obf_dec = folder.joinpath(f"{sample[2]}")
compiled_obf_dec = evaluation.joinpath(f"{sample[2]}.out")
with tmp.open("w") as tmp_f:
    tmp_f.write(imports)
    with obf_dec.open("r") as f:
        content = f.read()
        tmp_f.write(content)
    with main_xtea_obf.open("r") as f:
        tmp_f.write(f.read())
subprocess.run(["gcc", "-o", compiled_obf_dec.as_posix(), tmp.as_posix()])
# Test file for sobf .dec.c
sobf_dec = folder.joinpath(f"{sample[4]}")
compiled_sobf_dec = evaluation.joinpath(f"{sample[4]}.out")
with tmp.open("w") as tmp_f:
    tmp_f.write(imports)
    with sobf_dec.open("r") as f:
        content = f.read()
        tmp_f.write(content)
    with main_xtea_obf.open("r") as f:
        content = f.read().replace("sample_obf_xtea", "sample_sobf_xtea")
        tmp_f.write(content)
subprocess.run(["gcc", "-o", compiled_sobf_dec.as_posix(), tmp.as_posix()])
compiled.append((compiled_original, compiled_obf_dec, compiled_sobf_dec))

# TEST BINARIES
errors: dict[str, int] = {}

for sample in compiled:
    original = sample[0]
    obf_dec = sample[1]
    sobf_dec = sample[2]

    errors[obf_dec.name] = 0
    errors[sobf_dec.name] = 0

    r = subprocess.run([original], stdout=subprocess.PIPE)
    original_val = r.stdout.decode("utf-8").rstrip("\n")
    r = subprocess.run([obf_dec], stdout=subprocess.PIPE)
    obf_dec_val = r.stdout.decode("utf-8").rstrip("\n")
    r = subprocess.run([sobf_dec], stdout=subprocess.PIPE)
    sobf_dec_val = r.stdout.decode("utf-8").rstrip("\n")

    if original_val != obf_dec_val:
        print(f"mismatch between {original.name} and {obf_dec.name}:")
        print(f"  {original_val} != {obf_dec_val}")
        errors[obf_dec.name] += 1
    if original_val != sobf_dec_val:
        print(f"mismatch between {original.name} and {sobf_dec.name}:")
        print(f"  {original_val} != {sobf_dec_val}")
        errors[sobf_dec.name] += 1

print(errors)
