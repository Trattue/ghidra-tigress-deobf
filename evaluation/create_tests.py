import subprocess
from pathlib import Path

samples = [
    ("bkdrhash.c", "BKDRHash", "bkdrhash_obf_BKDRHash.dec.c", "bkdrhash_obf_BKDRHash",
     "bkdrhash_sobf_BKDRHash.dec.c", "bkdrhash_sobf_BKDRHash", "bkdrhash.obf.c",
     "bkdrhash.obf.c.out"),
    ("bphash.c", "BPHash", "bphash_obf_BPHash.dec.c", "bphash_obf_BPHash",
     "bphash_sobf_BPHash.dec.c", "bphash_sobf_BPHash", "bphash.obf.c",
     "bphash.obf.c.out"),
    ("dekhash.c", "DEKHash", "dekhash_obf_DEKHash.dec.c", "dekhash_obf_DEKHash",
     "dekhash_sobf_DEKHash.dec.c", "dekhash_sobf_DEKHash", "dekhash.obf.c",
     "dekhash.obf.c.out"),
    ("djbhash.c", "DJBHash", "djbhash_obf_DJBHash.dec.c", "djbhash_obf_DJBHash",
     "djbhash_sobf_DJBHash.dec.c", "djbhash_sobf_DJBHash", "djbhash.obf.c",
     "djbhash.obf.c.out"),
    ("elfhash.c", "ELFHash", "elfhash_obf_ELFHash.dec.c", "elfhash_obf_ELFHash",
     "elfhash_sobf_ELFHash.dec.c", "elfhash_sobf_ELFHash", "elfhash.obf.c",
     "elfhash.obf.c.out"),
    ("fnvhash.c", "FNVHash", "fnvhash_obf_FNVHash.dec.c", "fnvhash_obf_FNVHash",
     "fnvhash_sobf_FNVHash.dec.c", "fnvhash_sobf_FNVHash", "fnvhash.obf.c",
     "fnvhash.obf.c.out"),
    ("jshash.c", "JSHash", "jshash_obf_JSHash.dec.c", "jshash_obf_JSHash",
     "jshash_sobf_JSHash.dec.c", "jshash_sobf_JSHash", "jshash.obf.c",
     "jshash.obf.c.out"),
    ("pjwhash.c", "PJWHash", "pjwhash_obf_PJWHash.dec.c", "pjwhash_obf_PJWHash",
     "pjwhash_sobf_PJWHash.dec.c", "pjwhash_sobf_PJWHash", "pjwhash.obf.c",
     "pjwhash.obf.c.out"),
    ("rshash.c", "RSHash", "rshash_obf_RSHash.dec.c", "rshash_obf_RSHash",
     "rshash_sobf_RSHash.dec.c", "rshash_sobf_RSHash", "rshash.obf.c",
     "rshash.obf.c.out"),
    ("sdbmhash.c", "SDBMHash", "sdbmhash_obf_SDBMHash.dec.c", "sdbmhash_obf_SDBMHash",
     "sdbmhash_sobf_SDBMHash.dec.c", "sdbmhash_sobf_SDBMHash", "sdbmhash.obf.c",
     "sdbmhash.obf.c.out"),
]

imports = """#include <stdlib.h>
#include <stdio.h>
#include <string.h>

"""

folder = Path("./samples/simple_hash")
tmp = folder.joinpath("./tmp.c")
tmp.touch()
main = Path("./evaluation/main.c")
main_tigress = Path("./evaluation/main_tigress.c")
main_obf = Path("./evaluation/main_obf.c")
evaluation = Path("./evaluation")

compiled = []

# CREATE BINARIES

MAIN = "int main(int argc , char **argv , char **_formal_envp ) \n{"

for sample in samples:
    # Test file for obfuscated original
    obf_original = folder.joinpath(sample[6])
    compiled_obf_original = evaluation.joinpath(sample[7])
    with tmp.open("w") as tmp_f:
        with obf_original.open("r") as f:
            content = f.read()
            with main_tigress.open("r") as main_f:
                main_content = main_f.read().replace("HASH_FUNC_OBF", sample[1])
                new_main = main_content.split("}")[0]
                new_content = content.replace(MAIN, new_main)
                tmp_f.write(new_content)
    subprocess.run(["gcc", "-o", compiled_obf_original.as_posix(), tmp.as_posix()])

    # Test file for original
    original = folder.joinpath(f"{sample[0]}")
    compiled_original = evaluation.joinpath(f"{sample[0]}.out")
    with tmp.open("w") as tmp_f:
        with original.open("r") as f:
            content = f.read().split("/* End Of ")[0]
            tmp_f.write(content)
        with main.open("r") as f:
            content = f.read().replace("HASH_FUNC", sample[1])
            tmp_f.write(content)
    subprocess.run(["gcc", "-o", compiled_original.as_posix(), tmp.as_posix()])

    # Test file for obf .dec.c
    obf_dec = folder.joinpath(f"{sample[2]}")
    compiled_obf_dec = evaluation.joinpath(f"{sample[2]}.out")
    with tmp.open("w") as tmp_f:
        tmp_f.write(imports)
        with obf_dec.open("r") as f:
            content = f.read()
            tmp_f.write(content)
        with main_obf.open("r") as f:
            content = f.read().replace("HASH_FUNC_OBF", sample[3])
            tmp_f.write(content)
    subprocess.run(["gcc", "-o", compiled_obf_dec.as_posix(), tmp.as_posix()])

    # Test file for sobf .dec.c
    sobf_dec = folder.joinpath(f"{sample[4]}")
    compiled_sobf_dec = evaluation.joinpath(f"{sample[4]}.out")
    with tmp.open("w") as tmp_f:
        tmp_f.write(imports)
        with sobf_dec.open("r") as f:
            content = f.read()
            tmp_f.write(content)
        with main_obf.open("r") as f:
            content = f.read().replace("HASH_FUNC_OBF", sample[5])
            tmp_f.write(content)
    subprocess.run(["gcc", "-o", compiled_sobf_dec.as_posix(), tmp.as_posix()])

    compiled.append(
        (compiled_original, compiled_obf_dec, compiled_sobf_dec, compiled_obf_original))

# TEST BINARIES

test_values = ["", " ", "e", "OyG", "WdOeK", "UhSnZLr", "ho8NUUtZl", "C$EZm122t?7",
               "*Hn85)93Aa,I3"]

errors: dict[str, int] = {}

for sample in compiled:
    original = sample[0]
    obf_dec = sample[1]
    sobf_dec = sample[2]
    original_obf = sample[3]

    errors[obf_dec.name] = 0
    errors[sobf_dec.name] = 0

    for value in test_values:
        r = subprocess.run([original, value], stdout=subprocess.PIPE)
        original_val = r.stdout.decode("utf-8").rstrip("\n")
        # r = subprocess.run([original_obf, value], stdout=subprocess.PIPE)
        # original_obf_val = r.stdout.decode("utf-8").rstrip("\n")
        r = subprocess.run([obf_dec, value], stdout=subprocess.PIPE)
        obf_dec_val = r.stdout.decode("utf-8").rstrip("\n")
        r = subprocess.run([sobf_dec, value], stdout=subprocess.PIPE)
        sobf_dec_val = r.stdout.decode("utf-8").rstrip("\n")

        # if original_val != original_obf_val:
        #     print(f"LMFAO TIGRESS TRASHHH {original_val} != {original_obf_val}")
        if original_val != obf_dec_val:
            print(f"mismatch between {original.name} and {obf_dec.name} for {value}:")
            print(f"  {original_val} != {obf_dec_val}")
            errors[obf_dec.name] += 1
        if original_val != sobf_dec_val:
            print(f"mismatch between {original.name} and {sobf_dec.name} for {value}:")
            print(f"  {original_val} != {sobf_dec_val}")
            errors[sobf_dec.name] += 1

print(compiled)

print("Summary:")
for n, e in errors.items():
    print(f"{n}: {len(test_values) - e}/{len(test_values)} "
          f"({1 - (e / len(test_values)):.2%} success)")
print(f"Total test success rate: "
      f"{1 - (sum(errors.values()) / (len(test_values) * len(errors))):.2%}")
correct_samples = len(list(filter(lambda x: errors[x] == 0, errors)))
print(
    f"Correct samples: {correct_samples}/{len(errors)} ({correct_samples / len(errors):.2%})")
