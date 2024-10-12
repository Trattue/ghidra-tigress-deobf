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

test_values = ["", "G", "ok", "PEx", "yN1J", "SmcvK", "6nIcOc", "NI5VNU8", "QYR10KRW",
               "ppLIulmvB", "dLFNmDSUal", "OnmHlJsRru3", "PcYsns3EKFxd",
               "A1vLpeHU1SoPy", "XInZBqURQWBfPO", "ssXuUkrlbYt1Xdm", "ZXsdfWBHHMGenBrM",
               "iSfTvcJwM6jMSuAkj", "TF0U1sGco5E3Rv9qpr", "lGemGbV8EXqjc4HaAiW",
               "cuQY3tGj1plwO4591O5o", "BB4c4nZVVaO9XVmiRa7TS",
               "P1QU2HgIiIhIsqZueAswJT", "OJHqlMWRKBs7Zun7La55djd",
               "V9ZQX4L2SrmEbQUOobUmtUeh", "VOloNWUUHdzv4QqjAyj238Ixd",
               "x86wlXNcs1e5ju2inmW2yVmzTW", "742O7O9n199paB54merawDiN1az",
               "wnlriHqd2NRORXiXxRkSgPNuEnO2", "PAaey8J2uJc6iMfyfZFDsKSJMUKuN",
               "pjdV2vYRgyrjlAcl0qvfz31j2i9FS6", "P81obvs4RnZdsmGaORcoROtJsxa92lP",
               "jkKSMNlhNZ8oHfTLQ4a7j94gdanmDYD6", "3IYlAkPLpuWCbmY8ithWhguAREE4f7CNy",
               "mbNmhdILCUsZkvSdqNVrqBuC4zjVPOf3jU",
               "KbtZy7iZz3QcorrhRmbfOhNzXyu3eZQd23w",
               "V12dNeFO37yR7d1ls5j0DtMKrtdrma0sb9hC",
               "urt8ShOR88KG04zPxTIR9Z81Ql6PXvBM6Q63b",
               "izh8zmj0hbUhUinbg3yl4s1Cs1lnmKDM8u4W83",
               "w6APr93ga6GZg7GYNyrx7sjXIEGyX11RqNjbdWr",
               "o5Biqn8ICM3zi3zBgR9CgY46qbvgCAz9WK4QAzyW",
               "jeZvGz8tU9zcFaIiLOEAsumFS7uYEF3MkZhLumw24",
               "aABEHnRS4A9obg2ndUTQlyTJ9LGetpfZ2R8LuqsU4l",
               "3raC0DdNhIolaxfWntifU6RlRZPpvgKVVjwGJRK39av",
               "tcnnP0SI9Rza5livq3wC0hYKKwh7B1ui8h2RN8SMWMlE",
               "AUKtpVmHNmyzwx5RWQ2q9CRl0ZI0WUhtTPxMI4gfH8wKQ",
               "ku0vFA0ZXhVUaEpCmum3eydlzij884g1aJG4G7MYa3001D",
               "7lQUL85DhI7FtA1PK8R7mlTUVZDmTWEwHoAsnzgl1xPAiDw",
               "KJcia1xsDsfmdrYdyQrFu64mN6ulyiiEPfzpVtVXp3bbDqL9",
               "d8yoezZEdsWrs8rB9Q2UjaXjtMDBy4xCGDSGAsBA2NsmzQJaV",
               "7Qw75pzEKQKZzHv5P3YSFsTbFXg38M1kFgmLp7UzeBDoNgUPjB",
               "3z0oltAMCHEHAhMq5Q9d7qiSzNTomF3FTOX6mpMevHfv0QwxUxt",
               "Y9BCVLReW2fGymf86xLX2ao6YdxKZNFyvmN0xVOn51KVBaMa1hsx",
               "3Rvvale75S0luuI44Hz03hnWnympPrilK4WEF7CVqrf70gYDKUsnP",
               "2YDQPAFWv5dkCumfoiKEbS5huCUhnkJkjSPIPlPhQim80WxX6hPJdq",
               "Acbp3GcTDs2jmjq2eBqf00Skzl5A9GcpY97ALXhyOaJF1Qhs1Qg8LFd",
               "klmAizPfKKUFzufBv5LJsJ0YF0iJjMpOvDtaOlq4XxOFzVwCbXQ8klZv",
               "CDy21a8a3x70qAZJg75Nt1XeT7qVFAXiCymrBlQRn5PbF2Hr39m8zbUAM",
               "O7Yp5tvdyiMJ9CoLa484OrroheuY6BdmRhadtFtiBiUgw00FqZI1MzF8pk",
               "vA7A5mVzw6mLsdNXa4EYT3XlCd4R3uYUVvDw01wcCtiOlIVkrGfcLKmvLtU",
               "omV2p21x0FWa5gLV7PKOLHBb7gZq0uYkjbsFSd27EWkn2kJ48G4lObFwJn8U",
               "os8MnUXxLoDs9HIB5tJAUsVrqPNfrlbg552bBYaLWa3HRt5MfTBGXqXx5WX70",
               "P8DgvJ3Xl5KyWbx8370LzcGUlSRa8n41xuG2OhGFCUzlXH7fg1Auv2I5uWW2Iy",
               "50wxV1u9dlydJdi2qjhbfJJJqdOhOOa75yy65WkvrHfvXf6xbssUaAJNbvOV4jX",
               "EloPyDm0CRE1oAEPiDPSQam55dcnq3hqcdXpYHcbTPLA1L7KiacLqySFr9uhNLFG",
               "DbkfhjllX1vE4zZUrg0Z1YvU9dnUAourvdv0hNnLrOoQ11xX9AhUplWXfpdBABjrI",
               "kicQc7xyrnAsN5fx46oV1dMclZJpiar5NhocrizbgTJvbnIWYwDH9cJ9C99sjppkQh",
               "mC6bcYUInzADx5qYh73vMUT4zuC5vJAloLLafKxN7Q3FmPJrgrEOOogiPBLS2u0R843",
               "gA18rNnTDCHePqVyRlVJEyuTWLE0vcmHwZFZuNRXPO2hMfX67QnOwW4Kw5u7UM4mJKq1",
               "9tqBG1SiLMlSIGFd8pbnklrYHUJ0uVP1OL2WYBdcTMUZTPMAskJdyeQogM4pwdwNoH1Of",
               "ALE43Np8XFLdguviteWliysiq8xFP2ia9GXqz1kFCo3EMS4syIRLHFmSlfUW7JfMi6379n",
               "0xExMS1GLSUZrx3V305JHeZgxRquGAKphqnQATBkCaCR2OZdfmFIkh86ChbeMGOJFbXF7VB",
               "5Typ6Zi5dGrqzTCLow6SvvchhHWTMd82onPfFrg87N5ouprPkujVNhImu4RL3Va0zHArQ85a",
               "awckjCsPMCLyS2g3mTrHimUWniRssi0RpRIIAsWkpxC8bgXcDKeXutsvvznl0CO3XTDb278UG",
               "Rfh01FupV2VoZZ5owPfYss5pgvxR76zhEB86EdOG7B0BrLmEYHDi0VgAPEBYkXePUqerV4INtx",
               "5T0TyL2PWRYw7G7DfdH4xmMq3UcvKt5LnYLlxcKCSmJDTWBqWiTKSuYKpDHlkFxKj88UB0Gy5RH",
               "8MOre2ubrv0N6wDF1HguF2JLmIYYtQj0wxPODM9LxEhGwxZCW072BeTuUal3EbKB37sAD6AKw9Fr",
               "bIKJfspWKJBQHx7xlLqeQhCAzDImQbJyJAO8foXG8yAwcXiR5EBeDrVTkWmNCvcmUA7DBVxmBnVrn",
               "1IODrwrXfm266z9fLQNIytvplPpvUmtfpytPwpdJOxVDxUmPP2yG9kdouOAsFXf5Jcm0YPkbamirSD",
               "0JulBMWcvFiwnVtXs1LgTELfEeLzAxm7YgTfoEMDg7NRPMyaeKEnZyi7eOukVfRRdDeHob2JMunslgZ",
               "jsi9p90aTnOGJXouiRmkVvi2urODfl6NpWYBscR1PyPxYZeL6YKJxKHaM9xn8Al8cNoqriCXlanCqSp9",
               "7qvm3kRflkBeS9amvZTchCuCByD1GVSt70mcpRADTwq75va4TENiv4FjKAEJYz9crzCU0rmMytAoQUt8K",
               "21a9N0lNvogCCVm8sozLx66KSqnuW7FtCzlapeA2egsGNAY7ggyg1ehnnHHp3b8OsBEX9l1ZwcXO1ODw0s",
               "koHGKQwl3lSVEc0qmTqSVJ4OFfD8AKTqnZcRxwROYW7tBBpYgbWtouh9ljKtqqMml8fbPqwQqLuynkswAg5",
               "lfjB9VwjlpyX6DXQoc8HjbiZjJ95OQ0ljY1w2PogefATi5j0fG2Togmxk23cw2K4h6yL3mjQpXVCV1FUhT27",
               "E1HKkIxNJBh5OxQmQC74g39jNbNZLdmh5UO2RWaKZx6faFWvxKSZ9Y7qXI1xRhjaAY7zGf8kMPR1yMtQjrLKt",
               "0AR57FdX6rMrv0bso9T3z8dOxqGbsSkSuvd0qI6b3Z7Rv7LeNxL1500cUuFhjE831bS5UquYZbrQ6HLVkcc8Kx",
               "CfsxfCOvMLUDEj2GEvqDQbSIE3yKw7KaWiqBkKOxDtgv5rMahNYVGWGNUjBQu4u6RV9z7DElp4P79hDQY4rrnK0",
               "nvRWHHmg7ZvtPKe7DuCuGcRBtuyppUxLR7CL8S3NIkFgLZA0fQo1umQO9Vn1RGubYj9n8qNTjhi0iKJkr8bKoEl9",
               "1CZrQz9p7jptdVd8w79NuZvQyIgmMwZPTTUQTHeMHp2ZHSv5wMf0gK1JQKOxiVwhBMzcdHzACYzrcEb7kZl0YZc0q",
               "6qVa3fVoeahKjP2VcnYyKa4Q9RZNJq79IDvBBwHWP6Amao2zy19LSSS6QBzd6FaCMI21n6nlSg04baZpXWwvfZCK4z",
               "sOgmvIlBmWFLWwaLvH8IanbVGQd08h0lBwiMXLiwlLTUnpG4dLU2oDAss0CcbgWaYBg3VlyqlsjG0ZmamoaSg6RSocs",
               "cYpWyZX471jUMz57AtIDwGmsulfJ0qz4ZwYuebvXOXZcUjxTN1AWNzqNMPNHhw8d2eepwqqg5hbrlkZbJJjLSc48MDME",
               "hzCr0ezYniu9wm9Y8lHw3QsqhKKNoK7C14VHHtsh6htRRQNi71AQOCoSIDKX4ZEwnIAR939M5uyCkviMfzNur7NnKXr3s",
               "LaQB9JI8mq9Y3XO9aC0v3kon9bLG2zXTX3PCZy47FkfUWV7nwhSatKPwmQo2eoJpDgAgK6yNXhYGfuZ9xyzAZifqP8KTMa",
               "nbzTqmzhUr021ZonL6dIBF3YeDJAbjEUCpktslOIDYOdvkVSxd1rMgSnbtn0cph9IuABniPsUKkniHlUGmR4B80rNV793Hv",
               "jIcUumX5piKD28eU8jwcwKgOTVY18erEHEvj60z8LqbdFYWDoLlYeu9LEuc7soexBQ3w074RItyk1KWJ35KPXpfEQbJmbT5F",
               "TixRBwWLq3hRX7G4tPgb2IzP0iWGJZgr0u5swCVO3ssJy0Vf9thtlDVk06tITE5aMzWGCIZRLQqsnAcuCSBVReTrTSF4MmJ5M",
               "zVtxeSh0JV466GApMeHEtV69rNO6f3SM7wgmUBvVF2JuThfi2TBqsxT8efZPRIyhxSlrYfMPV2BU30lovXiW8ShjHLKDRtiI54",
               "lJ1qspRfUB8gsBeSflzE3kMoExFtS1hvVjuyfoDmqIBMxu78s6tULi72c9akdXOE9J2LuCCB0t4VGBWzoSSuYtKDHNsvniLfk8B"]

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
