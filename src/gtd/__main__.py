import argparse

from gtd.handler import Handler
from gtd.stuff import do_stuff

handlers = [
    # Size 5, load string (no cond)
    Handler(0xD2, 0x4011E4, 0x40123E),
    # Size 5, relative jump (no cond)
    Handler(0x6B, 0x401246, 0x401274),
    Handler(0x4C, 0x40127F, 0x4012CB),
    Handler(0x33, 0x4012D6, 0x401313),
    Handler(0x18, 0x40131E, 0x401375),
    Handler(0xF0, 0x401380, 0x4013A7),
    Handler(0x2E, 0x4013B2, 0x401413),
    Handler(0xBC, 0x40141E, 0x401444),
    # Size 1, return
    Handler(0xA6, 0x40144F, 0x401461),  # 0x401466
    Handler(0x3D, 0x40146C, 0x4014B5),
    # Size 5, relative jump if arg is not zero
    Handler(0x77, 0x4014C0, 0x401521),
    # Size 5, load function param if arg is zero
    Handler(0xEA, 0x40152C, 0x401585),
    Handler(0x85, 0x401590, 0x4015CF),
    Handler(0xF8, 0x4015DE, 0x40162D),
]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("path")
    # p.add_argument("config")
    args = p.parse_args()
    # TODO: do stuff with args.sample and args.config
    # TODO: use configparser
    do_stuff(args.path, handlers)
