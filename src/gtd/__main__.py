import argparse

from gtd.backend.codegen import Codegen
from gtd.config import Config
from gtd.config.function import Function
from gtd.config.handler import Handler
from gtd.config.locations import Locations
from gtd.frontend.simulator import simulate_vm

sample1_fib = Config(
    Locations(vpc_offset=0x140, vsp_offset=0x138, locals_offset=0x30),
    [
        Handler(0xCF, 0x4018AC, 0x4018FB, Handler.DETECT_OPERANDS),
        Handler(0xB5, 0x401903, 0x40195C, Handler.DETECT_OPERANDS),  # 4
        Handler(0x17, 0x401967, 0x4019B3, Handler.DETECT_OPERANDS),  # 4
        Handler(0x68, 0x4019BE, 0x4019EC, Handler.DETECT_OPERANDS),  # 4
        Handler(0xC0, 0x4019F7, 0x401A4E, Handler.DETECT_OPERANDS),  # 4
        Handler(0x55, 0x401A59, 0x401A98, Handler.DETECT_OPERANDS),
        Handler(0xB9, 0x401AA3, 0x401AEC, Handler.DETECT_OPERANDS),
        Handler(0x2F, 0x401AF7, 0x401B1D, Handler.DETECT_OPERANDS),
        Handler(0x49, 0x401B28, 0x401B82, Handler.DETECT_OPERANDS),  # 4
        Handler(0x83, 0x401B8D, 0x401BEE, Handler.DETECT_OPERANDS),  # 4
        Handler(0x79, 0x401BF9, 0x401C0B, Handler.DETECT_OPERANDS),
        Handler(0x53, 0x401C16, 0x401C77, Handler.DETECT_OPERANDS),  # 4
        Handler(0xDB, 0x401C82, 0x401CA9, Handler.DETECT_OPERANDS),
        Handler(0x18, 0x401CB8, 0x401CF5, Handler.DETECT_OPERANDS),
    ],
    [Function(0x401030, 3)],
)

sample1_xtea = Config(
    Locations(vpc_offset=0x140, vsp_offset=0x138, locals_offset=0x30),
    [
        Handler(0xEE, 0x401171, 0x40119A, Handler.DETECT_OPERANDS),
        Handler(0xFA, 0x4011A2, 0x4011EF, Handler.DETECT_OPERANDS),
        Handler(0xB9, 0x4011FA, 0x401243, Handler.DETECT_OPERANDS),
        Handler(0x7C, 0x40124E, 0x401260, Handler.DETECT_OPERANDS),
        Handler(0x8A, 0x40126B, 0x4012B9, Handler.DETECT_OPERANDS),  # 8
        Handler(0x2F, 0x4012C4, 0x401313, Handler.DETECT_OPERANDS),
        Handler(0x97, 0x40131E, 0x401367, Handler.DETECT_OPERANDS),
        Handler(0xF6, 0x401372, 0x40139A, Handler.DETECT_OPERANDS),
        Handler(0xAD, 0x4013A5, 0x4013F2, Handler.DETECT_OPERANDS),
        Handler(0x6F, 0x4013FD, 0x401421, Handler.DETECT_OPERANDS),
        Handler(0x1A, 0x40142C, 0x401450, Handler.DETECT_OPERANDS),
        Handler(0x89, 0x40145B, 0x401498, Handler.DETECT_OPERANDS),
        Handler(0x3D, 0x4014A3, 0x4014EC, Handler.DETECT_OPERANDS),
        Handler(0xCA, 0x4014F7, 0x40154E, Handler.DETECT_OPERANDS),  # 4
        Handler(0xBB, 0x401559, 0x4015A5, Handler.DETECT_OPERANDS),  # 4
        Handler(0x1B, 0x4015B0, 0x4015D7, Handler.DETECT_OPERANDS),
        Handler(0xF0, 0x4015E2, 0x40162E, Handler.DETECT_OPERANDS),  # 4
        Handler(0x1F, 0x40163D, 0x4016D5, Handler.DETECT_OPERANDS),  # 4
        Handler(0xC1, 0x4016E0, 0x40172E, Handler.DETECT_OPERANDS),
        Handler(0xB1, 0x401739, 0x401760, Handler.DETECT_OPERANDS),
        Handler(0xE2, 0x40176B, 0x4017B8, Handler.DETECT_OPERANDS),
        Handler(0xF4, 0x4017C3, 0x401824, Handler.DETECT_OPERANDS),  # 4
        Handler(0x0, 0x401833, 0x401861, Handler.DETECT_OPERANDS),  # 4
    ],
)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("path")
    args = p.parse_args()
    config = sample1_fib
    graphs = simulate_vm(args.path, config)
    codegen = Codegen(config)
    codegen.codegen_vm(graphs)
