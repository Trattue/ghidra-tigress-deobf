import argparse

from gtd.backend.codegen import Codegen
from gtd.config import Config
from gtd.config.function import Function
from gtd.config.handler import Handler
from gtd.config.locations import Locations
from gtd.frontend.simulator import simulate_vm

sample1_fib = Config(
    "sample1_fib",
    Locations(
        vpc_offset=0x140, vsp_offset=0x138, locals_offset=0x30, internal_offsets=[0x144]
    ),
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
    "sample1_xtea",
    Locations(
        vpc_offset=0x140,
        vsp_offset=0x138,
        locals_offset=0x30,
        internal_offsets=[0x144, 0x150, 0x158],
    ),
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

sample2_fib = Config(
    "sample2_fib",
    Locations(
        vpc_offset=0x140, vsp_offset=0x138, locals_offset=0x30, internal_offsets=[0x144]
    ),
    [
        Handler(0x86, 0x401163, 0x4011D7, Handler.DETECT_OPERANDS),
        Handler(0x45, 0x4011E6, 0x40128F, Handler.DETECT_OPERANDS),
        Handler(0x96, 0x40129E, 0x401346, Handler.DETECT_OPERANDS),
        Handler(0xB4, 0x401351, 0x4013B2, Handler.DETECT_OPERANDS),
        Handler(0xB6, 0x4013C1, 0x40143D, Handler.DETECT_OPERANDS),
        Handler(0x77, 0x40144C, 0x4014E0, Handler.DETECT_OPERANDS),
        Handler(0xA2, 0x4014EB, 0x4014FD, Handler.DETECT_OPERANDS),
        Handler(0xE7, 0x40150C, 0x40159D, Handler.DETECT_OPERANDS),
        Handler(0x28, 0x4015AC, 0x40168B, Handler.DETECT_OPERANDS),
        Handler(0x2, 0x401696, 0x401706, Handler.DETECT_OPERANDS),
        Handler(0xD9, 0x401715, 0x4017DA, Handler.DETECT_OPERANDS),
        Handler(0x51, 0x4017E5, 0x40183E, Handler.DETECT_OPERANDS),
        Handler(0x18, 0x40184D, 0x4018F2, Handler.DETECT_OPERANDS),
        Handler(0x75, 0x401901, 0x40192F, Handler.DETECT_OPERANDS),
    ],
    [Function(0x401030, 3)],
)

sample2_xtea = Config(
    "sample2_xtea",
    Locations(
        vpc_offset=0x140,
        vsp_offset=0x138,
        locals_offset=0x30,
        internal_offsets=[0x144, 0x150, 0x158],
    ),
    [
        Handler(0xEF, 0x4019DB, 0x401AB6, Handler.DETECT_OPERANDS),
        Handler(0xF7, 0x401AC5, 0x401BA4, Handler.DETECT_OPERANDS),
        Handler(0x34, 0x401BB3, 0x401C7A, Handler.DETECT_OPERANDS),
        Handler(0x29, 0x401C89, 0x401D43, Handler.DETECT_OPERANDS),
        Handler(0xFB, 0x401D52, 0x401E02, Handler.DETECT_OPERANDS),
        Handler(0xB8, 0x401E11, 0x401EBB, Handler.DETECT_OPERANDS),
        Handler(0x6F, 0x401EC6, 0x401EF4, Handler.DETECT_OPERANDS),
        Handler(0xBF, 0x401F03, 0x401FD2, Handler.DETECT_OPERANDS),
        Handler(0x74, 0x401FE1, 0x4020B2, Handler.DETECT_OPERANDS),
        Handler(0xDA, 0x4020BD, 0x402131, Handler.DETECT_OPERANDS),
        Handler(0xE8, 0x40213C, 0x402193, Handler.DETECT_OPERANDS),
        Handler(0x9D, 0x4021A2, 0x402291, Handler.DETECT_OPERANDS),
        Handler(0x5F, 0x4022A0, 0x40236E, Handler.DETECT_OPERANDS),
        Handler(0x71, 0x40237D, 0x40242B, Handler.DETECT_OPERANDS),
        Handler(0x1B, 0x402436, 0x4024AC, Handler.DETECT_OPERANDS),
        Handler(0xB3, 0x4024BB, 0x402585, Handler.DETECT_OPERANDS),
        Handler(0xD1, 0x402594, 0x40262C, Handler.DETECT_OPERANDS),
        Handler(0x60, 0x40263B, 0x402705, Handler.DETECT_OPERANDS),
        Handler(0xDC, 0x402710, 0x402789, Handler.DETECT_OPERANDS),
        Handler(0x93, 0x402798, 0x402854, Handler.DETECT_OPERANDS),
        Handler(0xED, 0x40285F, 0x4028C5, Handler.DETECT_OPERANDS),
        Handler(0xF4, 0x4028D4, 0x4028E6, Handler.DETECT_OPERANDS),
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
