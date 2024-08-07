import argparse
import logging
import re
import subprocess
from logging import error, info, warn
from pathlib import Path
from typing import ByteString

import angr
from angr.codenode import BlockNode
from cle import Symbol
from gtd.config import Config
from gtd.config.function import Function
from gtd.config.handler import Handler
from gtd.config.locations import Locations
from networkx.algorithms.shortest_paths import shortest_path
from networkx.classes.reportviews import OutEdgeView
from networkx.exception import NetworkXNoPath

TEST_HELP = "test the entire workflow and perform validation checks"
TEST_TIGRESS_HELP = "Tigress directory"
TEST_INPUT_HELP = "C source file to be obfuscated"
TEST_FUNCS_HELP = "functions in the C source file to be obfuscated"
TEST_SUPEROPS_HELP = "use superorperators during obfuscation"


def main():
    # TODO don't use root logger
    logging.basicConfig(level=logging.INFO, force=True)
    for l in logging.Logger.manager.loggerDict:
        if l != "root":
            logging.getLogger(l).disabled = True

    # Top level parser
    parser = argparse.ArgumentParser()
    parser.set_defaults(func=lambda _: parser.print_usage())
    commands = parser.add_subparsers(title="commands")

    # TODO Clean command?
    # Test command
    test = commands.add_parser("test", help=TEST_HELP)
    test.add_argument("input", help=TEST_INPUT_HELP)
    test.add_argument("functions", nargs="+", help=TEST_FUNCS_HELP)
    test.add_argument(
        "-s", "--superoperators", action="store_true", help=TEST_SUPEROPS_HELP
    )
    test.set_defaults(func=test_command)

    # Dispatch
    args = parser.parse_args()
    args.func(args)


def test_command(args):
    funcs = args.functions
    # obf_output = obfuscate(
    #     Path(args.input),
    #     funcs,
    #     args.superoperators,
    # )
    # binary = compile(obf_output)
    binary = Path("sample.obf.c.out")
    obf_output = Path("sample.obf.c")
    configs = [
        c
        for c in [create_and_validate_config(obf_output, binary, f) for f in funcs]
        if c != None
    ]
    write_config(binary, configs)


TIGRESS_CMD = """cd tigress && export TIGRESS_HOME=$(pwd) && ./tigress \\
    --Environment=x86_64:Linux:Gcc:4.6 \\
    --Transform=Virtualize \\
        --Functions={2} \\
        --VirtualizeDispatch=ifnest \\
    --out={1} {0}"""
TIGRESS_SUPEROPS_CMD = """cd tigress && export TIGRESS_HOME=$(pwd) && ./tigress \\
    --Environment=x86_64:Linux:Gcc:4.6 \\
    --Transform=Virtualize \\
        --Functions={2} \\
        --VirtualizeDispatch=ifnest \\
        --VirtualizeMaxMergeLength=5 --VirtualizeSuperOpsRatio=2.0 \\
    --out={1} {0}"""


def obfuscate(input: Path, funcs: list[str], use_superops: bool) -> Path:
    output = Path(f"{str(input).rsplit('.')[-2]}.obf.c")
    if use_superops:
        subprocess.run(
            TIGRESS_SUPEROPS_CMD.format(
                Path("..").joinpath(input),
                Path("..").joinpath(output),
                ",".join(funcs),
            ),
            shell=True,
        )
    else:
        subprocess.run(
            TIGRESS_CMD.format(
                Path("..").joinpath(input),
                Path("..").joinpath(output),
                ",".join(funcs),
            ),
            shell=True,
        )
    return output


GCC_CMD = "gcc {0} -o {1} -gdwarf-4"


def compile(input: Path) -> Path:
    # subprocess.run("")
    output = Path(f"{input}.out")
    subprocess.run(GCC_CMD.format(input, output), shell=True)
    return output


def create_and_validate_config(src: Path, binary: Path, vm_func) -> Config | None:
    config = create_config(binary, vm_func)
    if config != None:
        validate_config(src, config, vm_func)
    return config


def create_config(binary: Path, vm_func) -> Config | None:
    p = angr.Project(binary, load_options={"auto_load_libs": False})
    sy = p.loader.find_symbol(vm_func)
    if sy is None:
        error(f"VM function {vm_func} not found")
        return None
    vm_name = f"{binary.name.rsplit('.', 3)[0]}_{vm_func}"

    # Create CFG of VM function
    s: Symbol = sy
    region_start = s.rebased_addr
    region_end = region_start + s.size - 1
    regions = [(region_start, region_end)]
    cfg = p.analyses.CFGFast(regions=regions, start_at_entry=False)
    vm_func = cfg.kb.functions.get_by_addr(region_start)

    # Step 1: Finding the interpreter loop
    iloop = find_interpreter_loop(vm_func.transition_graph.edges)
    default_end = iloop.addr

    # Step 2: Finding end of handlers
    handlers = find_handlers(vm_func, iloop, default_end)

    # Step 3: Process functions
    functions = find_functions(vm_func)

    # Step 4: TODO
    locations = Locations(0, 0, 0, [])  # TODO
    return Config(vm_name, 0, 0, locations, handlers, functions)  # TODO


def find_interpreter_loop(edges: OutEdgeView[BlockNode]) -> BlockNode:
    # At the end of each handler is a jmp <interpreter_loop>. Thus, the interpreter loop
    # has a lot of incoming edges... We assume the basic block with the most incoming
    # edges is the interpreter loop.
    in_edges: dict[BlockNode, int] = dict()
    for e in edges:
        if in_edges.get(e[1]) == None:
            in_edges[e[1]] = 1
        else:
            in_edges[e[1]] += 1

    iloop = next(reversed(sorted(in_edges.items(), key=lambda item: item[1])))
    info(f"interpreter loop likely at {hex(iloop[0].addr)} ({iloop[1]} incoming edges)")
    return iloop[0]


def find_functions(
    vm_func: angr.knowledge_plugins.functions.function.Function,
) -> list[Function]:
    funcs = []
    for func in vm_func.functions_reachable():
        funcs.append(Function(func.name, func.addr, func.num_arguments))
    return funcs


def find_handlers(
    vm_func: angr.knowledge_plugins.functions.function.Function,
    iloop: BlockNode,
    default_end: int,
) -> list[Handler]:
    # Create a set of blocks at the end of handlers (leading to interpreter loop or the
    # function end)
    handler_end_addrs = set()
    handler_end_blocks: set[tuple[BlockNode, bool]] = set()
    for block in iloop.predecessors():
        if block.addr + block.size not in handler_end_addrs:
            handler_end_addrs.add(block.addr + block.size)
            handler_end_blocks.add((block, False))  # is not return
    for block in vm_func.endpoints:
        if block.addr + block.size not in handler_end_addrs:
            handler_end_addrs.add(block.addr + block.size)
            handler_end_blocks.add((block, True))  # is return

    # Create list of paths from interpreter loop to handler ends
    paths: list[tuple[list[BlockNode], bool]] = []
    for block, ret in handler_end_blocks:
        try:
            paths.append((shortest_path(vm_func.transition_graph, iloop, block), ret))
        except NetworkXNoPath:
            # No path
            pass

    handlers = []
    for path, ret in paths:
        opcode = 0
        start = 0
        for block in path[1:]:
            bs = block.bytestr
            if bs == None:
                break
            bs_: ByteString = bs
            if bs_[0] == 0x80:
                # cmp with opcode -> handler condition
                opcode = bs_[3]
            elif bs_[0] == 0x48 and bs_[1] == 0x8B and bs_[2] == 0x85:
                # mov rax, vpc -> handler start
                start = block.addr
                end = path[-1].addr + path[-1].size
                if opcode == 0:
                    # first handler has no seperate condition block, handle it here
                    # TODO is there a better way?
                    pre_code = block.predecessors()[0].bytestr
                    if pre_code[-2] == 0x75 and pre_code[-6] == 0x80:
                        opcode = pre_code[-3]
                    elif (
                        pre_code[-6] == 0x0F
                        and pre_code[-5] == 0x85
                        and pre_code[-10] == 0x80
                    ):
                        opcode = pre_code[-7]
                    else:
                        warn(f"first handler opcode not found in {vm_func}")
                if not ret:
                    end = default_end
                handlers.append(Handler(opcode, start, end, Handler.DETECT_OPERANDS))
                break
    return handlers


def write_config(binary: Path, configs: list[Config]) -> Path:
    output = Path(f"{binary}.toml")
    with open(output, "w+") as file:
        file.writelines(f'binary_path = "{binary}"\n')
        for config in configs:
            count = len(config.vm_name) + 4
            file.writelines(f"\n{'#' * count}\n")
            file.writelines(f"# {config.vm_name} #\n")
            file.writelines(f"{'#' * count}\n\n")
            file.writelines(config.unparse())
    info("wrote config file")
    return output


def validate_config(src_path: Path, config: Config, vm_func: str):
    with open(src_path, "r") as src:
        found = set(map(lambda h: h.opcode, config.handlers))
        expected: set[int] = set()
        for line in src:
            if line.strip() == f"enum _1_{vm_func}_$op {{":
                break
        for line in src:
            x = re.search(f"\\s*_1_{vm_func}__.*= (\\d+).*", line)
            if x == None:
                break
            expected.add(int(x.group(1)))
        if found.issubset(expected) and expected.issubset(found):
            info("all handlers found")
            info(f"found: {sorted(found)}")
            info(f"exprected: {sorted(expected)}")

        else:
            info("handler detection not correct")
            info(f"found: {sorted(found)}")
            info(f"exprected: {sorted(expected)}")
