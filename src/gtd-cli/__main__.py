import argparse
import logging
import re
import subprocess
from logging import debug, error, info, warn
from pathlib import Path

import angr
from angr.block import Block
from angr.codenode import BlockNode
from angr.knowledge_plugins.cfg import CFGNode
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
TEST_VERBOSE_HELP = "print debug messages"


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
    test.add_argument("-v", "--verbose", action="store_true", help=TEST_VERBOSE_HELP)
    test.set_defaults(func=test_command)

    # Dispatch
    args = parser.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, force=True)
    args.func(args)


def test_command(args):
    funcs = args.functions
    obf_output = obfuscate(
        Path(args.input),
        funcs,
        args.superoperators,
    )
    binary = compile(obf_output)
    configs = [
        c
        for c in [create_and_validate_config(obf_output, binary, f) for f in funcs]
        if c != None
    ]
    write_config(binary, configs)


TIGRESS_CMD = """cd tigress && export TIGRESS_HOME=$(pwd) && ./tigress \\
    --Environment=x86_64:Linux:Gcc:4.6 --Seed=42 \\
    --Transform=Virtualize \\
        --Functions={2} \\
        --VirtualizeDispatch=ifnest \\
    --out={1} {0}"""
TIGRESS_SUPEROPS_CMD = """cd tigress && export TIGRESS_HOME=$(pwd) && ./tigress \\
    --Environment=x86_64:Linux:Gcc:4.6 --Seed=42 \\
    --Transform=Virtualize \\
        --Functions={2} \\
        --VirtualizeDispatch=ifnest \\
        --VirtualizeMaxMergeLength=5 --VirtualizeSuperOpsRatio=2.0 \\
    --out={1} {0}"""


def obfuscate(input: Path, funcs: list[str], use_superops: bool) -> Path:
    output = Path(f"{str(input).rsplit('.')[-2]}.{'sobf' if use_superops else 'obf'}.c")
    if use_superops:
        subprocess.run(
            TIGRESS_SUPEROPS_CMD.format(
                Path("..").joinpath(input),
                Path("..").joinpath(output),
                ",".join(funcs),
            ),
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        subprocess.run(
            TIGRESS_CMD.format(
                Path("..").joinpath(input),
                Path("..").joinpath(output),
                ",".join(funcs),
            ),
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    info(f"Obfuscated {input} to {output}!")
    return output


GCC_CMD = "gcc {0} -o {1} -gdwarf-4"


def compile(input: Path) -> Path:
    output = Path(f"{input}.out")
    subprocess.run(
        GCC_CMD.format(input, output),
        shell=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    info(f"Compiled {input} to {output}!")
    return output


def create_and_validate_config(src: Path, binary: Path, vm_func) -> Config | None:
    info(f"Analysing {vm_func}...")
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
    vm_name = f"{binary.name.rsplit('.c')[0].replace(".", "_").replace("-", "_")}_{vm_func}"

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

    # Step 2: Finding stert of handlers
    handlers = find_handlers(cfg, vm_func, iloop, default_end)

    # Step 3: Process functions
    functions = find_functions(vm_func)

    # Step 4: TODO
    locations = find_locations(cfg, handlers)

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
    info(f"Interpreter loop likely at {hex(iloop[0].addr)} ({iloop[1]} incoming edges)")
    return iloop[0]


def find_handlers(
    cfg: angr.analyses.cfg.cfg_base.CFGBase,
    vm_func: angr.knowledge_plugins.functions.function.Function,
    iloop: BlockNode,
    default_end: int,
) -> list[Handler]:
    # Create a set of blocks at the end of handlers (leading to interpreter loop or the
    # function end)
    handler_end_addrs = set()
    handler_end_blocks: set[tuple[BlockNode, bool]] = set()
    for node in iloop.predecessors():
        if node.addr + node.size not in handler_end_addrs:
            handler_end_addrs.add(node.addr + node.size)
            handler_end_blocks.add((node, False))  # is not return
    for node in vm_func.endpoints:
        if node.addr + node.size not in handler_end_addrs:
            handler_end_addrs.add(node.addr + node.size)
            handler_end_blocks.add((node, True))  # is return

    # Create list of paths from interpreter loop to handler ends
    paths: list[tuple[list[BlockNode], bool]] = []
    for node, ret in handler_end_blocks:
        try:
            paths.append((shortest_path(vm_func.transition_graph, iloop, node), ret))
        except NetworkXNoPath:
            # No path
            pass

    handler_starts = set()
    handlers = []
    for path, ret in paths:
        opcode = 0
        start = 0

        # skip interpreter loop and iterate over nodes
        for node in path[1:]:
            block = cfg.get_any_node(node.addr).block
            if block == None:
                break
            insns: list[angr.block.DisassemblerBlock] = block.disassembly.insns

            if insns[0].mnemonic == "cmp":
                # cmp with opcode -> handler condition
                opcode = int(insns[0].op_str.lower().split(",")[-1], base=0)
            elif (
                insns[0].mnemonic == "mov"
                and insns[0].op_str.lower().split(",")[0] == "rax"
            ):
                # mov rax, vpc -> handler start
                start = node.addr
                if ret:
                    # we assume the last basic block contains leave; ret at the and
                    # substract leave; ret size from end
                    end = path[-1].addr + path[-1].size - 2
                else:
                    end = default_end
                if opcode == 0:
                    # First handler has no seperate condition block, handle it here
                    pre_insns: list[angr.block.DisassemblerBlock] = cfg.get_any_node(
                        node.predecessors()[0].addr
                    ).block.disassembly.insns

                    # Again, cmp with opcode -> handler condition
                    if pre_insns[-2].mnemonic == "cmp":
                        opcode = int(
                            pre_insns[-2].op_str.lower().split(",")[-1], base=0
                        )
                    else:
                        warn(f"First handler opcode not found in {vm_func}")
                if not start in handler_starts:
                    handlers.append(Handler(opcode, start, end, Handler.DETECT_OPERANDS))
                    handler_starts.add(start)
                break
    info(f"Found {len(handlers)} handlers")
    return handlers


def find_functions(
    vm_func: angr.knowledge_plugins.functions.function.Function,
) -> list[Function]:
    funcs = []
    for func in vm_func.functions_reachable():
        funcs.append(Function(func.name, func.addr, func.num_arguments))
    return funcs


def find_locations(cfg: angr.analyses.cfg.cfg_base.CFGBase, handlers: list[Handler]):
    vpc = 0

    for h in handlers:
        insns = cfg.get_any_node(h.start).block.disassembly.insns
        # Handler start should be mov rax, vpc; add rax, 1
        if (
            insns[0].mnemonic.lower() == "mov"
            and insns[0].op_str.lower().split(",")[0] == "rax"
            and insns[1].mnemonic.lower() == "add"
            and insns[1].op_str.lower().split(",")[0] == "rax"
        ):
            x = insns[0].op_str.lower().split(",")[1]
            vpc = int(re.search(f"\[rbp - (\\w+)\]", x).group(1), base=0)
            info(f"Found VPC offset: {hex(vpc)}")
            break

    offsets: dict[int, int] = {}
    for n in cfg.nodes():
        n: CFGNode = n
        b: Block = n.block
        for i in b.disassembly.insns:
            if "rbp" in i.op_str.lower():
                for o in re.findall(f"\[rbp - (\\w+)\]", i.op_str.lower()):
                    o = int(o, base=0)
                    if o in offsets:
                        offsets[o] += 1
                    else:
                        offsets[o] = 1
    sorted_offsets = sorted(offsets, reverse=True)

    # Assume most common offset apart from VPC is VSP
    so = list(sorted(offsets, key=offsets.get, reverse=True))
    so.remove(vpc)
    vsp = so[0]
    info(f"Found VSP offset: {hex(vsp)}")

    msg = "Stack accesses relative to RBP:"
    for o in sorted_offsets:
        msg += f"\n{hex(o)}: {offsets[o]}"
        if o == vpc:
            msg += " <- likely VPC"
        elif o == vsp:
            msg += " <- likely VSP"
    debug(msg)

    return Locations(vpc, vsp, 0, [])


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
    info("Wrote config file!")
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
            info(f"Validation: All handlers found!")
        else:
            error("Validation: Handler detection not correct")
        debug(f"Found: {sorted(found)}")
        debug(f"Exprected: {sorted(expected)}")
