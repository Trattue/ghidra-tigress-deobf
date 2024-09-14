import argparse
import logging
import os
import re
import subprocess
from collections import defaultdict
from itertools import dropwhile, islice
from logging import debug, error, info, warning
from pathlib import Path
from typing import TextIO, Callable

import angr
from angr import Project
from angr.analyses.cfg import CFGBase
from angr.block import Block
from angr.codenode import BlockNode
from angr.knowledge_plugins.cfg import CFGNode
from angr.knowledge_plugins.functions.function import Function as AngrFunction
from cle import Symbol
from networkx.algorithms.shortest_paths import shortest_path
from networkx.classes.reportviews import OutEdgeView
from networkx.exception import NetworkXNoPath

from gtd.config import Config
from gtd.config.function import Function
from gtd.config.handler import Handler
from gtd.config.locations import Locations

VALIDATE_HELP = "test the preprocessing workflow and perform validation checks"
VALIDATE_INPUT_HELP = "C source file to be obfuscated"
VALIDATE_FUNCS_HELP = "functions in the C source file to be obfuscated"
VALIDATE_SUPEROPS_HELP = "use super operators during obfuscation"
VALIDATE_VERBOSE_HELP = "print debug messages"


def main() -> None:
    # TODO don't use root logger
    logging.basicConfig(level=logging.INFO, force=True)
    for l in logging.Logger.manager.loggerDict:
        if l != "root":
            logging.getLogger(l).disabled = True

    # Top level parser
    parser = argparse.ArgumentParser()
    parser.set_defaults(func=parser.print_usage)
    commands = parser.add_subparsers(title="commands")

    # TODO Clean command?
    __create_command_preprocess(commands)
    __create_command_validate(commands)

    # Dispatch
    args = parser.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, force=True)
    args.func(args)


def __create_command_validate(commands) -> None:
    validate = commands.add_parser("validate", help=VALIDATE_HELP)
    validate.add_argument("input", help=VALIDATE_INPUT_HELP)
    validate.add_argument("functions", nargs="+", help=VALIDATE_FUNCS_HELP)
    validate.add_argument(
        "-s", "--super-operators", action="store_true", help=VALIDATE_SUPEROPS_HELP
    )
    validate.add_argument(
        "-v", "--verbose", action="store_true", help=VALIDATE_VERBOSE_HELP
    )
    validate.set_defaults(func=__command_validate)


def __command_validate(args) -> None:
    functions = args.functions
    source = Path(args.input)
    obfuscated_source, obfuscated_binary = __prepare_samples(
        source, functions, args.super_operators
    )
    configs = __create_and_validate_configs(
        obfuscated_source, obfuscated_binary, functions
    )
    successful_configs = list(filter(None, configs))
    __write_config(obfuscated_binary, successful_configs)


PREPROCESS_HELP = "run the preprocessing workflow"
PREPROCESS_INPUT_HELP = "obfuscated C binary"
PREPROCESS_FUNCS_HELP = "functions in the C source file to be obfuscated"
PREPROCESS_VERBOSE_HELP = "print debug messages"

# TODO double check
def __create_command_preprocess(commands) -> None:
    preprocess = commands.add_parser("preprocess", help=PREPROCESS_HELP)
    preprocess.add_argument("input", help=PREPROCESS_INPUT_HELP)
    preprocess.add_argument("functions", nargs="+", help=PREPROCESS_FUNCS_HELP)
    preprocess.add_argument(
        "-v", "--verbose", action="store_true", help=PREPROCESS_VERBOSE_HELP
    )
    preprocess.set_defaults(func=__command_preprocess)


def __command_preprocess(args) -> None:
    obfuscated_binary = Path(args.input)
    configs = [__create_config(obfuscated_binary, f) for f in args.functions]
    successful_configs = list(filter(None, configs))
    __write_config(obfuscated_binary, successful_configs)


def __prepare_samples(
    source: Path, functions: list[str], super_operators: bool
) -> (Path, Path):
    obfuscated_source = __obfuscate(source, functions, super_operators)
    obfuscated_binary = __compile(obfuscated_source)
    return obfuscated_source, obfuscated_binary


def __obfuscate(source: Path, functions: list[str], super_operators: bool) -> Path:
    # For a file named something.c, we want the something part
    name = str(source).rsplit(".")[-2]
    output = Path(f"{name}.{'sobf' if super_operators else 'obf'}.c")
    env = dict(os.environ)
    env["TIGRESS_HOME"] = Path("./tigress/").absolute().as_posix()

    if super_operators:
        tigress_command = [
            "./tigress",
            "--Environment=x86_64:Linux:Gcc:4.6",
            "--Seed=42",
            "--Transform=Virtualize",
            f"--Functions={','.join(functions)}",
            "--VirtualizeDispatch=ifnest",
            "--VirtualizeMaxMergeLength=5",
            "--VirtualizeSuperOpsRatio=2.0",
            f"--out={Path('..').joinpath(output)}",
            f"{Path('..').joinpath(source)}",
        ]
        subprocess.run(
            tigress_command,
            env=env,
            cwd="tigress",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    else:
        tigress_command = [
            "./tigress",
            "--Environment=x86_64:Linux:Gcc:4.6",
            "--Seed=42",
            "--Transform=Virtualize",
            f"--Functions={','.join(functions)}",
            "--VirtualizeDispatch=ifnest",
            f"--out={Path('..').joinpath(output)}",
            f"{Path('..').joinpath(source)}",
        ]
        subprocess.run(
            tigress_command,
            env=env,
            cwd="tigress",
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    info(f"Obfuscated {source} to {output}!")
    return output


def __compile(obfuscated_source: Path) -> Path:
    output = Path(f"{obfuscated_source}.out")
    gcc_command = [
        "gcc",
        obfuscated_source.as_posix(),
        "-o",
        output.as_posix(),
        "-gdwarf-4",
    ]
    subprocess.run(
        gcc_command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    info(f"Compiled {obfuscated_source} to {output}!")
    return output


def __create_and_validate_configs(
    obfuscated_source: Path, binary: Path, vm_functions: list[str]
) -> list[Config]:
    return [
        __create_and_validate_config(obfuscated_source, binary, f) for f in vm_functions
    ]


def __create_and_validate_config(
    obfuscated_source: Path, binary: Path, vm_function: str
) -> Config | None:
    info(f"Preprocessing {vm_function}...")
    config = __create_config(binary, vm_function)
    if config is not None:
        __validate_opcodes(obfuscated_source, config, vm_function)
    return config


def __create_config(binary: Path, vm_function_name: str) -> Config | None:
    p: Project = Project(binary, load_options={"auto_load_libs": False})
    vm_function_symbol = p.loader.find_symbol(vm_function_name)
    if vm_function_symbol is None:
        error(f"VM function {vm_function_name} not found")
        return None
    cfg = __create_cfg(p, vm_function_symbol)
    vm_function = cfg.kb.functions.get_by_addr(vm_function_symbol.rebased_addr)

    binary_name = binary.name.rsplit(".c")[0].replace(".", "_").replace("-", "_")
    vm_name = f"{binary_name}_{vm_function_name}"
    handlers = find_handlers(cfg, vm_function)
    locations = __find_locations(cfg, handlers)
    functions = __find_functions(vm_function)

    return Config(vm_name, 0, 0, locations, handlers, functions)  # TODO


def __create_cfg(project: Project, function: Symbol) -> CFGBase:
    region_start = function.rebased_addr
    region_end = region_start + function.size - 1
    regions = [(region_start, region_end)]
    return project.analyses.CFGFast(regions=regions, start_at_entry=False)


def find_handlers(cfg: CFGBase, vm_func: AngrFunction) -> list[Handler]:
    interpreter_loop = __find_interpreter_loop(vm_func.transition_graph.edges)
    default_end = interpreter_loop.addr
    handler_ends = __handler_ends(interpreter_loop, vm_func)
    handler_paths = __handler_paths(interpreter_loop, vm_func, handler_ends)

    handler_starts = set()
    handlers = []
    for path, ret in handler_paths:
        opcode = 0

        # skip interpreter loop and iterate over nodes
        for node in path[1:]:
            block = cfg.get_any_node(node.addr).block
            if block is None:
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
                    # subtract leave; ret size from end
                    end = path[-1].addr + path[-1].size - 2
                else:
                    end = default_end
                if opcode == 0:
                    # First handler has no separate condition block, handle it here
                    pre_insns: list[angr.block.DisassemblerBlock] = cfg.get_any_node(
                        node.predecessors()[0].addr
                    ).block.disassembly.insns

                    # Again, cmp with opcode -> handler condition
                    if pre_insns[-2].mnemonic == "cmp":
                        opcode = int(
                            pre_insns[-2].op_str.lower().split(",")[-1], base=0
                        )
                    else:
                        warning(f"First handler opcode not found in {vm_func}")
                if not start in handler_starts:
                    handlers.append(
                        Handler(opcode, start, end, ret, Handler.DETECT_OPERANDS)
                    )
                    handler_starts.add(start)
                break
    info(f"Found {len(handlers)} handlers")
    return handlers


def __find_interpreter_loop(edges: OutEdgeView[BlockNode]) -> BlockNode:
    in_edges: defaultdict[BlockNode, int] = defaultdict(int)
    for edge in edges:
        in_edges[edge[1]] += 1

    # At the end of each handler is a jmp <interpreter_loop>. Thus, the interpreter loop
    # has a lot of incoming edges... We assume the basic block with the most incoming
    # edges is the interpreter loop.
    interpreter_loop, in_count = sorted(
        in_edges.items(), key=lambda i: i[1], reverse=True
    )[0]
    info(
        f"Interpreter loop at {hex(interpreter_loop.addr)} ({in_count} incoming edges)"
    )
    return interpreter_loop


def __handler_ends(
    interpreter_loop: BlockNode, vm_func: AngrFunction
) -> set[tuple[BlockNode, bool]]:
    handler_ends: dict[int, tuple[BlockNode, bool]] = {}
    # Create a set of blocks at the end of handlers leading to interpreter loop
    for node in interpreter_loop.predecessors():
        end = node.addr + node.size
        if end not in handler_ends:
            handler_ends[end] = (node, False)  # is not return
    # Create a set of blocks at the end of handlers leading to the function end
    for node in vm_func.endpoints:
        end = node.addr + node.size
        if end not in handler_ends:
            handler_ends[end] = (node, True)  # is return
    return set(handler_ends.values())


def __handler_paths(
    interpreter_loop: BlockNode,
    vm_func: AngrFunction,
    handler_ends: set[tuple[BlockNode, bool]],
) -> list[tuple[list[BlockNode], bool]]:
    paths: list[tuple[list[BlockNode], bool]] = []
    for node, ret in handler_ends:
        try:
            # Create path from interpreter loop to handler end
            path = shortest_path(vm_func.transition_graph, interpreter_loop, node)
            paths.append((path, ret))
        except NetworkXNoPath:
            # No path
            pass
    return paths


def __find_functions(vm_func: AngrFunction) -> list[Function]:
    functions = []
    for function in vm_func.functions_reachable():
        functions.append(Function(function.name, function.addr, function.num_arguments))
    return functions


def __find_locations(cfg: CFGBase, handlers: list[Handler]) -> Locations:
    offsets = __rbp_offsets(cfg)
    vpc = __find_vpc(cfg, handlers)
    vsp = __find_vsp(offsets, vpc)
    debug(__pretty_print_offsets(offsets, vpc, vsp))

    # We don't know the locals or internal offsets, use placeholder values
    return Locations(vpc, vsp, 0, [])


def __rbp_offsets(cfg: CFGBase) -> dict[int, int]:
    offsets: defaultdict[int, int] = defaultdict(int)
    node: CFGNode
    for node in cfg.nodes():
        __add_block_rbp_offsets(offsets, node.block)
    return offsets


def __add_block_rbp_offsets(offsets: defaultdict[int, int], block: Block) -> None:
    operands = map(lambda i: i.op_str.lower(), block.disassembly.insns)
    rbp_operands = filter(lambda o: "rbp" in o, operands)
    operand: str
    for operand in rbp_operands:
        for offset in re.findall(f"\[rbp - (\\w+)\]", operand):
            offsets[int(offset, base=0)] += 1


def __find_vpc(cfg: CFGBase, handlers: list[Handler]) -> int | None:
    if not handlers:
        return None
    handler = handlers[0]
    instructions = cfg.get_any_node(handler.start).block.disassembly.insns
    # Handler start should be mov rax, vpc; add rax, 1
    if (
        instructions[0].mnemonic.lower() == "mov"
        and instructions[0].op_str.lower().split(",")[0] == "rax"
        and instructions[1].mnemonic.lower() == "add"
        and instructions[1].op_str.lower().split(",")[0] == "rax"
    ):
        # Check for the RBP offset in the mov rax, vpc instruction. If this doesn't work
        # something is seriously wrong as our assumptions don't hold, so no error
        # handling
        rbp_access = instructions[0].op_str.lower().split(",")[1]
        # TODO: check if '\]' is redundant character escape
        match = re.search(f"\[rbp - (\\w+)\]", rbp_access)
        vpc = int(match.group(1), base=0)
        info(f"Found VPC offset: {hex(vpc)}")
        return vpc


def __find_vsp(rbp_offset_counts: dict[int, int], vpc: int) -> int:
    # Assume most common offset apart from VPC is VSP
    so = list(sorted(rbp_offset_counts, key=rbp_offset_counts.get, reverse=True))
    so.remove(vpc)
    vsp = so[0]
    info(f"Found VSP offset: {hex(vsp)}")
    return vsp


def __pretty_print_offsets(
    rbp_offset_counts: dict[int, int], vpc: int, vsp: int
) -> str:
    sorted_offsets = sorted(rbp_offset_counts, reverse=True)
    msg = "Stack accesses relative to RBP:"
    for o in sorted_offsets:
        msg += f"\n{hex(o)}: {rbp_offset_counts[o]}"
        if o == vpc:
            msg += " <- likely VPC"
        elif o == vsp:
            msg += " <- likely VSP"
    return msg


def __write_config(binary: Path, configs: list[Config]) -> Path:
    config_path = Path(f"{binary}.toml")
    with open(config_path, "w+") as config_file:
        __write_binary_path(config_file, binary)
        __write_vm_configs(config_file, configs)
    info("Wrote config file!")
    return config_path


def __write_binary_path(file: TextIO, binary: Path) -> None:
    file.writelines(f'binary_path = "{binary}"\n')


def __write_vm_configs(file: TextIO, configs: list[Config]) -> None:
    for config in configs:
        __write_vm_config(file, config)


def __write_vm_config(file: TextIO, config: Config) -> None:
    # VM config separator
    count = len(config.vm_name) + 4
    file.writelines(f"\n{'#' * count}\n")
    file.writelines(f"# {config.vm_name} #\n")
    file.writelines(f"{'#' * count}\n\n")

    # VM config
    file.writelines(config.unparse())


def __validate_opcodes(obfuscated_source: Path, config: Config, vm_func: str) -> None:
    with open(obfuscated_source, "r") as obfuscated_source_file:
        __validate_opcodes_(config, obfuscated_source_file, vm_func)


def __validate_opcodes_(
    config: Config, obfuscated_source: TextIO, vm_func: str
) -> None:
    found: set[int] = __found_opcodes(config)
    expected: set[int] = __expected_opcodes(obfuscated_source, vm_func)
    if found == expected:
        info(f"Validation: All handlers found!")
    else:
        error("Validation: Handler detection not correct")
    debug(f"Found: {sorted(found)}")
    debug(f"Expected: {sorted(expected)}")


def __found_opcodes(config: Config) -> set[int]:
    return set(map(lambda h: h.opcode, config.handlers))


def __expected_opcodes(obfuscated_source: TextIO, vm_func: str) -> set[int]:
    expected: set[int] = set()
    for line in islice(
        dropwhile(__not_opcode_enum_start(vm_func), obfuscated_source), 1, None
    ):
        # The regex we look for describes the assignment of a number to an enum value
        # (the opcode) in the obfuscated file
        match = re.search(f"\\s*_1_{vm_func}__.*= (\\d+).*", line)
        if match is None:
            break
        expected.add(int(match.group(1), base=10))
    return expected


def __not_opcode_enum_start(vm_func: str) -> Callable[[str], bool]:
    return lambda l: l.strip() != f"enum _1_{vm_func}_$op {{"
