import argparse
import logging
from logging import debug, error, info
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


def pre_main():
    logging.basicConfig(level=logging.INFO, force=True)
    p = argparse.ArgumentParser()
    p.add_argument("binary")
    p.add_argument("vm_func")
    p.add_argument("test", nargs="?")
    args = p.parse_args()

    binary = Path(args.binary)
    config = create_config(binary, args.vm_func)
    if config == None:
        return
    config_name = f"{binary.name.rsplit('.', 1)[0]}.toml"
    with open(config_name, "w+") as file:
        file.writelines(config.unparse())
        info(f"Wrote config file to {config_name}")


def create_config(binary: Path, vm_func) -> Config | None:
    p = angr.Project(binary, load_options={"auto_load_libs": False})
    sy = p.loader.find_symbol(vm_func)
    if sy is None:
        error(f"VM function {vm_func} not found")
        return None
    vm_name = f"{binary.name.rsplit('.', 1)[0]}_{vm_func}"

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
                    opcode = block.predecessors()[0].bytestr[-3]
                if not ret:
                    end = default_end
                handlers.append(Handler(opcode, start, end, Handler.DETECT_OPERANDS))
                break
    return handlers
