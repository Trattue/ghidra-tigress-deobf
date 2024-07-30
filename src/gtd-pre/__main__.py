from typing import ByteString
import angr
from angr.codenode import BlockNode
from cle import Symbol
from networkx import predecessor
from networkx.algorithms.shortest_paths import has_path, shortest_path
from networkx.algorithms.tournament import is_tournament
from networkx.exception import NetworkXNoPath


def pre_main():
    p = angr.Project("samples/samplea.out", load_options={"auto_load_libs": False})
    sy = p.loader.find_symbol("fib")
    if sy is None:
        return
    s: Symbol = sy
    start = s.rebased_addr
    end = start + s.size - 1
    regions = [(start, end)]
    cfg = p.analyses.CFGFast(regions=regions, start_at_entry=False)
    fib = cfg.kb.functions.get_by_addr(start)
    es = fib.transition_graph.edges

    in_edges: dict[BlockNode, int] = dict()
    for e in es:
        e: tuple[BlockNode, BlockNode] = e
        if in_edges.get(e[1]) == None:
            in_edges[e[1]] = 1
        else:
            in_edges[e[1]] += 1

    # Step 1: Finding the interpreter loop
    # At the end of each handler is a jmp <interpreter_loop>. Thus, the interpreter loop
    # has a lot of incoming edges... We assume the basic block with the most incoming
    # edges is the interpreter loop.
    iloop = next(reversed(sorted(in_edges.items(), key=lambda item: item[1])))
    print(
        f"[+] interpreter loop likely found at {hex(iloop[0].addr)} ({iloop[1]} incoming edges)"
    )

    # Step 2: Finding end of handlers
    # The predecessors of the interpreter loop which are handlers TODO document
    pre_ends = set()
    blocks = set()
    for x in iloop[0].predecessors():
        if x.addr + x.size not in pre_ends:
            pre_ends.add(x.addr + x.size)
            blocks.add((x, False))
    for x in fib.endpoints:
        if x.addr + x.size not in pre_ends:
            pre_ends.add(x.addr + x.size)
            blocks.add((x, True))
    handlers: list[BlockNode] = []
    paths: list[tuple[list[BlockNode], bool]] = []
    for b, v in blocks:
        b: BlockNode = b
        try:
            paths.append((shortest_path(fib.transition_graph, iloop[0], b), v))
        except NetworkXNoPath:
            pass
    paths = sorted(paths, key=len)
    for path, v in paths:
        opcode = 0
        start = 0
        for block in path[1:]:
            bs = block.bytestr
            if bs == None:
                break
            bs_: ByteString = bs
            if bs_[0] == 0x80:
                opcode = bs_[3]
            elif bs_[0] == 0x48 and bs_[1] == 0x8B and bs_[2] == 0x85:
                start = block.addr
                end = path[-1].addr + path[-1].size
                if opcode == 0:
                    # TODO is there a better way?
                    opcode = block.predecessors()[0].bytestr[-3]
                if v:
                    print(f"handler {hex(opcode)} at {hex(start)} to {hex(end)}")
                else:
                    print(f"handler {hex(opcode)} at {hex(start)}")
                break
