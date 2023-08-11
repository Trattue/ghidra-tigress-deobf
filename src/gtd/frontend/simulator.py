import angr
import claripy
from gtd.config import Config
from gtd.config.handler import Handler
from gtd.config.locations import Locations
from gtd.frontend.graph import StateGraph
from gtd.frontend.hooks import Hooks


def simulate_vm(path: str, config: Config) -> list[StateGraph]:
    project = angr.Project(path, load_options={"auto_load_libs": False})

    graphs = []
    for handler in config.handlers:
        graphs.append(simulate_handler(project, handler, config))
    return graphs


def simulate_handler(
    project: angr.Project, handler: Handler, config: Config
) -> StateGraph:
    print(f"[+] Simulating handler {hex(handler.opcode)}...")
    vpc = claripy.BVS("vpc", 64)
    hooks = Hooks(config, vpc)
    simulation = create_simulation(project, handler.start, config.locations, hooks, vpc)
    simulation.explore(find=handler.end, num_find=999)

    for error in simulation.errored:
        print(f"[!] ERROR in handler {hex(handler.opcode)}: {error}")

    # Reconstruct operands
    if len(handler.operand_sizes) > 0 and handler.operand_sizes[0] == -1:
        # Sort by offset and create tuple of sizes sorted by index
        operand_sizes = tuple(
            map(lambda op: op[1], sorted(list(hooks.operands), key=lambda op: op[0]))
        )
        handler.set_operand_sizes(operand_sizes)
        if len(operand_sizes) > 0:
            print(f"[*] Found operands: {list(operand_sizes)}")

    graph = StateGraph(handler, config.locations, vpc)
    for solution in simulation.found:
        # Manually call end hook since that's custom
        hooks.end(solution)
        graph.add_solution(solution)
    return graph


def create_simulation(
    project: angr.Project,
    start: int,
    locations: Locations,
    hooks: Hooks,
    vpc: claripy.ast.BV,
) -> angr.sim_manager.SimulationManager:
    state = project.factory.blank_state(
        addr=start,
        add_options={
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            # Create actions for later usage
            angr.options.TRACK_MEMORY_ACTIONS,
            # Don't follow calls
            angr.options.CALLLESS,
        },
        remove_options={angr.options.TRACK_CONSTRAINT_ACTIONS},
    )

    # Set up RBP and registers for less angr issues
    state.regs.rbp = Locations.RBP
    state.mem[locations.vpc].uint64_t = vpc
    state.mem[locations.vsp].uint64_t = claripy.BVS("vsp", 64)

    # Breakpoints for custom SimActions
    state.inspect.b("mem_read", action=hooks.mem_read, when=angr.state_plugins.BP_AFTER)
    state.inspect.b("call", action=hooks.call, when=angr.state_plugins.BP_AFTER)
    state.inspect.b("exit", action=hooks.exit)
    state.inspect.b("fork", action=hooks.fork, when=angr.state_plugins.BP_AFTER)

    return project.factory.simgr(state)
