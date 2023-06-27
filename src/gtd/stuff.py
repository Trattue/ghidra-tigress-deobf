import angr
import claripy

import gtd.sim_actions
import gtd.sleigh.translation
from gtd.handler import Handler


def do_stuff(path, handlers):
    project = angr.Project(path, load_options={"auto_load_libs": False})
    for handler in handlers:
        visit_handler(project, handler)


def visit_handler(project: angr.Project, handler: Handler):
    print(f"\n# Handler {hex(handler.opcode)}")
    simulation = create_simulation(project, handler.start_addr)
    simulation.explore(find=handler.end_addr, num_find=999)
    for err in simulation.errored:
        print(f"ERROR: {err}")
    for i, sol in enumerate(simulation.found):
        print(f"## Solution {i}")
        visit_solution(sol)


RBP_ADDRESS = 0x7FF0000000
VPC_ADDRESS = RBP_ADDRESS - 0x140
VSP_ADDRESS = RBP_ADDRESS - 0x138


def create_simulation(
    project: angr.Project, start_addr: int
) -> angr.sim_manager.SimulationManager:
    state = project.factory.blank_state(
        addr=start_addr,
        add_options={
            angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
            angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            # Actions
            angr.options.TRACK_MEMORY_ACTIONS,
            # Don't follow calls
            angr.options.CALLLESS,
        },
        remove_options={angr.options.TRACK_CONSTRAINT_ACTIONS},
    )

    # Set up RBP for less angr issues and VM data
    state.regs.rbp = RBP_ADDRESS
    state.mem[VPC_ADDRESS].uint64_t = claripy.BVS("vpc", 64)
    state.mem[VSP_ADDRESS].uint64_t = claripy.BVS("vsp", 64)

    state.inspect.b("call", action=hook_call)
    state.inspect.b("exit", action=hook_exit)
    state.inspect.b("fork", action=hook_fork, when=angr.state_plugins.BP_AFTER)
    # state.inspect.b(
    #    "address_concretization",
    #    action=hook_address_concretization,
    #    when=angr.state_plugins.BP_AFTER,
    # )

    return project.factory.simgr(state)


def hook_call(state):
    function_address = state.solver.eval_one(state.inspect.function_address)
    a = gtd.sim_actions.SimActionCall(state, function_address)
    state.history.add_action(a)


def hook_exit(state):
    target = state.inspect.exit_target
    guard = state.inspect.exit_guard
    a = gtd.sim_actions.SimActionJump(state, target, guard)
    state.history.add_action(a)


def hook_fork(state):
    a = gtd.sim_actions.SimActionFork(state)
    state.history.add_action(a)
    succs = state.inspect.sim_successors.successors
    for s in succs:
        s.history.add_action(a)


def hook_address_concretization(state):
    print("ARGH")
    print(f"{state.inspect.address_concretization_expr}")
    print(f"{state.inspect.address_concretization_result}")


def visit_solution(solution):
    actions = solution.history.actions.hardcopy
    for a in actions:
        match type(a):
            case angr.state_plugins.SimActionData:
                if a.action == "write":
                    target = a.addr.to_claripy()
                    data = a.data.to_claripy()
                    print(gtd.sleigh.translation.translate_write(target, data))
                elif a.action == "read":
                    # TODO investigate what happens when address is symbolic (for example index) -- somehow create new symbolic variable? can't do that in read bp, only change name of bvs
                    source = a.addr.to_claripy()
                    data = a.data.to_claripy()
                    # print(gtd.sleigh.translation.convert_read(data, source))
            case gtd.sim_actions.SimActionCall:
                print(gtd.sleigh.translation.translate_call(a.target))
            case gtd.sim_actions.SimActionJump:
                print(gtd.sleigh.translation.translate_jump(a.target, a.guard))
            case gtd.sim_actions.SimActionFork:
                print("FORK")
            case _:
                pass
