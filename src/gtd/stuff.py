import angr
import claripy

import gtd.sim_actions
import gtd.sleigh.translation
from gtd.handler import Handler
from gtd.state.state import State
from gtd.state.tree import StateTree
from gtd.state.jump import StateJump


def do_stuff(path, handlers):
    project = angr.Project(path, load_options={"auto_load_libs": False})
    for handler in handlers:
        visit_handler(project, handler)


def visit_handler(project: angr.Project, handler: Handler):  # Clean up globals
    global fork_id, read_expr_count
    fork_id = 0
    read_expr_count = 0

    print(f"\n# Handler {hex(handler.opcode)}")
    simulation = create_simulation(project, handler.start_addr)
    simulation.explore(find=handler.end_addr, num_find=999)
    for err in simulation.errored:
        print(f"ERROR: {err}")
    for i, sol in enumerate(simulation.found):
        a = gtd.sim_actions.SimActionEnd(sol, fork_id)
        sol.history.add_action(a)
        fork_id += 1
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
    state.inspect.b("mem_read", action=hook_mem_read, when=angr.state_plugins.BP_AFTER)
    # state.inspect.b(
    #     "address_concretization", when=angr.state_plugins.BP_AFTER, action=hook_conc
    # )

    return project.factory.simgr(state)


def hook_conc(state):
    expr = state.inspect.address_concretization_expr
    res = state.inspect.address_concretization_result
    print(f"ARGHH: {expr} -> {res}")


def hook_call(state):
    function_address = state.solver.eval_one(state.inspect.function_address)
    a = gtd.sim_actions.SimActionCall(state, function_address)
    state.history.add_action(a)


def hook_exit(state):
    target = state.inspect.exit_target
    guard = state.inspect.exit_guard
    a = gtd.sim_actions.SimActionJump(state, target, guard)
    state.history.add_action(a)


fork_id = 0


def hook_fork(state):
    global fork_id
    a = gtd.sim_actions.SimActionFork(state, fork_id)
    state.history.add_action(a)
    succs = state.inspect.sim_successors.successors
    for s in succs:
        s.history.add_action(a)
    fork_id += 1


read_expr_count = 0


def hook_mem_read(state):
    global read_expr_count
    length = state.inspect.mem_read_length
    expr = state.inspect.mem_read_expr
    addr = state.inspect.mem_read_address

    if (
        addr.op != "BVS"
        and addr.concrete
        and (
            addr.args[0] == 0x7FF0000000 - 0x140 or addr.args[0] == 0x7FF0000000 - 0x138
        )
    ):
        # TODO: remove ugly hardcode
        return

    state.inspect.mem_read_expr = claripy.BVS(f"read_{read_expr_count}", length * 8)
    read_expr_count += 1


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
                    addr = a.addr.to_claripy()
                    expr = a.data.to_claripy()
                    result = gtd.sleigh.translation.translate_read(expr, addr)
                    if result != None:
                        print(result)
            case gtd.sim_actions.SimActionCall:
                print(gtd.sleigh.translation.translate_call(a.target))
            case gtd.sim_actions.SimActionJump:
                print(gtd.sleigh.translation.translate_jump(a.target, a.guard))
            case gtd.sim_actions.SimActionFork:
                print(f"FORK {a.id}")
            case gtd.sim_actions.SimActionEnd:
                print(f"END {a.id}")
            case _:
                pass


def visit_solution_new(solution, state_tree):
    actions = solution.history.actions.hardcopy

    state_expressions = []
    state_jump = None

    last_state_id = 0
    last_state_jump = None

    for action in actions:
        match type(action):
            case angr.state_plugins.SimActionData:
                # Nothing really special here, we simply add the translated expression
                # to a expression buffer. Once we encounter a fork, we know the state id
                # of the previous expressions and can create a state for them.
                if action.action == "write":
                    address = action.addr.to_claripy()
                    data = action.data.to_claripy()
                    result = gtd.sleigh.translation.translate_write(address, data)
                    state_expressions.append(result)
                elif action.action == "read":
                    address = action.addr.to_claripy()
                    data = action.data.to_claripy()
                    result = gtd.sleigh.translation.translate_write(data, address)
                    if result != None:
                        state_expressions.append(result)
            case gtd.sim_actions.SimActionCall:
                # Same deal as reads and writes, simply append it to the expression
                # buffer.
                result = gtd.sleigh.translation.translate_call(action.target)
                state_expressions.append(result)
            case gtd.sim_actions.SimActionJump:
                # Whenever there is a condition that is not trivially true, angr will
                # fork the current state. Therefore, we can safely ignore any jumps
                # apart from the last jump before the fork. This means we can overwrite
                # the stored jump until we encounter a fork.
                state_jump = gtd.sleigh.translation._translate_bool(action.guard)
            case gtd.sim_actions.SimActionFork:
                # We know that the last jump before a fork is different between
                # execution passes in the same state. We know the jump condition, but we
                # do not yet know the target state id.
                # Since this method goes through one solution, we know that the next
                # state will be the state the jump targets. Therefore, we will save the
                # jump and, in the next state, add it to the previous state with the
                # correct target.
                if last_state_jump != None:
                    jump = StateJump(action.id, last_state_jump)
                    state_tree.states[last_state_id].jumps.append(jump)
                    last_state_jump = None
                last_state_id = action.id
                last_state_jump = state_jump

                # First, we check if there exists a state with the fork id. That would
                # mean we already encountered execution of that state, the only thing
                # different from the previous execution is the jump at the end.
                # If we did not encounter that state before, we have to create a state.
                # After that, we can clear the expressions buffer and the jump.
                if state_tree.states[action.id] == None:
                    state = State(action.id, state_expressions)
                    state_tree.states[action.id] = state
                state_expressions = []
                state_jump = None
            case gtd.sim_actions.SimActionEnd:
                # Same thing as with the fork, except this is just an indicator for a
                # leaf in the state tree.
                # Since no other fork occurs afterwards, we can safely ignore all jumps
                # (except the jump of the last state).
                if state_tree.states[action.id] == None:
                    state = State(action.id, state_expressions)
                    state_tree.states[action.id] = state
                if last_state_jump != None:
                    jump = StateJump(action.id, last_state_jump)
                    state_tree.states[last_state_id].jumps.append(jump)
                    last_state_jump = None
