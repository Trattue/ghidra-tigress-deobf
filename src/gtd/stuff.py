import angr
import claripy

import gtd.sim_actions
import gtd.sleigh.translation
from gtd.handler import Handler
from gtd.sleigh.expression import SleighExpr
from gtd.state.jump import StateJump
from gtd.state.state import State
from gtd.state.tree import StateTree


def do_stuff(path, handlers):
    project = angr.Project(path, load_options={"auto_load_libs": False})
    for handler in handlers:
        visit_handler(project, handler)


def visit_handler(project: angr.Project, handler: Handler):
    global fork_id, read_expr_count

    # Clean up globals
    fork_id = 0
    read_expr_count = 0

    simulation = create_simulation(project, handler.start_addr)
    simulation.explore(find=handler.end_addr, num_find=999)

    for err in simulation.errored:
        print(f"ERROR in handler {hex(handler.opcode)}: {err}")

    state_tree = StateTree()
    for sol in simulation.found:
        a = gtd.sim_actions.SimActionEnd(sol, fork_id)
        sol.history.add_action(a)
        fork_id += 1
        visit_solution(sol, state_tree, handler)

    hex_opcode = hex(handler.opcode)
    if handler.has_argument:
        print(f"\n:vm_{hex_opcode} imm32 is op={hex_opcode}; imm32 {{")
    else:
        print(f"\n:vm_{hex_opcode} is op={hex_opcode} {{")
    print(state_tree)
    print("}")


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


def visit_solution(solution, state_tree, handler):
    actions = solution.history.actions.hardcopy

    state_expressions = []
    state_jump = None

    last_state_id = 0
    last_state_jump = None

    # TODO: xtea 0x1f: check for addition of multiple jumps to the same state and multiple same states

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
                    result = gtd.sleigh.translation.translate_read(data, address)
                    if result != None:
                        state_expressions.append(result)
            case gtd.sim_actions.SimActionCall:
                # Same deal as reads and writes, simply append it to the expression
                # buffer.
                # We have to keep the calling convention in mind, though. In our case,
                # the return address is pushed to the stack... Since we don't actually
                # follow calls, it serves no use and we need to remove it. That push
                # _should_ be the last expression before the call, so let's remove that.
                state_expressions.pop(-1)
                result = gtd.sleigh.translation.translate_call(action.target)
                state_expressions.append(result)
            case gtd.sim_actions.SimActionJump:
                # Whenever there is a condition that is not trivially true, angr will
                # fork the current state. Therefore, we can safely ignore any jumps
                # apart from the last jump before the fork. This means we can overwrite
                # the stored jump until we encounter a fork.
                # TODO should be correct, but discuss with Fabian
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
                if state_tree.states.get(action.id) == None:
                    state = State(action.id, state_expressions)
                    state_tree.states[action.id] = state
                state_expressions = []
                state_jump = None
            case gtd.sim_actions.SimActionEnd:
                # Same thing as with the fork, except this is just an indicator for a
                # leaf in the state tree.
                # Since no other fork occurs afterwards, we can safely ignore all jumps
                # (except the jump of the last state). Since sleigh code is executed
                # sequentially, we need to add a jump to an end state though.
                end = SleighExpr()
                # TODO make this whole thing actually good code :vomit:
                opcode_size = 5 if handler.has_argument else 1
                tmp = claripy.simplify(
                    # TODO: fix ugly vpc hack
                    solution.mem[VPC_ADDRESS].uint64_t.resolved
                    - opcode_size
                )
                if (
                    isinstance(tmp, claripy.ast.bv.BV)
                    and tmp.op == "BVS"
                    and tmp.args[0].startswith("vpc")
                ):
                    # TODO end label might get unused...
                    end.expression = "VSP = vsp;\ngoto <end>;"
                else:
                    end.expression = "goto [vpc];"
                state_expressions.append(end)
                if state_tree.states.get(action.id) == None:
                    state = State(action.id, state_expressions)
                    state_tree.states[action.id] = state
                if last_state_jump != None:
                    jump = StateJump(action.id, last_state_jump)
                    state_tree.states[last_state_id].jumps.append(jump)
                    last_state_jump = None
