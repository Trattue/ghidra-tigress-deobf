import claripy
from gtd.config import Config
from gtd.frontend.sim_actions import (
    SimActionCall,
    SimActionEnd,
    SimActionFork,
    SimActionJump,
    SimActionJumpTable,
    SimActionJumpTableTarget,
)


class Hooks:
    def __init__(self, config: Config, vpc: claripy.ast.BV):
        self.config = config
        self.vpc = vpc
        self.__read_expr_count = 0
        self.__fork_id = 0
        self.operands: set[tuple[int, int]] = set()
        self.jt_targets: set[int] = set()

    def mem_read(self, state):
        length = state.inspect.mem_read_length
        origin = state.inspect.mem_read_address

        # Do not track reads of vpc or vsp
        if (
            origin.op != "BVS"
            and origin.concrete
            and (
                origin.args[0] == self.config.locations.vpc
                or origin.args[0] == self.config.locations.vsp
            )
        ):
            return

        # TODO fix this :(
        # state.inspect.mem_read_expr = claripy.BVS(
        #    f"read_{self.__read_expr_count}", length * 8
        # )
        left = state.inspect.mem_read_expr
        if not str(left.args[0]).startswith("mem_") and left.op != "If":
            # print(f"{left.op} ~ {left.args}")
            state.inspect.mem_read_expr = claripy.BVS(
                f"read_{self.__read_expr_count}", length * 8
            )
        self.__read_expr_count += 1

        # Arguments
        sym_offset = claripy.simplify(origin - self.vpc)
        if (
            sym_offset.op != "BVS"
            and sym_offset.concrete
            and sym_offset.args[0] <= 420
            and sym_offset.args[0] > 0
        ):
            offset = sym_offset.args[0]
            self.operands.add((offset, length))

    def call(self, state):
        # TODO symbolic function address?
        function_address = state.solver.eval_one(state.inspect.function_address)

        # Figure out how many arguments this function has in the config and create sim
        # action
        functions = list(
            filter(lambda f: f.address == function_address, self.config.functions)
        )
        # Sanity check: function should be in config, else complain and assume no args
        if len(functions) == 0:
            print(f"[!] ERROR in function hook: {hex(function_address)} not in config")
            a = SimActionCall(state, function_address, [])
            state.history.add_action(a)
            return

        func = functions[0]
        remaining = func.arguments
        cc = [
            state.regs.rdi,
            state.regs.rsi,
            state.regs.rdx,
            state.regs.rcx,
            state.regs.r8,
            state.regs.r9,
        ]
        arguments = []
        while remaining > 0:
            arguments.append(cc[func.arguments - remaining])
            remaining -= 1
        a = SimActionCall(state, function_address, arguments)
        state.history.add_action(a)

    def exit(self, state):
        target = state.inspect.exit_target
        guard = state.inspect.exit_guard
        a = SimActionJump(state, target, guard)
        if target.op == "If":
            # Switch case special case... angr encodes switch case dispatching in a weird way
            # where the guard is true but the target is an if-expression...
            target = claripy.simplify(target)
            jumps = dict()
            jump_table(target, jumps)
            for addr in jumps:
                self.jt_targets.add(addr)
            a = SimActionJumpTable(state, self.__fork_id, jumps)
            self.__fork_id += 1
        state.history.add_action(a)

    # TODO idea: instead of giving forks an id, create SimActionStart with id?
    def fork(self, state):
        a = SimActionFork(state, self.__fork_id)
        state.history.add_action(a)
        successors = state.inspect.sim_successors.successors
        for successor in successors:
            successor.history.add_action(a)
        self.__fork_id += 1

    def end(self, state):
        a = SimActionEnd(state, self.__fork_id)
        self.__fork_id += 1
        state.history.add_action(a)

    def instruction(self, state):
        insn = state.inspect.instruction
        if insn in self.jt_targets:
            state.history.add_action(SimActionJumpTableTarget(state, insn))


def jump_table(target, jumps: dict[int, claripy.ast.bool.Bool]):
    jumps[target.args[1]._model_concrete.value] = target.args[0]
    if target.args[2].symbolic or target.args[2]._model_concrete.value != 0xC0DEB4BE:
        jump_table(target.args[2], jumps)
