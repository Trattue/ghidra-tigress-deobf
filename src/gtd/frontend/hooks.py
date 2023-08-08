import claripy
from gtd.config import Config
from gtd.frontend.sim_actions import (
    SimActionCall,
    SimActionEnd,
    SimActionFork,
    SimActionJump,
)


class Hooks:
    def __init__(self, config: Config):
        self.config = config
        self.__read_expr_count = 0
        self.__fork_id = 0

    def mem_read(self, state):
        length = state.inspect.mem_read_length
        origin = state.inspect.mem_read_address

        # Do not track reads of vpc or vsp
        if (
            origin.op != "BVS"
            and origin.concrete
            and (
                origin.args[0] == 0x7FF0000000 - 0x140
                or origin.args[0] == 0x7FF0000000 - 0x138
            )
        ):
            return

        state.inspect.mem_read_expr = claripy.BVS(
            f"read_{self.__read_expr_count}", length * 8
        )
        self.__read_expr_count += 1

    def call(self, state):
        # TODO symbolic function address?
        function_address = state.solver.eval_one(state.inspect.function_address)

        functions = self.config.functions
        func = list(filter(lambda f: f.address == function_address, functions))[0]
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
