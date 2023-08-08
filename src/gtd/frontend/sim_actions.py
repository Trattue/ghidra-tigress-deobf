import angr
import claripy


class SimActionCall(angr.state_plugins.SimAction):
    def __init__(
        self,
        state: angr.sim_state.SimState,
        target: int,
        arguments: list[claripy.ast.bv.BV],
    ):
        super().__init__(state, "tmp")
        self.target = target
        self.state = state
        self.arguments = arguments


class SimActionJump(angr.state_plugins.SimAction):
    def __init__(
        self, state: angr.sim_state.SimState, target: int, guard: claripy.ast.bool.Bool
    ):
        super().__init__(state, "tmp")
        self.target = target
        self.guard = guard


class SimActionFork(angr.state_plugins.SimAction):
    def __init__(self, state: angr.sim_state.SimState, id: int):
        super().__init__(state, "tmp")
        self.id = id


class SimActionEnd(SimActionFork):
    def __init__(self, state: angr.sim_state.SimState, id):
        super().__init__(state, id)
