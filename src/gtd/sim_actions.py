import angr
import claripy


class SimActionCall(angr.state_plugins.SimAction):
    def __init__(self, state, target: int):
        super().__init__(state, "tmp")
        self.target = target
        self.state = state


class SimActionJump(angr.state_plugins.SimAction):
    def __init__(self, state, target: int, guard: claripy.ast.bool.Bool):
        super().__init__(state, "tmp")
        self.target = target
        self.guard = guard


class SimActionFork(angr.state_plugins.SimAction):
    def __init__(self, state, id: int):
        super().__init__(state, "tmp")
        self.id = id


class SimActionEnd(SimActionFork):
    def __init__(self, state, id):
        super().__init__(state, id)
