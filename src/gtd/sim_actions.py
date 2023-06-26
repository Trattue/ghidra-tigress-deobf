import angr
import claripy


class SimActionCall(angr.state_plugins.SimAction):
    target: int

    def __init__(self, state, target):
        super().__init__(state, "tmp")
        self.target = target


class SimActionJump(angr.state_plugins.SimAction):
    target: int
    guard: claripy.ast.bool.Bool

    def __init__(self, state, target, guard):
        super().__init__(state, "tmp")
        self.target = target
        self.guard = guard


class SimActionFork(angr.state_plugins.SimAction):
    def __init__(self, state):
        super().__init__(state, "tmp")
