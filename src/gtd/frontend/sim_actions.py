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

    def _desc(self):
        return f"{self.type}/call: {hex(self.target)}"


class SimActionJump(angr.state_plugins.SimAction):
    def __init__(
        self, state: angr.sim_state.SimState, target, guard: claripy.ast.bool.Bool
    ):
        super().__init__(state, "tmp")
        self.target = target
        self.guard = guard

    def _desc(self):
        return f"{self.type}/jump: if {self.guard} goto {self.target}"


class SimActionJumpTable(angr.state_plugins.SimAction):
    def __init__(
        self,
        state: angr.sim_state.SimState,
        id: int,
        jumps: dict[int, claripy.ast.bool.Bool],
    ):
        super().__init__(state, "tmp")
        self.jumps = jumps
        self.id = id

    def _desc(self):
        return f"{self.type}/jump_table"


class SimActionJumpTableTarget(angr.state_plugins.SimAction):
    def __init__(
        self,
        state: angr.sim_state.SimState,
        addr: int,
    ):
        super().__init__(state, "tmp")
        self.addr = addr

    def _desc(self):
        return f"{self.type}/jump_table_target: {self.addr}"


class SimActionFork(angr.state_plugins.SimAction):
    def __init__(self, state: angr.sim_state.SimState, id: int):
        super().__init__(state, "tmp")
        self.id = id

    def _desc(self):
        return f"{self.type}/fork: {self.id}"


class SimActionEnd(SimActionFork):
    def __init__(self, state: angr.sim_state.SimState, id):
        super().__init__(state, id)

    def _desc(self):
        return f"{self.type}/end: {self.id}"
