import claripy
from gtd.frontend.statement import Statement


class State:
    """
    A state in a symbolically executed program.

    When symbolically executing a program, at some point a condition is
    not trivially true. At this point, angr forks the current state into
    multiple states in order to account for all further possible paths.
    This class models those states: It contains a list of expressions
    and the jumps leading to other states.

    Parameters:
    -----------
    id : int
        The unique integer id of the state.

    Attributes:
    -----------
    jumps : dict[int, claripy.ast.Bool | None]
        Jumps to other states. Key is the target state id. Value is the
        condition of the jump or None if the jump is unconditional.
    predecessors : list[int]
        List of predecessor state ids.
    """

    def __init__(self, id: int) -> None:
        self.id = id
        self.jumps: dict[int, claripy.ast.Bool | None] = {}
        self.predecessors: set[int] = set()
        self.statements: list[Statement] = []
