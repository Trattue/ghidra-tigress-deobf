from gtd.sleigh.expression import SleighExpr
from gtd.state.jump import StateJump


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
    expressions : list[SleighExpr]
        The expressions executed in this state.

    Attributes:
    -----------
    jumps : dict[int, StateJump]
        Jumps to other states. Key is the target state id.
    """

    def __init__(self, id: int, expressions: list[SleighExpr]):
        self.id = id
        self.expressions = expressions
        self.jumps: dict[int, StateJump] = {}

    def __str__(self) -> str:
        initial_label = ""
        if self.id != 0:
            initial_label += f"<state_{self.id}>\n"
        expressions = list(map(lambda se: f"{se}", self.expressions))
        jumps = list(map(lambda se: f"{se}", self.jumps.values()))
        return initial_label + "\n".join(expressions + jumps)
