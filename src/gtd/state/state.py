from gtd.sleigh.expression import SleighExpr
from gtd.state.jump import StateJump


class State:
    id: int
    expressions: list[SleighExpr]
    jumps: list[StateJump]

    def __init__(self, id, expressions):
        self.id = id
        self.expressions = expressions
        self.jumps = []

    def __str__(self) -> str:
        result = ""
        if self.id != 0:
            result = f"<state_{self.id}>\n"
        result += "\n".join(map(lambda se: f"{se}", self.expressions))
        if len(self.jumps) > 0:
            result += "\n"
        result += "\n".join(map(lambda se: f"{se}", self.jumps))
        return result
