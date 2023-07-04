from gtd.sleigh.expression import SleighExpr
from gtd.state.jump import StateJump


class State:
    id: int
    expressions: list[SleighExpr]
    jumps: list[StateJump]

    def __init__(self, id, expressions):
        self.id = id
        self.expressions = expressions

    def __str__(self) -> str:
        result = f"<state_{id}>:"
        for expression in self.expressions:
            result += f"\n{expression}"
        for jump in self.jumps:
            result += f"\n{jump}"
        return result
