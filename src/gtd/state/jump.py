from gtd.sleigh.expression import SleighExpr


class StateJump:
    target_id: int
    condition: SleighExpr

    def __init__(self, target_id, condition):
        self.target_id = target_id
        self.condition = condition

    def __str__(self) -> str:
        return f"if ({self.condition}) goto <state_{self.target_id}>;"
