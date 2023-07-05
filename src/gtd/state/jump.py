from gtd.sleigh.expression import SleighExpr


class StateJump:
    """
    A jump from one state to another.

    Parameters:
    -----------
    target_id : int
        The id of the jump target state.
    condition : SleighExpr
        The condition upon which the jump is executed.
    """

    def __init__(self, target_id: int, condition: SleighExpr):
        self.target_id = target_id
        self.condition = condition

    def __str__(self) -> str:
        return f"if ({self.condition}) goto <state_{self.target_id}>;"
