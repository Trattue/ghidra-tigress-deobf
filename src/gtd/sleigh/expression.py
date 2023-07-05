class SleighExpr:
    """
    An expression translated to p-code.

    Attributes:
    -----------
    expression : str
        P-code string containing the translated expression. Empty by default.
    context : list[str]
        List of p-code strings needed before the expression. For
        example, helper variables used in the experssion can be defined
        here. Empty by default.
    """

    def __init__(self):
        self.expression: str = ""
        self.context: list[str] = []

    def __str__(self) -> str:
        return "\n".join(self.context + [self.expression])
