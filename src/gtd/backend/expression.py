class CodeGenExpr:
    """
    A translated expression.

    Attributes:
    -----------
    expression : str
        String containing the translated expression. Empty by default.
    context : list[str]
        List of statements, represented as strings, needed before the
        expression. As example, helper variables used in the expression
        can be defined here. Empty by default.
    """

    def __init__(self):
        self.expression: str = ""
        self.context: list[str] = []

    def __str__(self) -> str:
        return "\n".join(self.context + [self.expression])
