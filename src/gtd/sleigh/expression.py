class SleighExpr:
    """An expression translated to p-code."""

    context: list[str]
    expr: str

    def __init__(self):
        self.context = []
        self.expr = ""

    def __str__(self) -> str:
        result = ""
        for h in self.context:
            result = result + h + "\n"
        result = result + self.expr
        return result
