import claripy


class Statement:
    pass


class WriteStatement(Statement):
    def __init__(self, target, data):
        super().__init__()
        self.target = target
        self.data = data


class ReadStatement(Statement):
    def __init__(self, data, origin):
        super().__init__()
        self.data = data
        self.origin = origin


class CallStatement(Statement):
    def __init__(self, target: int, arguments: list[claripy.ast.bv.BV]):
        super().__init__()
        self.target = target
        self.arguments = arguments


class RetStatement(Statement):
    def __init__(self, value: claripy.ast.bv.BV) -> None:
        super().__init__()
        self.value = value
