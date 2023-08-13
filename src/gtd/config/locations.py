class Locations:
    RBP = 0x7FF0000000

    def __init__(
        self,
        vpc_offset: int,
        vsp_offset: int,
        locals_offset: int,
        internal_offsets: list[int] = [],
    ):
        self.vpc = self.RBP - vpc_offset
        self.vsp = self.RBP - vsp_offset
        self.locals = self.RBP - locals_offset
        self.internals = list(map(lambda o: self.RBP - o, internal_offsets))
