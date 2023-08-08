class Locations:
    RBP = 0x7FF0000000

    def __init__(self, vpc_offset: int, vsp_offset: int, locals_offset: int):
        self.vpc = self.RBP - vpc_offset
        self.vsp = self.RBP - vsp_offset
        self.locals = self.RBP - locals_offset
