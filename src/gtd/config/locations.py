from typing import Self


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

    @classmethod
    def parse(cls, locations_config) -> Self:
        return cls(
            vpc_offset=locations_config["vpc_offset"],
            vsp_offset=locations_config["vsp_offset"],
            locals_offset=locations_config["locals_offset"],
            internal_offsets=locations_config["internal_offsets"],
        )

    def unparse(self) -> str:
        return (
            "[virtual_machines.locations]\n"
            f"vpc_offset = {hex(self.RBP - self.vpc)}\n"
            f"vsp_offset = {hex(self.RBP - self.vsp)}\n"
            f"locals_offset = {hex(self.RBP - self.locals)}\n"
            "internal_offsets = "
            f"[{', '.join(map(lambda i: hex(self.RBP - i), self.internals))}]\n"
        )
