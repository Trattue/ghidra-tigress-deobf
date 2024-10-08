from typing import Self


class Handler:
    """
    Information about a VM handler.

    Parameters:
    -----------
    opcode : int
        The opcode of the vm handler.
    start : int
        Start address of the vm handler.
    end : int
        End address of the vm handler (the address of the instruction
        after the last instruction in the handler).
    *operand_sizes : int
        Operand sizes in bytes. If the first element is -1, we will try to automagically
        detect operands by usage in the vm handler.
    """

    DETECT_OPERANDS = -1

    def __init__(
        self, opcode: int, start: int, end: int, ret: bool, *operand_sizes: int
    ):
        """Create a handler."""
        self.opcode = opcode
        self.start = start
        self.end = end
        self.set_operand_sizes(operand_sizes)
        self.ret = ret

    def set_operand_sizes(self, operand_sizes: tuple[int, ...]):
        self.operand_sizes: tuple[int, ...] = operand_sizes
        # Calculate operand offsets from sizes. We assume the opcode is 1 byte and all
        # operands are consecutive in the order passed
        self.operands: dict[int, tuple[int, int]] = {}
        offset = 1
        for i, operand_size in enumerate(operand_sizes):
            self.operands[offset] = (i, operand_size)
            offset += operand_size

    @classmethod
    def parse(cls, handler_config, default_end: int) -> Self:
        opcode: int = handler_config["opcode"]
        start: int = handler_config["start"]
        end: int = default_end
        if "end" in handler_config:
            end = handler_config["end"]
        ret: bool = False
        if "ret" in handler_config:
            ret = handler_config["ret"]
        detect_operands: bool = handler_config["detect_operands"]
        if detect_operands:
            return cls(opcode, start, end, ret, Handler.DETECT_OPERANDS)
        else:
            operands: list[int] = handler_config["operands"]
            return cls(opcode, start, end, ret, *operands)

    def unparse(self, default_end: int) -> str:
        result = (
            f"[[virtual_machines.handlers]]\n"
            f"opcode = {hex(self.opcode)}\n"
            f"start = {hex(self.start)}\n"
        )

        # Don't write default end
        if default_end != self.end:
            result += f"end = {hex(self.end)}\n"

        if self.ret:
            result += f"ret = true\n"

        if (
            len(self.operand_sizes) == 1
            and self.operand_sizes[0] == self.DETECT_OPERANDS
        ):
            result += "detect_operands = true\n"
        else:
            result += "detect_operands = false\noperands = []"
        return result
