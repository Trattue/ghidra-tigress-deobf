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

    def __init__(self, opcode: int, start: int, end: int, *operand_sizes: int):
        """Create a handler."""
        self.opcode = opcode
        self.start = start
        self.end = end
        self.set_operand_sizes(operand_sizes)

    def set_operand_sizes(self, operand_sizes: tuple[int, ...]):
        self.operand_sizes: tuple[int, ...] = operand_sizes
        # Calculate operand offsets from sizes. We assume the opcode is 1 byte and all
        # operands are consecutive in the order passed
        self.operands: dict[int, tuple[int, int]] = {}
        offset = 1
        for i, operand_size in enumerate(operand_sizes):
            self.operands[offset] = (i, operand_size)
            offset += operand_size
