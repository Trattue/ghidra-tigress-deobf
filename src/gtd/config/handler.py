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
        Operand sizes in bytes.
    """

    def __init__(self, opcode: int, start: int, end: int, *operand_sizes: int):
        """Create a handler."""
        self.opcode = opcode
        self.start = start
        self.end = end
        self.operand_sizes = operand_sizes
