class Handler:
    """VM handler data class."""

    opcode: int
    start_addr: int
    end_addr: int

    def __init__(self, opcode: int, start_addr: int, end_addr: int):
        """Create a handler."""
        self.opcode = opcode
        self.start_addr = start_addr
        self.end_addr = end_addr
