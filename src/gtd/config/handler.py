class Handler:
    """VM handler data class."""

    def __init__(
        self, opcode: int, start_addr: int, end_addr: int, argument_size: int = 0
    ):
        """Create a handler."""
        self.opcode = opcode
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.argument_size = argument_size
