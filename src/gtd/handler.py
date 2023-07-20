class Handler:
    """VM handler data class."""

    def __init__(
        self, opcode: int, start_addr: int, end_addr: int, has_argument: bool = False
    ):
        """Create a handler."""
        self.opcode = opcode
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.has_argument = has_argument
