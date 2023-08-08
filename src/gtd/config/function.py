class Function:
    """
    Information about a function called in the vm.

    Parameters:
    -----------
    address : int
        Address of the function.
    arguments : int
        Number of argument the function has.
    """

    def __init__(self, address: int, arguments: int):
        self.address = address
        self.arguments = arguments
