from typing import Self


class Function:
    """
    Information about a function called in the vm.

    Parameters:
    -----------
    name : str
        Function name.
    address : int
        Address of the function.
    arguments : int
        Number of argument the function has.
    """

    def __init__(self, name: str, address: int, arguments: int):
        self.name = name
        self.address = address
        self.arguments = arguments

    @classmethod
    def parse(cls, function_config) -> Self:
        return cls(
            function_config["name"],
            function_config["address"],
            function_config["argument_count"],
        )
