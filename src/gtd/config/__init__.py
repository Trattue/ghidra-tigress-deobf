from typing import Self

from gtd.config.function import Function
from gtd.config.handler import Handler
from gtd.config.locations import Locations


class Config:
    def __init__(
        self,
        vm_name: str,
        bytecode_start: int,
        bytecode_end: int,
        locations: Locations,
        handlers: list[Handler],
        functions: list[Function] = [],
    ):
        self.vm_name = vm_name
        self.bytecode_start = bytecode_start
        self.bytecode_end = bytecode_end
        self.locations = locations
        self.handlers = handlers
        self.functions = functions

    @classmethod
    def parse(cls, vm_config) -> Self:
        name = vm_config["name"]
        default_end: int = vm_config["default_end"]
        bytecode_start = vm_config["bytecode_start"]
        bytecode_end = vm_config["bytecode_end"]
        locations = Locations.parse(vm_config["locations"])
        handlers = []
        for handler_config in vm_config["handlers"]:
            handlers.append(Handler.parse(handler_config, default_end))
        functions = []
        for function_config in vm_config["functions"]:
            functions.append(Function.parse(function_config))
        return cls(name, bytecode_start, bytecode_end, locations, handlers, functions)

    def unparse(self) -> str:
        result = (
            "[[virtual_machines]]\n"
            f'name = "{self.vm_name}"\n'
            f"bytecode_start = {hex(self.bytecode_start)}\n"
            f"bytecode_end = {hex(self.bytecode_end)}\n\n"
        )
        result += self.locations.unparse()
        result += "\n"
        result += "\n".join(map(lambda h: h.unparse(), self.handlers))
        result += "\n"
        result += "\n".join(map(lambda f: f.unparse(), self.functions))
        return result
