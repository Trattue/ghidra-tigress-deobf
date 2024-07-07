from typing import Self

from gtd.config.function import Function
from gtd.config.handler import Handler
from gtd.config.locations import Locations


class Config:
    def __init__(
        self,
        vm_name: str,
        locations: Locations,
        handlers: list[Handler],
        functions: list[Function] = [],
    ):
        self.vm_name = vm_name
        self.locations = locations
        self.handlers = handlers
        self.functions = functions

    @classmethod
    def parse(cls, vm_config) -> Self:
        name = vm_config["name"]
        default_end: int = vm_config["default_end"]
        locations = Locations.parse(vm_config["locations"])
        handlers = []
        for handler_config in vm_config["handlers"]:
            handlers.append(Handler.parse(handler_config, default_end))
        functions = []
        for function_config in vm_config["functions"]:
            functions.append(Function.parse(function_config))
        return cls(name, locations, handlers, functions)
