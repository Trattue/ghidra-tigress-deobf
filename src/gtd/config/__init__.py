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
