import argparse
import tomllib

from gtd.backend.codegen import Codegen
from gtd.backend.plugin import generate_plugin
from gtd.config import Config
from gtd.config.function import Function
from gtd.config.handler import Handler
from gtd.config.locations import Locations
from gtd.frontend.simulator import simulate_vm


def main():
    p = argparse.ArgumentParser()
    p.add_argument("config_path", help="Path to the VM config")
    args = p.parse_args()
    run_with_config(args.config_path)


def run_with_config(config_path: str):
    with open(config_path, mode="rb") as file:
        toml_config = tomllib.load(file)
        binary_path: str = toml_config["binary_path"]
        for vm in toml_config["virtual_machines"]:
            config = parse_vm_config(vm)
            graphs = simulate_vm(binary_path, config)
            slaspec = Codegen(config).codegen_vm(graphs)
            generate_plugin(config.vm_name, slaspec)
    print("Done.")


def parse_vm_config(vm_config) -> Config:
    name = vm_config["name"]
    default_end: int = vm_config["default_end"]
    locations = parse_locations_config(vm_config["locations"])
    handlers = parse_handlers_config(vm_config["handlers"], default_end)
    functions = parse_functions_config(vm_config["functions"])
    return Config(name, locations, handlers, functions)


def parse_locations_config(locations_config) -> Locations:
    return Locations(
        vpc_offset=locations_config["vpc_offset"],
        vsp_offset=locations_config["vsp_offset"],
        locals_offset=locations_config["locals_offset"],
        internal_offsets=locations_config["internal_offsets"],
    )


def parse_handlers_config(handlers_config, default_end: int) -> list[Handler]:
    result = []
    for handler in handlers_config:
        opcode: int = handler["opcode"]
        start: int = handler["start"]
        end: int = default_end
        if "end" in handler:
            end = handler["end"]
        detect_operands: bool = handler["detect_operands"]
        if detect_operands:
            result.append(Handler(opcode, start, end, Handler.DETECT_OPERANDS))
        else:
            operands: list[int] = handler["operands"]
            result.append(Handler(opcode, start, end, *operands))
    return result


def parse_functions_config(functions_config) -> list[Function]:
    result = []
    for fun in functions_config:
        result.append(Function(fun["name"], fun["address"], fun["argument_count"]))
    return result
