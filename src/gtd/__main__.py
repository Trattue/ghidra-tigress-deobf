import argparse
import tomllib

from gtd.backend.codegen import Codegen
from gtd.backend.plugin import generate_plugin
from gtd.config import Config
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
            config = Config.parse(vm)
            graphs = simulate_vm(binary_path, config)
            slaspec = Codegen(config).codegen_vm(graphs)
            generate_plugin(config.vm_name, slaspec)
    print("Done.")
