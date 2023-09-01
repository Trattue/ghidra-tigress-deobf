# ghidra-tigress-deobf

Requires [poetry](https://python-poetry.org/) installed
([installation guide](https://python-poetry.org/docs/)). 

After cloning, run `poetry install`.

Usage: `poetry run main <path_to_config>`

## Config

Example:

```toml
# Path relative to the project root directory
binary_path = "samples/sample1.out"

[[virtual_machines]]
name = "sample1-foobar"

# Offsets to RBP during handler execution
# We omit the minus sign, in this example vpc is at RBP-0x160 ;)
[virtual_machines.locations]
vpc_offset = 0x160
vsp_offset = 0x158
locals_offset = 0x50
internal_offsets = [0x164]

# Array of handlers: 
[[virtual_machines.handlers]]
opcode = 0x1
# Handler start: first instruction in the handler
start = 0x4011ba
# Handler end: first instruction after the handler (e.g. jmp <interpreter_loop>)
end = 0x401211
detect_operands = true

[[virtual_machines.handlers]]
opcode = 0x2
start = 0x123123
end = 0x123456
detect_operands = false
# Since detect_operands is false, we need to provide a list of operand sizes
operands = [4, 8]

[...]

[[virtual_machines.functions]]
address = 0x401030
argument_count = 3

[[virtual_machines]]
name = "sample1-xtea"
# No functions, so we can define an empty array here
functions = []

[...]
```

## Development
### Code Style

Using black formatter (88 line length); 72 line length for docstrings (normal
comments length like code).
