import math

import claripy
from gtd.config.handler import Handler
import gtd.frontend.statement
from gtd.backend.expression import CodeGenExpr
from gtd.config import Config
from gtd.frontend.graph import StateGraph
from gtd.frontend.state import State


class Codegen:
    def __init__(self, config: Config):
        self.config = config
        self.__concat_tmp_count = 0
        self.__concat_result_count = 0
        self.__if_result_count = 0
        self.__if_label_count = 0
        self.__extract_count = 0
        self.__zext_count = 0
        self.__sext_count = 0

    def codegen_vm(self, graphs: list[StateGraph]):
        print("\nSleigh code for VM below:")
        print("=========================\n")

        # Generate different operand sizes (only those that are atually used by the
        # handlers)
        sizes: set[int] = set()
        operands: dict[int, set[int]] = {}
        for handler in self.config.handlers:
            for (index, size) in handler.operands.values():
                sizes.add(size)
                if size not in operands:
                    operands[size] = set()
                operands[size].add(index)
        for size in sizes:
            bits = size * 8
            print(f"define token I{bits}({bits})")
            for index in operands[size]:
                print(f"    imm{index}_{bits}=(0,{bits - 1})")
            print(";")

        # Codegen handlers/graphs
        for graph in graphs:
            self._codegen_graph(graph)

    def _codegen_graph(self, graph: StateGraph):
        # Reset counters
        self.__concat_tmp_count = 0
        self.__concat_result_count = 0
        self.__if_result_count = 0
        self.__if_label_count = 0
        self.__extract_count = 0
        self.__zext_count = 0
        self.__sext_count = 0

        # Structure definition
        hex_opcode = hex(graph.handler.opcode)
        if len(graph.handler.operand_sizes) == 0:
            print(f"\n:vm_{hex_opcode} is op={hex_opcode} {{")
        else:
            # TODO: think how to do this in ghidra
            structure = f"\n:vm_{hex_opcode}"
            for i, operand_size in enumerate(graph.handler.operand_sizes):
                if i != 0:
                    structure += ","
                structure += f" imm{i}_{operand_size * 8}"
            structure += f" is op={hex_opcode}"
            for i, operand_size in enumerate(graph.handler.operand_sizes):
                structure += f"; imm{i}_{operand_size * 8}"
            structure += " {"
            print(structure)

        # Codegen states
        for state in graph.__iter__():
            self._codegen_state(state, graph.handler, graph.vpc)

        # End
        print("}")

    def _codegen_state(self, state: State, handler: Handler, vpc: claripy.ast.BV):
        match state.id:
            case StateGraph.END_GOTO_VPC_ID:
                print(f"<end_goto_vpc>")
                print("VSP = vsp;")
                print("goto [vpc];")
            case StateGraph.END_REGULAR_ID:
                print(f"<end_regular>")
                print(f"VSP = vsp;")
            case StateGraph.START_ID:
                # No label to print since the first label is not used
                print("local vpc:8 = inst_start;")
                print("local vsp:8 = VSP;")
            case _:
                print(f"<state_{state.id}>")

        for statement in state.statements:
            self._codegen_statement(statement, handler, vpc)

        for target, condition in state.jumps.items():
            target_name = ""
            if target == StateGraph.END_GOTO_VPC_ID:
                target_name = "end_goto_vpc"
            elif target == StateGraph.END_REGULAR_ID:
                target_name = "end_regular"
            else:
                target_name = f"state_{target}"

            if condition == None:
                print(f"goto <{target_name}>;")
            else:
                if_side = f"if {self._codegen_bool(condition)} "
                goto_side = f"goto <{target_name}>;"
                print(if_side + goto_side)

    def _codegen_statement(self, stmt, handler: Handler, vpc: claripy.ast.BV):
        match type(stmt):
            case gtd.frontend.statement.WriteStatement:
                result = CodeGenExpr()
                # Special case: On the left side, we need to replace the addresses, at
                # which vpc and vsp are, with the actual registers.
                # We can translate the target and use its context in either way since in
                # our special case there is no context. Maybe some day I will seperate
                # the cases more clearly...
                target = self._codegen_expression(stmt.target)
                result.context.extend(target.context)
                left_side = f"*{target.expression} = "
                if stmt.target.concrete:
                    if stmt.target.args[0] == self.config.locations.vpc:
                        left_side = f"vpc = "
                    elif stmt.target.args[0] == self.config.locations.vsp:
                        left_side = f"vsp = "

                data = self._codegen_expression(stmt.data)
                result.context.extend(data.context)
                right_side = f"{data.expression};"

                result.expression = left_side + right_side
                print(result)
            case gtd.frontend.statement.ReadStatement:
                # We ignore reads at vpc and vsp as in sleigh code the registers can
                # simply be used.
                if stmt.origin.concrete and (
                    stmt.origin.args[0] == self.config.locations.vpc
                    or stmt.origin.args[0] == self.config.locations.vsp
                ):
                    return

                result = CodeGenExpr()

                length = math.ceil(stmt.data.length / 8)
                left_side = f"local {stmt.data.args[0]}:{length} = "

                origin = self._codegen_expression(stmt.origin)
                result.context.extend(origin.context)
                right_side = f"*({origin.expression});"

                # Argument support. We check if origin is at an offset to vpc; if that
                # is the case, it likely is an operand. To filter out data accesses
                # relative to vpc that are not arguments, we limit the offset to 420 bytes.
                sym_offset = claripy.simplify(stmt.origin - vpc)
                if (
                    sym_offset.op != "BVS"
                    and sym_offset.concrete
                    and sym_offset.args[0] <= 420
                ):
                    offset = sym_offset.args[0]
                    operand = handler.operands[offset]
                    operand_size = operand[1] * 8

                    # Sanity check: Is the size defined correctly?
                    if operand_size != stmt.data.length:
                        print(
                            f"[!] ERROR: operand with offset {offset} is defined as {operand_size}bit, but is {stmt.data.length}bit"
                        )
                        exit(1)

                    right_side = f"imm{operand[0]}_{operand_size};"

                result.expression = left_side + right_side
                print(result)
            case gtd.frontend.statement.CallStatement:
                result = CodeGenExpr()
                for i, arg in enumerate(stmt.arguments):
                    expr = self._codegen_expression(arg)
                    result.context.extend(expr.context)
                    result.context.append(f"param{i + 1} = {expr.expression};")
                result.expression = f"call {hex(stmt.target)};"
                print(result)

    def _codegen_expression(self, expression) -> CodeGenExpr:
        match type(expression):
            case claripy.ast.bool.Bool:
                return self._codegen_bool(expression)
            case claripy.ast.bv.BV:
                return self._codegen_bv(expression)
            case _:
                result = CodeGenExpr()
                result.expression = f"[NOT IMPLEMENTED: {type(expression)}]"
                return result

    def _codegen_bool(self, expression) -> CodeGenExpr:
        result = CodeGenExpr()
        match expression.op:
            case "BoolV":
                result.expression = "1" if expression.args[0] else "0"
            case "__eq__":
                arg0 = self._codegen_expression(expression.args[0])
                arg1 = self._codegen_expression(expression.args[1])
                result.context.extend(arg0.context)
                result.context.extend(arg1.context)
                result.expression = f"({arg0.expression}) == ({arg1.expression})"
            case "__ne__":
                arg0 = self._codegen_expression(expression.args[0])
                arg1 = self._codegen_expression(expression.args[1])
                result.context.extend(arg0.context)
                result.context.extend(arg1.context)
                result.expression = f"({arg0.expression}) != ({arg1.expression})"
            case "__lt__":
                arg0 = self._codegen_expression(expression.args[0])
                arg1 = self._codegen_expression(expression.args[1])
                result.context.extend(arg0.context)
                result.context.extend(arg1.context)
                result.expression = f"({arg0.expression}) < ({arg1.expression})"
            case "SLT":
                arg0 = self._codegen_expression(expression.args[0])
                arg1 = self._codegen_expression(expression.args[1])
                result.context.extend(arg0.context)
                result.context.extend(arg1.context)
                result.expression = f"({arg0.expression}) s< ({arg1.expression})"
            case "SLE":
                arg0 = self._codegen_expression(expression.args[0])
                arg1 = self._codegen_expression(expression.args[1])
                result.context.extend(arg0.context)
                result.context.extend(arg1.context)
                result.expression = f"({arg0.expression}) s<= ({arg1.expression})"
            case "SGT":
                arg0 = self._codegen_expression(expression.args[0])
                arg1 = self._codegen_expression(expression.args[1])
                result.context.extend(arg0.context)
                result.context.extend(arg1.context)
                result.expression = f"({arg0.expression}) s> ({arg1.expression})"
            case _:
                result.expression = f"[NOT IMPLEMENTED BOOL: {expression.op}]"
        return result

    def _codegen_bv(self, expr) -> CodeGenExpr:
        match expr.op:
            case "BVV":
                result = CodeGenExpr()
                c = expr.args[0]
                locals_address = self.config.locations.locals
                if c == locals_address:
                    result.expression = "locals"
                elif c == 0x7FF0000000 - 0x144:
                    # fib only
                    # TODO: config option for vm arguments
                    result.expression = f"internal1"
                elif (
                    c & 0x7FFFFFFFFF == c
                    and c & 0xFFFFFFFF != c
                    and c != self.config.locations.vpc
                    and c != self.config.locations.vsp
                ):
                    result.expression = f"locals + {hex(c - locals_address)}"
                else:
                    result.expression = (
                        f"{hex(expr.args[0])}:{math.ceil(expr.length / 8)}"
                    )
                return result
            case "BVS":
                result = CodeGenExpr()
                name = expr.args[0]
                if name.startswith("vsp"):
                    result.expression = "VSP"
                elif name.startswith("vpc"):
                    result.expression = "inst_start"
                else:
                    result.expression = f"{expr.args[0]}"
                return result
            case "__add__":
                return self.__codegen_multop(expr, " + ")
            case "__sub__":
                return self.__codegen_multop(expr, " - ")
            case "__mul__":
                return self.__codegen_multop(expr, " * ")
            case "__and__":
                return self.__codegen_multop(expr, " & ")
            case "__xor__":
                return self.__codegen_multop(expr, " ^ ")
            case "__lshift__":
                return self.__codegen_binop(expr, " << ")
            case "LShR":
                return self.__codegen_binop(expr, " >> ")
            case "ZeroExt":
                result = CodeGenExpr()
                translated = self._codegen_expression(expr.args[1])
                result.context.extend(translated.context)
                result.context.append(
                    f"local zext_{self.__zext_count}:{math.ceil(expr.length / 8)} = zext({translated.expression});"
                )
                result.expression = f"zext_{self.__zext_count}"
                self.__zext_count += 1
                return result
            case "SignExt":
                result = CodeGenExpr()
                translated = self._codegen_expression(expr.args[1])
                result.context.extend(translated.context)
                result.context.append(
                    f"local sext_{self.__sext_count}:{math.ceil(expr.length / 8)} = sext({translated.expression});"
                )
                result.expression = f"sext_{self.__sext_count}"
                self.__sext_count += 1
                return result
            case "Extract":
                result = CodeGenExpr()
                translated = self._codegen_expression(expr.args[2])
                result.context.extend(translated.context)

                result.context.append(
                    f"local extract_{self.__extract_count}:{math.ceil(expr.args[2].length / 8)} = {translated.expression};"
                )
                least_significant_bit = expr.args[1]
                bit_count = expr.args[0] - least_significant_bit
                result.expression = f"extract_{self.__extract_count}[{least_significant_bit},{bit_count}]"
                self.__extract_count += 1
                return result
            case "Concat":
                # Since p-code does not have an instruction for concatenation, we have to
                # implement it manually.
                #
                # We have given:
                # * The bit vectors to be concatenated
                # * Their lengths (possibly not divisable by word size 8)
                # * The total length of the concatenated expression (should be dividable
                #   by word size 8)
                #
                # The general idea is to create local variables for each value to be
                # concatenated and bit-shift it so the bits are at the correct position.
                # Then we can simply logically or those values.
                result = CodeGenExpr()
                translated_exprs = list(
                    map(lambda e: self._codegen_expression(e), expr.args)
                )

                for e in translated_exprs:
                    result.context.extend(e.context)

                # Concat value shifts
                shift = expr.length
                tmp_used = []
                for i, e in enumerate(expr.args):
                    shift -= e.length

                    # Sleigh wants value to be shifted to have the same size as the
                    # shifted value... That's why we use zext(), that should
                    # semantically be the same
                    size = math.ceil(expr.length / 8)
                    left = f"local concat_tmp_{self.__concat_tmp_count}:{size}"
                    right = f"zext({translated_exprs[i].expression}) << {shift};"
                    result.context.append(left + " = " + right)
                    tmp_used.append(self.__concat_tmp_count)
                    self.__concat_tmp_count += 1

                # Actual concat
                concat_result = f"local concat_result_{self.__concat_result_count}:{math.ceil(expr.length / 8)} = "
                concat_result += " | ".join(map(lambda t: f"concat_tmp_{t}", tmp_used))
                concat_result += ";"
                self.__concat_result_count += 1
                result.context.append(concat_result)
                result.expression = f"concat_result_{self.__concat_result_count - 1}"
                return result
            case "If":
                # Since p-code does not have a mechanism for ternaries (or even
                # if-else-constructs apart from conditional jumps), we have to manually
                # implement it.
                #
                # To do that, we use a local variable for the ternary value and
                # conditional jumps to set the value.
                result = CodeGenExpr()

                # Condition
                cond = self._codegen_expression(expr.args[0])
                result.context.extend(cond.context)
                result.context.append(
                    f"local if_result_{self.__if_result_count}:{math.ceil(expr.length / 8)} = 0;"
                )
                result.context.append(
                    f"if ({cond.expression}) goto <if_label_{self.__if_label_count}>;"
                )

                # Branch 2
                branch2 = self._codegen_expression(expr.args[2])
                result.context.extend(branch2.context)
                result.context.append(
                    f"if_result_{self.__if_result_count} = {branch2.expression};"
                )
                result.context.append(f"goto <if_label_{self.__if_label_count + 1}>;")

                # Branch 1
                result.context.append(f"<if_label_{self.__if_label_count}>")
                branch1 = self._codegen_expression(expr.args[1])
                result.context.extend(branch1.context)
                result.context.append(
                    f"if_result_{self.__if_result_count} = {branch1.expression};"
                )

                # End
                result.context.append(f"<if_label_{self.__if_label_count + 1}>")
                result.expression = f"if_result_{self.__if_result_count}"
                self.__if_result_count += 1
                self.__if_label_count += 2
                return result
            case _:
                result = CodeGenExpr()
                result.expression = f"[NOT IMPLEMENTED BV: {expr.op}]"
                return result

    def __codegen_multop(self, expr, op: str) -> CodeGenExpr:
        result = CodeGenExpr()
        translated = list(map(lambda e: self._codegen_expression(e), expr.args))
        for t in translated:
            result.context.extend(t.context)
        expressions = list(map(lambda e: e.expression, translated))
        result.expression = f"({op.join(expressions)})"
        return result

    def __codegen_binop(self, expr, op: str) -> CodeGenExpr:
        result = CodeGenExpr()
        arg0 = self._codegen_expression(expr.args[0])
        arg1 = self._codegen_expression(expr.args[1])
        result.context.extend(arg0.context)
        result.context.extend(arg1.context)
        result.expression = f"{arg0.expression}{op}{arg1.expression}"
        return result
