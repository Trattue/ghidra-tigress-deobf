import math

import claripy


class TranslatedExpr:
    expr: str
    helpers: list[str]

    def __init__(self):
        self.expr = ""
        self.helpers = []

    def __str__(self) -> str:
        result = ""
        for h in self.helpers:
            result = result + h + "\n"
        result = result + self.expr
        return result


def convert_jump(target, guard) -> TranslatedExpr:
    # TODO: simplify if(1)?
    # TODO: handle jumps properly with labels (in state tree?)
    result = TranslatedExpr()
    translated_target = convert(target)
    translated_guard = convert(guard)
    result.helpers.extend(translated_target.helpers)
    result.helpers.extend(translated_guard.helpers)
    result.expr = f"if ({translated_guard.expr}) goto {translated_target.expr};"
    return result


def convert_write(target, data):
    # TODO: handle target assignment properly (addr vs variables) (do we even have variables currently?)

    result = TranslatedExpr()
    translated_target = convert(target)
    translated_data = convert(data)
    result.helpers.extend(translated_target.helpers)
    result.helpers.extend(translated_data.helpers)

    result.expr = f"{translated_target.expr} = {translated_data.expr};"
    if target.op != "BVS":
        # TODO: remove ugly hardcode
        if target.concrete:
            if target.args[0] == 0x7FF0000000 - 0x140:
                result.expr = f"vpc = {translated_data.expr};"
            elif target.args[0] == 0x7FF0000000 - 0x138:
                result.expr = f"vsp = {translated_data.expr};"

        else:
            result.expr = "*" + result.expr
    return result


def convert_read(a, b):
    # TODO
    return f"READ: {a} at {b}"


def convert_call(target):
    result = TranslatedExpr()
    result.expr = f"call {hex(target)};"
    return result


def convert(expr) -> TranslatedExpr:
    match type(expr):
        case claripy.ast.bool.Bool:
            return _convert_bool(expr)
        case claripy.ast.bv.BV:
            return _convert_bv(expr)
        case _:
            result = TranslatedExpr()
            result.expr = f"[NOT IMPLEMENTED: {type(expr)}]"
            return result


def _convert_bool(expr) -> TranslatedExpr:
    result = TranslatedExpr()
    match expr.op:
        case "BoolV":
            result.expr = "1" if expr.args[0] else "0"
        case "__eq__":
            arg0 = convert(expr.args[0])
            arg1 = convert(expr.args[1])
            result.helpers.extend(arg0.helpers)
            result.helpers.extend(arg1.helpers)
            result.expr = f"({arg0.expr}) == ({arg1.expr})"
        case "__ne__":
            arg0 = convert(expr.args[0])
            arg1 = convert(expr.args[1])
            print(arg0.expr)
            print(arg1.expr)
            result.helpers.extend(arg0.helpers)
            result.helpers.extend(arg1.helpers)
            result.expr = f"({arg0.expr}) != ({arg1.expr})"
        case "SLT":
            arg0 = convert(expr.args[0])
            arg1 = convert(expr.args[1])
            result.helpers.extend(arg0.helpers)
            result.helpers.extend(arg1.helpers)
            result.expr = f"({arg0.expr}) s< ({arg1.expr})"
        case _:
            result.expr = f"[NOT IMPLEMENTED BOOL: {expr.op}]"
    return result


concat_tmp_count = 0
concat_result_count = 0
if_result_count = 0
if_label_count = 0


def _convert_bv(expr) -> TranslatedExpr:
    result = TranslatedExpr()
    match expr.op:
        case "BVV":
            result.expr = f"{hex(expr.args[0])}"
        case "BVS":
            # TODO: remove ugly hardcode
            name = expr.args[0]
            if name.startswith("vsp"):
                result.expr = "vsp"
            elif name.startswith("vpc"):
                result.expr = "vpc"
            else:
                result.expr = f"{expr.args[0]}"

        case "__add__":
            arg0 = convert(expr.args[0])
            branch1 = convert(expr.args[1])
            result.expr = f"({arg0} + {branch1})"
        case "__sub__":
            arg0 = convert(expr.args[0])
            branch1 = convert(expr.args[1])
            result.expr = f"({arg0} - {branch1})"
        case "SignExt":
            # TODO: handle length properly for sleigh? new variable?
            result.expr = f"sext({convert(expr.args[1])})"
        case "Concat":
            global concat_tmp_count, concat_result_count

            # Since p-code does not have an instruction for concatenation, we have to
            # implement it manually.
            #
            # We have given:
            # * The bit vectors to be concatenated
            # * Their lengths (possibly not divisable by word size 8)
            # * The total length of the concatenated expression (should be dividable by
            #   word size 8)
            #
            # The general idea is to create local variables for each value to be
            # concatenated and bit-shift it so the bits are at the correct position.
            # Then we can simply logically or those values.
            bit_vectors = expr.args
            total_length = expr.length
            translated_exprs = list(map(lambda e: convert(e), bit_vectors))

            for te in translated_exprs:
                result.helpers.extend(te.helpers)

            # Concat value shifts
            shift = total_length
            tmp_used = []
            for i, e in enumerate(bit_vectors):
                shift -= e.length
                result.helpers.append(
                    f"local concat_tmp_{concat_tmp_count}: {math.ceil(total_length / 8)} = ({translated_exprs[i].expr}) << {shift};"
                )
                tmp_used.append(concat_tmp_count)
                concat_tmp_count += 1

            # Actual concat
            concat_result = f"local concat_result_{concat_result_count}: {math.ceil(total_length / 8)} = "
            for i, tmp in enumerate(tmp_used):
                if i != 0:
                    concat_result = concat_result + " | "
                concat_result = concat_result + f"concat_tmp_{tmp}"
            concat_result += ";"
            concat_result_count += 1
            result.helpers.append(concat_result)
            result.expr = f"(concat_result_{concat_result_count - 1})"
        case "If":
            global if_result_count, if_label_count

            # Since p-code does not have a mechanism for ternaries (or even
            # if-else-constructs apart from conditional jumps), we have to manually
            # implement it.
            #
            # To do that, we use a local variable for the ternary value and conditional
            # jumps to set the value.

            # Condition
            cond = convert(expr.args[0])
            result.helpers.extend(cond.helpers)
            result.helpers.append(
                # TODO: check if 1bit local variable is correct (do we have to expand it when assigning to larger variable?)
                f"local if_result_{if_result_count}: {math.ceil(expr.length / 8)} = 0;"
            )
            result.helpers.append(f"if ({cond.expr}) goto <if_label_{if_label_count}>;")

            # Branch 2
            branch2 = convert(expr.args[2])
            result.helpers.extend(branch2.helpers)
            result.helpers.append(f"if_result_{if_result_count} = {branch2.expr};")
            result.helpers.append(f"goto <if_label_{if_label_count + 1}>;")

            # Branch 1
            result.helpers.append(f"<if_label_{if_label_count}>:")
            branch1 = convert(expr.args[1])
            result.helpers.extend(branch1.helpers)
            result.helpers.append(f"if_result_{if_result_count} = {branch1.expr};")

            # End
            result.helpers.append(f"<if_label_{if_label_count + 1}>:")
            result.expr = f"if_result_{if_result_count}"
            if_result_count += 1
            if_label_count += 2
        case _:
            result.expr = f"[NOT IMPLEMENTED BV: {expr.op}]"
    return result
