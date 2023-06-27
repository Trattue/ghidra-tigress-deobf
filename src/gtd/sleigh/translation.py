import math

import claripy

from .expression import SleighExpr


def translate_jump(target, guard) -> SleighExpr:
    # TODO: simplify if(1)?
    # TODO: handle jumps properly with labels (in state tree?)
    result = SleighExpr()
    translated_target = _translate_expr(target)
    translated_guard = _translate_expr(guard)
    result.context.extend(translated_target.context)
    result.context.extend(translated_guard.context)
    result.expr = f"if ({translated_guard.expr}) goto {translated_target.expr};"
    return result


def translate_write(target, data):
    # TODO: handle target assignment properly (addr vs variables) (do we even have variables currently?)

    result = SleighExpr()
    translated_target = _translate_expr(target)
    translated_data = _translate_expr(data)
    result.context.extend(translated_target.context)
    result.context.extend(translated_data.context)

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


def translate_read(a, b):
    # TODO
    return f"READ: {a} at {b}"


def translate_call(target):
    result = SleighExpr()
    result.expr = f"call {hex(target)};"
    return result


def _translate_expr(expr) -> SleighExpr:
    match type(expr):
        case claripy.ast.bool.Bool:
            return _translate_bool(expr)
        case claripy.ast.bv.BV:
            return _translate_bv(expr)
        case _:
            result = SleighExpr()
            result.expr = f"[NOT IMPLEMENTED: {type(expr)}]"
            return result


def _translate_bool(expr) -> SleighExpr:
    result = SleighExpr()
    match expr.op:
        case "BoolV":
            result.expr = "1" if expr.args[0] else "0"
        case "__eq__":
            arg0 = _translate_expr(expr.args[0])
            arg1 = _translate_expr(expr.args[1])
            result.context.extend(arg0.context)
            result.context.extend(arg1.context)
            result.expr = f"({arg0.expr}) == ({arg1.expr})"
        case "__ne__":
            arg0 = _translate_expr(expr.args[0])
            arg1 = _translate_expr(expr.args[1])
            print(arg0.expr)
            print(arg1.expr)
            result.context.extend(arg0.context)
            result.context.extend(arg1.context)
            result.expr = f"({arg0.expr}) != ({arg1.expr})"
        case "SLT":
            arg0 = _translate_expr(expr.args[0])
            arg1 = _translate_expr(expr.args[1])
            result.context.extend(arg0.context)
            result.context.extend(arg1.context)
            result.expr = f"({arg0.expr}) s< ({arg1.expr})"
        case _:
            result.expr = f"[NOT IMPLEMENTED BOOL: {expr.op}]"
    return result


concat_tmp_count = 0
concat_result_count = 0
if_result_count = 0
if_label_count = 0


def _translate_bv(expr) -> SleighExpr:
    result = SleighExpr()
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
            add_result = ""
            for i, e in enumerate(expr.args):
                t = _translate_expr(e)
                result.context.extend(t.context)
                if i != 0:
                    add_result += " + "
                add_result += t.expr
            result.expr = f"({add_result})"
        case "__sub__":
            sub_result = ""
            for i, e in enumerate(expr.args):
                t = _translate_expr(e)
                result.context.extend(t.context)
                if i != 0:
                    sub_result += " + "
                sub_result += t.expr
            result.expr = f"({sub_result})"
        case "SignExt":
            # TODO: handle length properly for sleigh? new variable?
            result.expr = f"sext({_translate_expr(expr.args[1])})"
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
            translated_exprs = list(map(lambda e: _translate_expr(e), bit_vectors))

            for te in translated_exprs:
                result.context.extend(te.context)

            # Concat value shifts
            shift = total_length
            tmp_used = []
            for i, e in enumerate(bit_vectors):
                shift -= e.length
                result.context.append(
                    f"local concat_tmp_{concat_tmp_count}: {math.ceil(total_length / 8)} = ({translated_exprs[i].expr}) << {shift};"
                )
                tmp_used.append(concat_tmp_count)
                concat_tmp_count += 1

            # Actual concat
            concat_result = f"local concat_result_{concat_result_count}: {math.ceil(total_length / 8)} = "
            for i, tmp in enumerate(tmp_used):
                if i != 0:
                    concat_result += " | "
                concat_result += f"concat_tmp_{tmp}"
            concat_result += ";"
            concat_result_count += 1
            result.context.append(concat_result)
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
            cond = _translate_expr(expr.args[0])
            result.context.extend(cond.context)
            result.context.append(
                # TODO: check if 1bit local variable is correct (do we have to expand it when assigning to larger variable?)
                f"local if_result_{if_result_count}: {math.ceil(expr.length / 8)} = 0;"
            )
            result.context.append(f"if ({cond.expr}) goto <if_label_{if_label_count}>;")

            # Branch 2
            branch2 = _translate_expr(expr.args[2])
            result.context.extend(branch2.context)
            result.context.append(f"if_result_{if_result_count} = {branch2.expr};")
            result.context.append(f"goto <if_label_{if_label_count + 1}>;")

            # Branch 1
            result.context.append(f"<if_label_{if_label_count}>:")
            branch1 = _translate_expr(expr.args[1])
            result.context.extend(branch1.context)
            result.context.append(f"if_result_{if_result_count} = {branch1.expr};")

            # End
            result.context.append(f"<if_label_{if_label_count + 1}>:")
            result.expr = f"if_result_{if_result_count}"
            if_result_count += 1
            if_label_count += 2
        case _:
            result.expr = f"[NOT IMPLEMENTED BV: {expr.op}]"
    return result
