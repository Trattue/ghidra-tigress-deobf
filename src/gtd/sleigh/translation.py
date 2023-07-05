import math

import claripy

from .expression import SleighExpr


def translate_write(target, data):
    # TODO: handle target assignment properly (addr vs variables) (do we even have variables currently?)

    result = SleighExpr()
    translated_target = _translate_expr(target)
    translated_data = _translate_expr(data)
    result.context.extend(translated_target.context)
    result.context.extend(translated_data.context)

    # TODO: how to encode data length? check sleigh docs for * operator
    result.expression = (
        f"*{translated_target.expression} = {translated_data.expression};"
    )
    # TODO: remove ugly hardcode
    if target.concrete:
        if target.args[0] == 0x7FF0000000 - 0x140:
            result.expression = f"VPC = {translated_data.expression};"
        elif target.args[0] == 0x7FF0000000 - 0x138:
            result.expression = f"VSP = {translated_data.expression};"
    return result


def translate_read(expr, addr) -> SleighExpr | None:
    if addr.concrete and (
        addr.args[0] == 0x7FF0000000 - 0x140 or addr.args[0] == 0x7FF0000000 - 0x138
    ):
        # TODO: remove ugly hardcode
        return

    # TODO: use references?
    result = SleighExpr()
    translated_addr = _translate_expr(addr)
    result.context.extend(translated_addr.context)
    length = math.ceil(expr.length / 8)
    result.expression = (
        f"local {expr.args[0]}:{length} = *{translated_addr.expression};"
    )
    return result


def translate_call(target):
    result = SleighExpr()
    result.expression = f"call {hex(target)};"
    return result


def _translate_expr(expr) -> SleighExpr:
    match type(expr):
        case claripy.ast.bool.Bool:
            return _translate_bool(expr)
        case claripy.ast.bv.BV:
            return _translate_bv(expr)
        case _:
            result = SleighExpr()
            result.expression = f"[NOT IMPLEMENTED: {type(expr)}]"
            return result


def _translate_bool(expr) -> SleighExpr:
    result = SleighExpr()
    match expr.op:
        case "BoolV":
            result.expression = "1" if expr.args[0] else "0"
        case "__eq__":
            arg0 = _translate_expr(expr.args[0])
            arg1 = _translate_expr(expr.args[1])
            result.context.extend(arg0.context)
            result.context.extend(arg1.context)
            result.expression = f"({arg0.expression}) == ({arg1.expression})"
        case "__ne__":
            arg0 = _translate_expr(expr.args[0])
            arg1 = _translate_expr(expr.args[1])
            result.context.extend(arg0.context)
            result.context.extend(arg1.context)
            result.expression = f"({arg0.expression}) != ({arg1.expression})"
        case "SLT":
            arg0 = _translate_expr(expr.args[0])
            arg1 = _translate_expr(expr.args[1])
            result.context.extend(arg0.context)
            result.context.extend(arg1.context)
            result.expression = f"({arg0.expression}) s< ({arg1.expression})"
        case _:
            result.expression = f"[NOT IMPLEMENTED BOOL: {expr.op}]"
    return result


concat_tmp_count = 0
concat_result_count = 0
if_result_count = 0
if_label_count = 0


def _translate_bv(expr) -> SleighExpr:
    result = SleighExpr()
    match expr.op:
        case "BVV":
            result.expression = f"{hex(expr.args[0])}:{math.ceil(expr.length / 8)}"
        case "BVS":
            # TODO: remove ugly hardcode
            name = expr.args[0]
            if name.startswith("vsp"):
                result.expression = "VSP"
            elif name.startswith("vpc"):
                result.expression = "VPC"
            else:
                result.expression = f"{expr.args[0]}"
        case "__add__":
            add_result = ""
            for i, e in enumerate(expr.args):
                t = _translate_expr(e)
                result.context.extend(t.context)
                if i != 0:
                    add_result += " + "
                add_result += t.expression
            result.expression = f"({add_result})"
        case "__sub__":
            sub_result = ""
            for i, e in enumerate(expr.args):
                t = _translate_expr(e)
                result.context.extend(t.context)
                if i != 0:
                    sub_result += " - "
                sub_result += t.expression
            result.expression = f"({sub_result})"
        case "SignExt":
            result.expression = f"sext({_translate_expr(expr.args[1])})"
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

                # Sleigh wants value to be shifted to have the same size as the shifted
                # value... That's why we use zext(), that should semantically be the
                # same
                size = math.ceil(total_length / 8)
                left = f"local concat_tmp_{concat_tmp_count}:{size}"
                right = f"zext({translated_exprs[i].expression}) << {shift};"
                result.context.append(left + " = " + right)
                tmp_used.append(concat_tmp_count)
                concat_tmp_count += 1

            # Actual concat
            concat_result = f"local concat_result_{concat_result_count}: {math.ceil(total_length / 8)} = "
            concat_result += " | ".join(map(lambda t: f"concat_tmp_{t}", tmp_used))
            concat_result += ";"
            concat_result_count += 1
            result.context.append(concat_result)
            result.expression = f"(concat_result_{concat_result_count - 1})"
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
            result.context.append(
                f"if ({cond.expression}) goto <if_label_{if_label_count}>;"
            )

            # Branch 2
            branch2 = _translate_expr(expr.args[2])
            result.context.extend(branch2.context)
            result.context.append(
                f"if_result_{if_result_count} = {branch2.expression};"
            )
            result.context.append(f"goto <if_label_{if_label_count + 1}>;")

            # Branch 1
            result.context.append(f"<if_label_{if_label_count}>")
            branch1 = _translate_expr(expr.args[1])
            result.context.extend(branch1.context)
            result.context.append(
                f"if_result_{if_result_count} = {branch1.expression};"
            )

            # End
            result.context.append(f"<if_label_{if_label_count + 1}>")
            result.expression = f"if_result_{if_result_count}"
            if_result_count += 1
            if_label_count += 2
        case _:
            result.expression = f"[NOT IMPLEMENTED BV: {expr.op}]"
    return result
