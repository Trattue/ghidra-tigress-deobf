import math

import claripy
from gtd.sleigh.expression import SleighExpr


def translate_write(address, data):
    result = SleighExpr()
    translated_address = _translate_expression(address)
    translated_data = _translate_expression(data)
    result.context.extend(translated_address.context)
    result.context.extend(translated_data.context)
    left_side = f"*{translated_address.expression} = "
    # TODO: remove ugly hardcode
    if address.concrete:
        # Here, we use local variables for vpc and vsp for writing. We
        # will save the values to the registers at the end of the
        # handler.
        if address.args[0] == 0x7FF0000000 - 0x140:
            left_side = f"vpc = "
        elif address.args[0] == 0x7FF0000000 - 0x138:
            left_side = f"vsp = "
    right_side = f"{translated_data.expression};"
    result.expression = left_side + right_side
    return result


def translate_read(data, address) -> SleighExpr | None:
    if address.concrete and (
        address.args[0] == 0x7FF0000000 - 0x140
        or address.args[0] == 0x7FF0000000 - 0x138
    ):
        # TODO: remove ugly hardcode
        return

    result = SleighExpr()
    translated_address = _translate_expression(address)
    result.context.extend(translated_address.context)
    length = math.ceil(data.length / 8)
    left_side = f"local {data.args[0]}:{length} = "
    right_side = f"*{translated_address.expression};"

    # Hardcoded patch to support one argument...
    # TODO: make this dynamic (config!)
    tmp = claripy.simplify(address - 1)
    if (
        isinstance(tmp, claripy.ast.bv.BV)
        and tmp.op == "BVS"
        and tmp.args[0].startswith("vpc")
    ):
        right_side = f"imm{data.length};"

    result.expression = left_side + right_side
    return result


def translate_call(target):
    result = SleighExpr()
    result.expression = f"call {hex(target)};"
    return result


def _translate_expression(expression) -> SleighExpr:
    match type(expression):
        case claripy.ast.bool.Bool:
            return _translate_bool(expression)
        case claripy.ast.bv.BV:
            return _translate_bv(expression)
        case _:
            result = SleighExpr()
            result.expression = f"[NOT IMPLEMENTED: {type(expression)}]"
            return result


def _translate_bool(expression) -> SleighExpr:
    result = SleighExpr()
    match expression.op:
        case "BoolV":
            result.expression = "1" if expression.args[0] else "0"
        case "__eq__":
            arg0 = _translate_expression(expression.args[0])
            arg1 = _translate_expression(expression.args[1])
            result.context.extend(arg0.context)
            result.context.extend(arg1.context)
            result.expression = f"({arg0.expression}) == ({arg1.expression})"
        case "__ne__":
            arg0 = _translate_expression(expression.args[0])
            arg1 = _translate_expression(expression.args[1])
            result.context.extend(arg0.context)
            result.context.extend(arg1.context)
            result.expression = f"({arg0.expression}) != ({arg1.expression})"
        case "__lt__":
            arg0 = _translate_expression(expression.args[0])
            arg1 = _translate_expression(expression.args[1])
            result.context.extend(arg0.context)
            result.context.extend(arg1.context)
            result.expression = f"({arg0.expression}) < ({arg1.expression})"
        case "SLT":
            arg0 = _translate_expression(expression.args[0])
            arg1 = _translate_expression(expression.args[1])
            result.context.extend(arg0.context)
            result.context.extend(arg1.context)
            result.expression = f"({arg0.expression}) s< ({arg1.expression})"
        case "SLE":
            arg0 = _translate_expression(expression.args[0])
            arg1 = _translate_expression(expression.args[1])
            result.context.extend(arg0.context)
            result.context.extend(arg1.context)
            result.expression = f"({arg0.expression}) s<= ({arg1.expression})"
        case "SGT":
            arg0 = _translate_expression(expression.args[0])
            arg1 = _translate_expression(expression.args[1])
            result.context.extend(arg0.context)
            result.context.extend(arg1.context)
            result.expression = f"({arg0.expression}) s> ({arg1.expression})"
        case _:
            result.expression = f"[NOT IMPLEMENTED BOOL: {expression.op}]"
    return result


concat_tmp_count = 0
concat_result_count = 0
if_result_count = 0
if_label_count = 0
extract_count = 0
zext_count = 0
sext_count = 0


# TODO: config option for locals
locals_addr = 0x7FEFFFFFD0


def _translate_bv(expr) -> SleighExpr:
    result = SleighExpr()
    match expr.op:
        case "BVV":
            c = expr.args[0]
            if c == locals_addr:
                result.expression = "locals"
            elif (
                c & 0x7FFFFFFFFF == c
                and c & 0xFFFFFFFF != c
                and c != 0x7FF0000000 - 0x140
                and c != 0x7FF0000000 - 0x138
            ):
                # TODO: currently: locals - XXX; idea: locals + YYY
                result.expression = f"locals - {hex(locals_addr - c)}"
            else:
                result.expression = f"{hex(expr.args[0])}:{math.ceil(expr.length / 8)}"
        case "BVS":
            # TODO: remove ugly hardcode
            name = expr.args[0]
            if name.startswith("vsp"):
                result.expression = "VSP"
            elif name.startswith("vpc"):
                result.expression = "inst_start"
            else:
                result.expression = f"{expr.args[0]}"
        case "__add__":
            translated = list(map(lambda e: _translate_expression(e), expr.args))
            for t in translated:
                result.context.extend(t.context)
            expressions = list(map(lambda e: e.expression, translated))
            result.expression = f"({' + '.join(expressions)})"
        case "__sub__":
            translated = list(map(lambda e: _translate_expression(e), expr.args))
            for t in translated:
                result.context.extend(t.context)
            expressions = list(map(lambda e: e.expression, translated))
            result.expression = f"({' - '.join(expressions)})"
        case "__mul__":
            translated = list(map(lambda e: _translate_expression(e), expr.args))
            for t in translated:
                result.context.extend(t.context)
            expressions = list(map(lambda e: e.expression, translated))
            result.expression = f"({' * '.join(expressions)})"
        case "__and__":
            translated = list(map(lambda e: _translate_expression(e), expr.args))
            for t in translated:
                result.context.extend(t.context)
            expressions = list(map(lambda e: e.expression, translated))
            result.expression = f"({' & '.join(expressions)})"
        case "__xor__":
            translated = list(map(lambda e: _translate_expression(e), expr.args))
            for t in translated:
                result.context.extend(t.context)
            expressions = list(map(lambda e: e.expression, translated))
            result.expression = f"({' ^ '.join(expressions)})"
        case "__lshift__":
            arg0 = _translate_expression(expr.args[0])
            arg1 = _translate_expression(expr.args[1])
            result.context.extend(arg0.context)
            result.context.extend(arg1.context)
            result.expression = f"{arg0.expression} << {arg1.expression}"
        case "LShR":
            arg0 = _translate_expression(expr.args[0])
            arg1 = _translate_expression(expr.args[1])
            result.context.extend(arg0.context)
            result.context.extend(arg1.context)
            result.expression = f"{arg0.expression} >> {arg1.expression}"
        case "ZeroExt":
            global zext_count

            translated = _translate_expression(expr.args[1])
            result.context.extend(translated.context)
            result.context.append(
                f"local zext_{zext_count}:{math.ceil(expr.length / 8)} = zext({translated.expression});"
            )
            result.expression = f"zext_{zext_count}"
            zext_count += 1
        case "SignExt":
            global sext_count

            translated = _translate_expression(expr.args[1])
            result.context.extend(translated.context)
            result.context.append(
                f"local sext_{sext_count}:{math.ceil(expr.length / 8)} = sext({translated.expression});"
            )
            result.expression = f"sext_{sext_count}"
            sext_count += 1
        case "Extract":
            global extract_count

            translated = _translate_expression(expr.args[2])
            result.context.extend(translated.context)

            result.context.append(
                f"local extract_{extract_count}:{math.ceil(expr.args[2].length / 8)} = {translated.expression};"
            )
            least_significant_bit = expr.args[1]
            bit_count = expr.args[0] - least_significant_bit
            result.expression = (
                f"extract_{extract_count}[{least_significant_bit},{bit_count}]"
            )
            extract_count += 1
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
            translated_exprs = list(map(lambda e: _translate_expression(e), expr.args))

            for e in translated_exprs:
                result.context.extend(e.context)

            # Concat value shifts
            shift = expr.length
            tmp_used = []
            for i, e in enumerate(expr.args):
                shift -= e.length

                # Sleigh wants value to be shifted to have the same size as the shifted
                # value... That's why we use zext(), that should semantically be the
                # same
                size = math.ceil(expr.length / 8)
                left = f"local concat_tmp_{concat_tmp_count}:{size}"
                right = f"zext({translated_exprs[i].expression}) << {shift};"
                result.context.append(left + " = " + right)
                tmp_used.append(concat_tmp_count)
                concat_tmp_count += 1

            # Actual concat
            concat_result = f"local concat_result_{concat_result_count}:{math.ceil(expr.length / 8)} = "
            concat_result += " | ".join(map(lambda t: f"concat_tmp_{t}", tmp_used))
            concat_result += ";"
            concat_result_count += 1
            result.context.append(concat_result)
            result.expression = f"concat_result_{concat_result_count - 1}"
        case "If":
            global if_result_count, if_label_count

            # Since p-code does not have a mechanism for ternaries (or even
            # if-else-constructs apart from conditional jumps), we have to manually
            # implement it.
            #
            # To do that, we use a local variable for the ternary value and conditional
            # jumps to set the value.

            # Condition
            cond = _translate_expression(expr.args[0])
            result.context.extend(cond.context)
            result.context.append(
                f"local if_result_{if_result_count}:{math.ceil(expr.length / 8)} = 0;"
            )
            result.context.append(
                f"if ({cond.expression}) goto <if_label_{if_label_count}>;"
            )

            # Branch 2
            branch2 = _translate_expression(expr.args[2])
            result.context.extend(branch2.context)
            result.context.append(
                f"if_result_{if_result_count} = {branch2.expression};"
            )
            result.context.append(f"goto <if_label_{if_label_count + 1}>;")

            # Branch 1
            result.context.append(f"<if_label_{if_label_count}>")
            branch1 = _translate_expression(expr.args[1])
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
