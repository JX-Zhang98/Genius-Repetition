#!/home/xianglin/.virtualenvs/angr/bin/ python
# -*- coding: utf-8 -*-
__Auther__ = 'xianglin'

import angr
import capstone
import claripy
from tools.image import Image
from tools.util.asm import is_jump

"""
it is based on ARM64 instruction set, might add more CPU arch in the future
"""
######################################################################
# numeric feature
######################################################################
def get_consts(img, insn, offset):
    """
    get const from an instruction
    if op is in call function, pass
    else:   if it is an imm, check if it is an addr or numeric
            else [mem]

    Args:
        insn:(capstone.insn) an instuction
        offset(int): the i-th operand

    Returns:
        string_consts(list):
        numeric_consts(list):
    """
    string_consts = []
    numeric_consts = []
    insn = insn.insn
    arm64_CI = {'b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz'}
    op_imm = {'ARM_OP_IMM', 'ARM64_OP_IMM', 'X86_OP_IMM', 'MIPS_OP_IMM'}
    op_mnemonic = insn.mnemonic
    # if mnemonic is in call functions, return
    if check_type(op_mnemonic, arm64_CI):
        return string_consts, numeric_consts

    base_pointer = {'pc'}
    operand = insn.operands[offset]
    op_type = operand.type
    # if it is an immediate value, output the value
    # contingent across all arch
    if op_type == capstone.arm64.ARM64_OP_IMM:
        # if adr, then string/numeric?, else numeric
        if check_type(op_mnemonic, {'adr'}):
            # turn int to addr hex
            bvv = claripy.BVV(operand.value.imm, 64)
            addr = bvv.args[0]
            string_const = get_string(img, addr)
            if string_const is None:
                numeric_const = get_numeric(img, addr)
                numeric_consts.append(numeric_const)
            else:
                string_consts.append(string_const)
        else:
            numeric_consts.append(operand.value.imm)
    # [mem]
    elif op_type == capstone.arm64.ARM64_OP_MEM:
        if operand.value.mem.base != 0:
            base_reg = insn.reg_name(operand.value.mem.base)
            if base_reg in base_pointer:
                disp = operand.value.mem.disp
                addr = insn.address + disp
                numeric_const = get_numeric(img, addr)
                numeric_consts.append(numeric_const)

    return string_consts, numeric_consts


def get_BB_consts(img, block):
    """
    get string and numeric consts from a block
    Args:
        img(tools.image.Image)
        block: angr.block

    Returns:
        string_consts(list): string consts from a block
        numeric_consts(list): numeric consts from a block

    """
    string_consts = []
    numeric_consts = []
    cs = block.capstone
    insns = cs.insns
    for insn in insns:
        num_operands = len(insn.operands)
        for offset in range(num_operands):
            strings, numerics = get_consts(img, insn, offset)
            string_consts += strings
            numeric_consts += numerics

    return string_consts, numeric_consts


def cal_insts(block):
    """calculate the number of instructions in a block"""
    return block.instructions


def cal_transfer_insts(block):
    arm_TI = {'mvn', "mov"}
    num = 0
    cs = block.capstone
    insns = cs.insns
    for insn in insns:
        op_type = insn.insn.mnemonic
        if check_type(op_type, arm_TI):
            num = num + 1
    return num


def cal_call_insts(block):
    arm64_CI = {'b', 'bl', 'cbz', 'cbnz', 'tbz', 'tbnz'}
    num = 0
    cs = block.capstone
    insns = cs.insns
    for insn in insns:
        op_type = insn.insn.mnemonic
        if check_type(op_type, arm64_CI):
            num = num + 1
    return num


def cal_arithmetic_insts(block):
    arm64_AI = {'add', 'sub', 'adc', 'sbc'}
    num = 0
    cs = block.capstone
    insns = cs.insns
    for insn in insns:
        op_type = insn.insn.mnemonic
        if check_type(op_type, arm64_AI):
            num = num + 1
    return num


######################################################################
# other functions
######################################################################
def check_type(t, t_set):
    """
    Args:
        t(str): operator or register
        t_set(set): check type set

    Returns:
        states(boolean): true if t is in t_set

    """
    for t_type in t_set:
        if t.startswith(t_type):
            return True
    return False


def get_string(img, addr):
    string = ""
    for i in range(1000):
        c = img.project.loader.memory.load(addr + i, 1)
        if ord(c) == 0:
            break
        elif 40 <= ord(c) < 128:
            string += chr(ord(c))
        else:
            return None
    return string


def get_numeric(img, addr):
    b = img.project.loader.memory.load(addr, 4)
    num = int.from_bytes(b, "little")
    return num
