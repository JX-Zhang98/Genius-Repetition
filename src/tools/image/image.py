#!/usr/bin/env python3
# coding:utf-8

import os
import re
import subprocess
import sys

from capstone.arm import ARM_OP_IMM

import angr

from ..util.asm import disasm, is_call, is_jump
from ..util.error import Error
from ..util.file import read
from ..util.format import normalize_symbol
from ..util.log import logging
from ..util.packing import u32


class Image(object):
    """Class for kernel image."""

    def __init__(self, filename, system_map=None):
        self.log = logging.getLogger(__name__)
        if not os.path.isfile(filename):
            raise Error('invalid image path')
        self.filename = filename
        with open(filename, 'rb') as fp:
            self.type = 'elf' if fp.read(4) == b'\x7fELF' else 'kernel'
        self._system_map = system_map
        if self.type == 'elf' and self._system_map is not None:
            self.log.warning('System.map will be ignored for ELF Image.')

    def get_data(self, addr=None, length=None):
        """Get data at certain address."""
        if addr is None:
            addr = self.rebase
        if length is None:
            length = self.project.loader.max_addr - addr + 1
        return self.project.loader.memory.load(addr, length)

    def get_int(self, addr):
        """Get an integer from certain address."""
        return u32(self.get_data(addr, 4))

    def get_instr(self, addr):
        """Disassemble an instruction at certain addr."""
        return disasm(self.get_data(addr, 4), addr)

    def get_format_instr(self, addr):
        """Disassemble an instruction to certain format at certain addr."""
        return self._format_instr(self.get_instr(addr))

    def get_func(self, name):
        """Extract function with given name."""
        if name not in self.funcs:
            return None
        sym = self.get_symbol(name)
        addr = sym.rebased_addr
        end_addr = addr + sym.size
        self.log.debug('extracting function %s at %#x', name, addr)

        body = []
        for i in range(addr, end_addr, 4):
            instr = self.get_format_instr(i)
            if instr is None:
                instr = (i, '', '', self.get_data(i, 4))
            body.append(instr)
        return body

    def get_raw_func(self, name):
        """Extract raw function instructions."""
        if name not in self.funcs:
            return []
        sym = self.get_symbol(name)
        addr = sym.rebased_addr
        end_addr = addr + sym.size
        self.log.debug('extracting raw function %s at %#x', name, addr)

        body = []
        for i in range(addr, end_addr, 4):
            instr = self.get_instr(i)
            if instr is None:
                continue
            body.append(instr)
        return body

    def get_symbol(self, thing):
        """Search for the symbol with the given name or address."""
        if type(thing) is int:
            return self.symbol_by_addr.get(thing)
        return self.symbol_by_name.get(thing)

    def get_symbol_name(self, addr):
        """Convert symbol name to address."""
        if addr not in self.symbol_by_addr:
            return None
        return self.symbol_by_addr[addr].name

    def get_symbol_addr(self, name):
        """Convert address to symbol name."""
        if name not in self.symbol_by_name:
            return None
        return self.symbol_by_name[name].rebased_addr

    def get_sub_func(self, fn):
        """Extract sub function set for given function."""
        if not hasattr(self, '_sub_fn'):
            self._sub_fn = {}
        if fn in self._sub_fn:
            return self._sub_fn[fn]
        sub_fn = set()
        self._sub_fn[fn] = sub_fn
        for instr in self.get_raw_func(fn):
            if is_call(instr) or is_jump(instr):
                op = instr.operands[0]
                if op.type != ARM_OP_IMM:
                    continue
                symbol = self.get_symbol_name(op.imm & 0xffffffff)
                if symbol is None:
                    continue
                sub_fn.add(str(symbol))
        return sub_fn

    def get_sub_func_deep(self, fn, depth=1):
        """Extract sub function set for give function with given depth."""
        sub_fn = self.get_sub_func(fn)
        if depth > 1:
            for x in sub_fn.copy():
                sub_fn.update(self.get_sub_func_deep(x, depth=depth - 1))
        return sub_fn

    def get_cfg(self, fn):
        """Get CFG for certain function."""
        if not hasattr(self, '_cfg'):
            self._cfg = {}
        if fn not in self._cfg:
            self._cfg[fn] = self.project.analyses.CFGEmulated(
                context_sensitivity_level=0,
                call_depth=0,
                starts=[self.get_symbol_addr(fn)])
        return self._cfg[fn]

    @property
    def project(self):
        """Corresponding angr project for the image."""
        main_opts = dict(backend=self.type)
        if self.type == 'kernel':
            main_opts['system_map'] = self._system_map
        if not hasattr(self, '_project'):
            self._project = angr.Project(
                self.filename, auto_load_libs=False, main_opts=main_opts)
        return self._project

    @property
    def version(self):
        """Kernel version for the image."""
        if not hasattr(self, '_version'):
            found = re.search(rb'Linux version ([^ ]*)', self.get_data())
            if not found:
                raise Exception('could not recognize kernel version')
            version = found.group(1).decode()
            self.log.info('kernel version: %s', version)
            self._version = '.'.join(version.split('.')[:2])
        return self._version

    @property
    def bits(self):
        """Kernel word bits width."""
        return self.project.arch.bits

    @property
    def raw_instrs(self):
        """Instructions for the image, generated with objdump."""
        tpl = '${{CROSS_COMPILE}}objdump -D -bbinary -marm --adjust-vma {} {}'
        cmd = tpl.format(self.rebase, self.filename)
        return subprocess.check_output(cmd).split('\n')

    @property
    def rebase(self):
        """Base address for the image."""
        return self.project.loader.main_object.mapped_base

    @property
    def funcs(self):
        if not hasattr(self, '_funcs'):
            self._funcs = set()
            for sym in self.project.loader.symbols:
                if sym.is_function:
                    self._funcs.add(normalize_symbol(sym.name))
        return self._funcs

    @property
    def symbol_by_addr(self):
        if not hasattr(self, '_symbol_by_addr'):
            self._symbol_by_addr = {}
            for sym in self.project.loader.symbols:
                if sym.type == sym.TYPE_OTHER:
                    continue
                address = sym.rebased_addr
                name = normalize_symbol(sym.name)
                if (not sym.is_local or address not in self._symbol_by_addr):
                    self._symbol_by_addr[address] = sym
        return self._symbol_by_addr

    @property
    def symbol_by_name(self):
        if not hasattr(self, '_symbol_by_name'):
            self._symbol_by_name = {}
            for sym in self.project.loader.symbols:
                if sym.type == sym.TYPE_OTHER:
                    continue
                address = sym.rebased_addr
                name = normalize_symbol(sym.name)
                self._symbol_by_name[name] = sym
        return self._symbol_by_name

    @property
    def regions(self):
        """Mapping regions for kernel."""
        return self.project.loader.main_object.segments

    def _format_instr(self, instr):
        """Format raw instruction to (addr, opcode, operands) tuple."""
        if instr is None:
            return None
        addr = instr.address
        opcode = instr.mnemonic
        if is_call(instr):
            # symbolize call instruction
            invoked_addr = instr.operands[0].imm & 0xfffffffe
            operands = self.get_symbol_name(invoked_addr)
            if operands is None:
                operands = instr.op_str
        # elif is_pc_relative_load(instr):
        #     # parse PC relative load data
        #     op = instr.operands[1]
        #     data_addr = (addr + 8 + op.mem.disp) & 0xfffffffc
        #     data = self.get_int(data_addr)
        #     dist_reg = instr.reg_name(instr.operands[0].reg)
        #     operands = '{}, ={:#x}'.format(dist_reg, data)
        # elif instr.id == ARM_INS_ADR:
        #     raise Exception('adr handler not implemented yet')
        else:
            operands = instr.op_str
        operands = operands.strip('#')
        # use hex format for digits only operands
        if re.match(r'^\d+$', operands):
            operands = '{:#x}'.format(int(operands))
        return (addr, opcode, operands, bytes(instr.bytes))


if __name__ == '__main__':
    image = Image(sys.argv[1])
    print('version:', image.version)
    print('rebase:', hex(image.rebase))
    print(image.get_format_instr(0x30 + image.rebase))
    print('ping_unhash:')
    for i in image.get_func('ping_unhash'):
        print('\t{}'.format(i))
