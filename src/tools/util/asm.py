from capstone import *
from capstone.arm64 import *

from .log import logging

__all__ = [
    'disasm',
    'is_jump',
    'is_call',
]

log = logging.getLogger(__name__)


def disasm(data, addr):
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md.detail = True
    try:
        return next(md.disasm(data, addr))
    except StopIteration as err:
        log.debug('failed to disassemble %r at %#x', data, addr)
        return None


def is_jump(instr):
    return instr.group(ARM64_GRP_JUMP)


def is_call(instr):
    return instr.id == ARM64_INS_BL
