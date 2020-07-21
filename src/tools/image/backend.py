from cle.backends import Blob

from ..util.const import PAGE_MASK, PAGE_SIZE
from ..util.file import read
from ..util.log import logging
from .region import KernelSegment
from .sym import do_get_arch, extract_kallsyms
from .symbol import KernelSymbol

log = logging.getLogger(__name__)


class Kernel(Blob):
    """
    Representation of a kernel image.
    """

    def __init__(self, binary, system_map=None, **kwargs):
        raw_data = read(binary, mode='rb')
        bits = do_get_arch(raw_data)
        log.debug('kernel bits: %d', bits)
        base_addr, kallsyms = extract_kallsyms(raw_data, bits, system_map)
        log.debug('kernel base address: %#x', base_addr)

        arch = 'aarch64' if bits == 64 else 'arm'
        super().__init__(binary, arch=arch, base_addr=base_addr, **kwargs)

        # setup symbols
        self._symbols_by_name = {}
        last_rva = len(raw_data)
        last_diff_rva = last_rva
        for sym in kallsyms[::-1]:
            rva = sym['address'] - base_addr
            if rva != last_rva:
                last_diff_rva = last_rva
            size = last_diff_rva - rva
            cle_sym = KernelSymbol(self, sym['name'], rva, size, sym['type'])
            last_rva = rva

            self.symbols.add(cle_sym)
            self._cache_symbol_name(cle_sym)

        # setup segments
        type_blacklist = [KernelSymbol.TYPE_FUNCTION, KernelSymbol.TYPE_OBJECT]
        filtered_symbols = [
            sym for sym in self.symbols if sym.type in type_blacklist
        ]
        idx = 0
        while filtered_symbols[idx].rebased_addr < base_addr:
            idx += 1
        while idx < len(filtered_symbols):
            sym = filtered_symbols[idx]
            idx += 1
            start_addr = sym.rebased_addr & PAGE_MASK
            while idx < len(filtered_symbols):
                next_sym = filtered_symbols[idx]
                if next_sym.type != sym.type:
                    size = (next_sym.rebased_addr & PAGE_MASK) - start_addr
                    break
                idx += 1
            else:
                last_address = filtered_symbols[-1].rebased_addr
                last_address = (last_address + PAGE_SIZE - 1) & PAGE_MASK
                size = last_address - start_addr

            perms = KernelSegment.PERM_READ
            if sym.type == KernelSymbol.TYPE_FUNCTION:
                perms |= KernelSegment.PERM_EXECUTE
            elif sym.raw_type.lower() == 'd':
                perms |= KernelSegment.PERM_WRITE

            log.debug('region (%#x, %#x, %s)', start_addr, size, perms)
            start_offset = start_addr - base_addr
            segment = KernelSegment(start_offset, start_addr, size, perms)
            self.segments.append(segment)

    def get_symbol(self, name):
        """Get symbol by name."""
        return self._symbols_by_name.get(name)

    def _cache_symbol_name(self, symbol):
        name = symbol.name
        if name:
            if name in self._symbols_by_name:
                old_symbol = self._symbols_by_name[name]
                if not old_symbol.is_weak and symbol.is_weak:
                    return
            self._symbols_by_name[name] = symbol
