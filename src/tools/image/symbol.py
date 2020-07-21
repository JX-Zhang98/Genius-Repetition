from cle.backends import Symbol


class KernelSymbol(Symbol):
    """
    Represents a symbol for the kernel image (kallsyms).
    """

    def __init__(self, owner, name, relative_addr, size, raw_type):
        # `aNUw` is excepted from kallsyms
        self.raw_type = raw_type
        upper_sym_type = raw_type.upper()

        if upper_sym_type == 'T':
            # code
            sym_type = Symbol.TYPE_FUNCTION
        elif upper_sym_type in ['D', 'G', 'R']:
            # initialized data
            sym_type = Symbol.TYPE_OBJECT
        elif upper_sym_type in ['B', 'C', 'S']:
            # uninitialized data
            sym_type = Symbol.TYPE_OBJECT
            self.is_common = True
        else:
            sym_type = Symbol.TYPE_NONE
            if upper_sym_type in ['V', 'W']:
                self.is_weak = True

        self.is_static = raw_type.islower() or upper_sym_type in ['A']
        self.is_local = raw_type.islower()
        self.is_export = not self.is_local

        super().__init__(owner, name, relative_addr, size, sym_type)
