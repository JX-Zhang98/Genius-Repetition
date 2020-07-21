from cle.backends.region import Segment


class KernelSegment(Segment):
    """
    Represents a segment for the kernel image (kallsyms).
    """

    PERM_EXECUTE = 0x1
    PERM_WRITE = 0x2
    PERM_READ = 0x4

    def __init__(self, offset, vaddr, size, flags):
        super().__init__(offset, vaddr, size, size)
        self.flags = flags

    @property
    def is_readable(self):
        return self.flags & self.PERM_READ != 0

    @property
    def is_writable(self):
        return self.flags & self.PERM_WRITE != 0

    @property
    def is_executable(self):
        return self.flags & self.PERM_EXECUTE != 0