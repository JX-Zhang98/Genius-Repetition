class Error(Exception):
    """Base error for the project."""

    def __init__(self, message):
        self.message = message


class ArchitectureError(Error):
    """Not supported architecture."""


class KallsymsError(Error):
    """Error for failing to extract kallsyms."""


class FunctionNotFoundError(Error):
    """Error for function not found."""


class InputInapplicableError(Error):
    """Error represents input inapplicable for current kernel."""


class FixFailedError(Error):
    """Error for failing to fix input."""


class InvalidMemoryError(Error):
    """Error for invalid memory operation."""

    def __init__(self, address, trace, mem_op, impact_list):
        self.address = address
        self.trace = trace
        self.mem_op = mem_op
        self.impact_list = impact_list


class InvalidMemoryReadError(InvalidMemoryError):
    """Error for invalid memory read operation."""


class InvalidMemoryWriteError(InvalidMemoryError):
    """Error for invalid memory write operation."""
