__all__ = ['Image']

from cle.backends import register_backend

from .backend import Kernel
from .image import Image

register_backend('kernel', Kernel)
