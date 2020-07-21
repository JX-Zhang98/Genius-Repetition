import os
import shutil


class WorkingDir:

    def __init__(self, path):
        self.path = path

    def __enter__(self):
        self.original = os.path.abspath('.')
        os.chdir(self.path)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        os.chdir(self.original)


def copy(src, dst):
    """Copy file when src file exists."""
    if not os.path.exists(src):
        return False
    shutil.copy(src, dst)
    return True


def move(src, dst):
    """Move a file or directory to another location when src file exists."""
    if not os.path.exists(src):
        return False
    shutil.move(src, dst)
    return True


def mkdir(path):
    """Create directory when not exists."""
    if os.path.exists(path):
        return False
    os.makedirs(path)
    return True
