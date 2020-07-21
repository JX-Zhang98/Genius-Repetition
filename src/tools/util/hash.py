import hashlib


def md5sumhex(data):
    return hashlib.md5(data).hexdigest()
