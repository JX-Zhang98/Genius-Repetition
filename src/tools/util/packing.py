import struct


def p32(number):
    return struct.pack('<I', number)


def p64(number):
    return struct.pack('<Q', number)


def u32(data):
    assert len(data) == 4
    return struct.unpack('<I', data)[0]


def u64(data):
    assert len(data) == 8
    return struct.unpack('<Q', data)[0]
