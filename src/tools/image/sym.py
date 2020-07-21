#!/usr/bin/env python3
# coding:utf-8

import argparse
import os
import re
import struct
import subprocess

from ..util.error import KallsymsError
from ..util.file import read, read_json, write_json
from ..util.hash import md5sumhex
from ..util.log import logging

__all__ = [
    'do_get_arch',
    'extract_kallsyms',
]

log = logging.getLogger(__name__)


def INT(offset, vmlinux, kallsyms):
    word_size = kallsyms['arch'] // 8
    s = vmlinux[offset:offset + word_size]
    f = 'I' if word_size == 4 else 'Q'
    (num,) = struct.unpack(f, s)
    return num


def INT32(offset, vmlinux):
    s = vmlinux[offset:offset + 4]
    (num,) = struct.unpack('I', s)
    return num


def INT64(offset, vmlinux):
    s = vmlinux[offset:offset + 8]
    (num,) = struct.unpack('Q', s)
    return num


def SHORT(offset, vmlinux):
    s = vmlinux[offset:offset + 2]
    (num,) = struct.unpack('H', s)
    return num


def STRIPZERO(offset, vmlinux, kallsyms, step=4):
    if step == 4:
        for i in range(offset, len(vmlinux), step):
            if INT32(i, vmlinux):
                return i
    else:
        for i in range(offset, len(vmlinux), step):
            if INT(i, vmlinux, kallsyms):
                return i


def do_token_index_table(kallsyms, offset, vmlinux):
    kallsyms['token_index_table'] = offset
    log.debug('[+] kallsyms_token_index_table = %#x', offset)


def do_token_table(kallsyms, offset, vmlinux):
    kallsyms['token_table'] = offset
    log.debug('[+] kallsyms_token_table = %#x', offset)

    for i in range(offset, len(vmlinux)):
        if SHORT(i, vmlinux) == 0:
            break
    for i in range(i, len(vmlinux)):
        if vmlinux[i]:
            break
    offset = i - 2

    do_token_index_table(kallsyms, offset, vmlinux)


def do_marker_table(kallsyms, offset, vmlinux):
    kallsyms['marker_table'] = offset
    log.debug('[+] kallsyms_marker_table = %#x', offset)

    offset += (((kallsyms['numsyms'] - 1) >> 8) + 1) * (kallsyms['arch'] // 8)
    offset = STRIPZERO(offset, vmlinux, kallsyms)

    do_token_table(kallsyms, offset, vmlinux)


def do_type_table(kallsyms, offset, vmlinux):
    flag = True
    for i in range(offset, offset + 256 * 4, 4):
        if INT(i, vmlinux, kallsyms) & ~0x20202020 != 0x54545454:
            flag = False
            break

    if flag:
        kallsyms['type_table'] = offset

        while INT(offset, vmlinux, kallsyms):
            offset += (kallsyms['arch'] // 8)
        offset = STRIPZERO(offset, vmlinux, kallsyms)
    else:
        kallsyms['type_table'] = 0

    log.debug('[+] kallsyms_type_table = %#x', kallsyms['type_table'])

    offset -= 4
    do_marker_table(kallsyms, offset, vmlinux)


def do_name_table(kallsyms, offset, vmlinux):
    kallsyms['name_table'] = offset
    log.debug('[+] kallsyms_name_table = %#x', offset)

    for i in range(kallsyms['numsyms']):
        length = vmlinux[offset]
        offset += length + 1
    while offset % 4 != 0:
        offset += 1
    offset = STRIPZERO(offset, vmlinux, kallsyms)

    do_type_table(kallsyms, offset, vmlinux)

    # decompress name and type
    name_offset = 0
    for i in range(kallsyms['numsyms']):
        offset = kallsyms['name_table'] + name_offset
        length = vmlinux[offset]

        offset += 1
        name_offset += length + 1

        name = ''
        while length:
            token_index_table_offset = vmlinux[offset]
            xoffset = kallsyms[
                'token_index_table'] + token_index_table_offset * 2
            token_table_offset = SHORT(xoffset, vmlinux)
            strptr = kallsyms['token_table'] + token_table_offset

            while vmlinux[strptr]:
                name += '%c' % vmlinux[strptr]
                strptr += 1

            length -= 1
            offset += 1

        if kallsyms['type_table']:
            kallsyms['type'].append('X')
            kallsyms['name'].append(name)
        else:
            kallsyms['type'].append(name[0])
            kallsyms['name'].append(name[1:])


def do_guess_start_address(kallsyms, vmlinux):
    _startaddr_from_xstext = 0
    _startaddr_from_banner = 0
    _startaddr_from_processor = 0

    for i in range(kallsyms['numsyms']):
        if kallsyms['name'][i] in [
                '_text', 'stext', '_stext', '_sinittext', '__init_begin'
        ]:
            if hex(kallsyms['address'][i]):
                if _startaddr_from_xstext == 0 or kallsyms['address'][
                        i] < _startaddr_from_xstext:
                    _startaddr_from_xstext = kallsyms['address'][i]

        elif kallsyms['name'][i] == 'linux_banner':
            linux_banner_addr = kallsyms['address'][i]
            linux_banner_fileoffset = vmlinux.find(b'Linux version ')
            if linux_banner_fileoffset:
                _startaddr_from_banner = linux_banner_addr - linux_banner_fileoffset

        elif kallsyms['name'][i] == '__lookup_processor_type_data':
            lookup_processor_addr = kallsyms['address'][i]

            step = kallsyms['arch'] // 8
            if kallsyms['arch'] == 32:
                addr_base = 0xC0008000
            else:
                addr_base = 0xffffffc000080000

            for i in range(0, 0x100000, step):
                _startaddr_from_processor = addr_base + i
                fileoffset = lookup_processor_addr - _startaddr_from_processor

                if fileoffset + step > len(vmlinux):
                    continue

                if lookup_processor_addr == INT(fileoffset, vmlinux, kallsyms):
                    break

            if _startaddr_from_processor == _startaddr_from_processor + 0x100000:
                _startaddr_from_processor = 0

    if _startaddr_from_banner:
        kallsyms['_start'] = _startaddr_from_banner
    elif _startaddr_from_processor:
        kallsyms['_start'] = _startaddr_from_processor
    elif _startaddr_from_xstext:
        kallsyms['_start'] = _startaddr_from_xstext

    if kallsyms[
            'arch'] == 64 and _startaddr_from_banner != _startaddr_from_xstext:
        kallsyms['_start'] = 0xffffffc000000000 + INT(8, vmlinux, kallsyms)

    if kallsyms['arch'] == 64:
        log.debug('[+] kallsyms_guess_start_addresses = %#x %#x %#x %#x',
                  0xffffffc000000000 + INT(8, vmlinux, kallsyms),
                  _startaddr_from_xstext, _startaddr_from_banner,
                  _startaddr_from_processor)
    else:
        log.debug('[+] kallsyms_guess_start_addresses = %#x %#x %#x',
                  _startaddr_from_xstext, _startaddr_from_banner,
                  _startaddr_from_processor)

    return kallsyms['_start']


def do_address_table(kallsyms, offset, vmlinux):
    step = kallsyms['arch'] // 8
    if kallsyms['arch'] == 32:
        addr_base = 0xC0000000
    else:
        addr_base = 0xffffffc000000000

    kallsyms['address'] = []
    for i in range(offset, len(vmlinux), step):
        addr = INT(i, vmlinux, kallsyms)
        if addr < addr_base:
            return (i - offset) // step
        else:
            kallsyms['address'].append(addr)

    return 0


def do_kallsyms(kallsyms, vmlinux):
    step = kallsyms['arch'] // 8

    offset = 0
    vmlen = len(vmlinux)
    while offset + step < vmlen:
        num = do_address_table(kallsyms, offset, vmlinux)
        if num > 10000:
            off_tmp = offset + num * step
            off_tmp = STRIPZERO(off_tmp, vmlinux, kallsyms, step)
            num_tmp = INT(off_tmp, vmlinux, kallsyms)
            if abs(num - num_tmp) <= 128:
                kallsyms['numsyms'] = num
                break
            else:
                offset += (num + 1) * step
        else:
            offset += (num + 1) * step

    if kallsyms['numsyms'] == 0:
        log.error('[!] lookup_address_table error...')
        return

    kallsyms['address_table'] = offset
    log.debug('[+] kallsyms_address_table = %#x', offset)

    offset += kallsyms['numsyms'] * step
    offset = STRIPZERO(offset, vmlinux, kallsyms, step)
    num = INT(offset, vmlinux, kallsyms)
    offset += step

    log.debug('[+] kallsyms_num = %x %x', kallsyms['numsyms'], num)
    if abs(num - kallsyms['numsyms']) > 128:
        kallsyms['numsyms'] = 0
        log.error('[!] not equal, maybe error...')
        return

    if num > kallsyms['numsyms']:
        for i in range(kallsyms['numsyms'], num):
            kallsyms['address'].insert(0, 0)
        kallsyms['numsyms'] = num

    offset = STRIPZERO(offset, vmlinux, kallsyms)
    do_name_table(kallsyms, offset, vmlinux)
    do_guess_start_address(kallsyms, vmlinux)
    return


########################
## Exported functions ##
########################


def do_get_arch(vmlinux):

    if not os.path.isdir('cache'):
        os.mkdir('cache')
    cache_file = os.path.join('cache', md5sumhex(vmlinux))
    cache_file += '.arch'
    arch = read_json(cache_file)
    if arch is not None:
        log.debug('get arch from cache')
        return arch

    def fuzzy_arm64(vmlinux):
        step = 8
        offset = 0
        vmlen = len(vmlinux) - len(vmlinux) % 8
        addr_base = 0xffffffc000000000
        while offset + step < vmlen:
            for i in range(offset, vmlen, step):
                if INT64(i, vmlinux) < addr_base:
                    addrnum = (i - offset) // step
                    if addrnum > 10000:
                        return True
                    else:
                        offset = i + step
        return False

    if re.search(b'ARMd', vmlinux[:0x200]):
        arch = 64
    elif fuzzy_arm64(vmlinux):
        arch = 64
    else:
        arch = 32

    log.debug('[+] kallsyms_arch = %s', arch)
    write_json(cache_file, arch)
    return arch


def extract_kallsyms(image, arch, system_map=None):
    '''extract kallsyms from kernel image'''
    if not os.path.isdir('cache'):
        os.mkdir('cache')
    cache_file = os.path.join('cache', md5sumhex(image))
    rebase_cache_file = cache_file + '.rebase'
    symbol_cache_file = cache_file + '.symbol'
    try:
        rebase = read_json(rebase_cache_file)
        symbol = read_json(symbol_cache_file)
        if rebase is not None and symbol is not None:
            log.debug('get rebase & symbol from cache')
            return rebase, symbol
    except ValueError:
        log.debug('failed to load cache')

    if system_map is None:
        kallsyms = {
            'arch': arch,
            '_start': 0,
            'numsyms': 0,
            'address': [],
            'type': [],
            'name': [],
            'address_table': 0,
            'name_table': 0,
            'type_table': 0,
            'token_table': 0,
            'table_index_table': 0,
        }
        try:
            do_kallsyms(kallsyms, image)
        except Exception as err:
            raise KallsymsError(err)
        if kallsyms['numsyms'] <= 0:
            raise KallsymsError('num <= 0')
    else:
        if isinstance(system_map, (str, bytes)):
            sym_list = sorted(
                [s.split(' ') for s in read(system_map).strip().split('\n')])
            sym_list = [x for x in sym_list if x[0]]
        else:
            sym_list = system_map
        kallsyms = {
            'arch': 32,
            'numsyms': len(sym_list),
            'address': [int(x[0], 16) for x in sym_list],
            'type': [x[1] for x in sym_list],
            'name': [x[2] for x in sym_list],
        }
        do_guess_start_address(kallsyms, image)

    rebase, symbol = kallsyms['_start'], [
        dict(
            address=kallsyms['address'][i],
            type=kallsyms['type'][i],
            name=kallsyms['name'][i].split('.', 1)[0])
        for i in range(kallsyms['numsyms'])
    ]
    write_json(rebase_cache_file, rebase)
    write_json(symbol_cache_file, symbol)
    return rebase, symbol


##########
## Main ##
##########


def main():
    parser = argparse.ArgumentParser(
        description='Extract symbol from kernel image.')
    parser.add_argument('image', help='kernel image')
    args = parser.parse_args()

    image = read(args.image, mode='rb')
    arch = do_get_arch(image)
    rebase, kallsyms = extract_kallsyms(image, arch)
    print('kernel base address: {:#x}'.format(rebase))
    for sym in kallsyms:
        print('{0[address]:x} {0[type]:s} {0[name]:s}'.format(sym))


if __name__ == '__main__':
    main()
