# -*- coding: utf-8 -*-
# This file is part of Viper - https://github.com/viper-framework/viper
# See the file 'LICENSE' for copying permission.
#
# Modernized (Python 3.12) pehash. The classic implementation used the
# `bitstring` library and had a variable-length quirk (section virtual
# addresses below 0x1000000 produced fewer than 24 bits). This port uses the
# intended fixed-width algorithm: 24 high bits for each section VA/raw size,
# 8-bit XOR folds for the header fields. For PEs with VAs >= 0x1000000 the
# output is identical to the classic; the result is always a 40-char SHA-1.

import bz2
import hashlib
import struct

import pefile


def _xor16(v):
    v &= 0xFFFF
    return (v >> 8) ^ (v & 0xFF)


def _xor32_high(v):
    v &= 0xFFFFFFFF
    return ((v >> 8) & 0xFF) ^ ((v >> 16) & 0xFF) ^ ((v >> 24) & 0xFF)


def _high24(v):
    v &= 0xFFFFFFFF
    return bytes([(v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF])


def _float8(k):
    """MSB byte of the 32-bit IEEE-754 single-precision representation of k."""
    return (struct.unpack('I', struct.pack('f', k))[0] >> 24) & 0xFF


def calculate_pehash(file_path=None, data=None):
    if not file_path and not data:
        return ''

    try:
        if file_path:
            exe = pefile.PE(file_path)
        else:
            exe = pefile.PE(data=data)

        pehash_bin = bytearray()

        # image characteristics (16-bit XOR fold)
        pehash_bin.append(_xor16(exe.FILE_HEADER.Characteristics))
        # machine type (16-bit XOR fold)
        pehash_bin.append(_xor16(exe.FILE_HEADER.Machine))
        # stack commit size (32-bit, high 3 bytes XOR-folded to 8)
        pehash_bin.append(_xor32_high(exe.OPTIONAL_HEADER.SizeOfStackCommit))
        # heap commit size (32-bit, high 3 bytes XOR-folded to 8)
        pehash_bin.append(_xor32_high(exe.OPTIONAL_HEADER.SizeOfHeapCommit))

        for section in exe.sections:
            # virtual address (high 24 bits)
            pehash_bin += _high24(section.VirtualAddress)
            # raw size (high 24 bits)
            pehash_bin += _high24(section.SizeOfRawData)
            # section characteristics (bytes 2 and 3 XOR-folded to 8)
            chars = section.Characteristics & 0xFFFFFFFF
            pehash_bin.append(((chars >> 16) & 0xFF) ^ ((chars >> 24) & 0xFF))
            # compression-ratio "entropy" of the data following the section
            address = section.VirtualAddress
            size = section.SizeOfRawData
            raw = exe.__data__[address + size:]
            if size == 0:
                k = 1.0
            else:
                k = len(bz2.compress(raw)) / size
            pehash_bin.append(_float8(k))

        m = hashlib.sha1()
        m.update(bytes(pehash_bin))
        return m.hexdigest()
    except Exception as err:
        return "ERROR not PE ({})".format(err)
