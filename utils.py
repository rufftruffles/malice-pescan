# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pescan
# See the file 'LICENSE' for copying permission.
#
# Modernized (Python 3.12) helper utilities. Ported from the classic
# utils/__init__.py + utils/charset.py, dropping the Python-2-only
# `reload(sys)` / `unicode` shims and the chardet dependency (its result was
# never used).

import hashlib
import math
import os
from collections import Counter

import magic

ROOT = os.path.normpath(os.path.dirname(os.path.abspath(__file__)))


def get_type(data):
    """Return the libmagic description of a byte buffer ('' on failure)."""
    try:
        return magic.from_buffer(data)
    except Exception:
        return ''


def get_entropy(data):
    """Calculate the Shannon entropy of a chunk of data."""
    if len(data) == 0:
        return 0.0
    occurrences = Counter(bytearray(data))
    entropy = 0
    for x in occurrences.values():
        p_x = float(x) / len(data)
        entropy -= p_x * math.log(p_x, 2)
    return entropy


def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()


def get_md5(data):
    m = hashlib.md5()
    m.update(data)
    return m.hexdigest()


def get_sha256(data):
    s = hashlib.sha256()
    s.update(data)
    return s.hexdigest()


def safe_str(s):
    """Decode bytes to str defensively (pefile returns some fields as bytes)."""
    if isinstance(s, bytes):
        return s.decode('utf-8', errors='replace')
    return s


def json2markdown(json_data):
    """Convert the JSON result document to a Markdown table (jinja2)."""
    from jinja2 import Template
    with open(os.path.join(ROOT, 'markdown.jinja2')) as f:
        return Template(f.read()).render(exe=json_data)
