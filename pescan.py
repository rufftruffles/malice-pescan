#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pescan
# See the file 'LICENSE' for copying permission.
#
# Modernized (Python 3.12) Malice PE-executable Plugin analysis entry point.
# Invoked by the Go wrapper (scan.go):  python3 /app/pescan.py <file>
# Prints the result document (the exact plugins.exe.pescan shape the classic
# engine wrote, including the rendered markdown) as a single JSON object.
#
# The engine is fully defensive: it always emits valid JSON. A non-PE file
# yields a graceful {"signature": {"error": "MZ header not found"}, ...}
# result (matching the classic engine) rather than crashing.

import json
import logging
import os
import sys

from pe_analyzer import MalPEFile
from signature import get_signature
from utils import json2markdown

log = logging.getLogger(__name__)

PEID_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'peid', 'UserDB.TXT')


def _sanitize(obj):
    """Recursively convert bytes keys/values to str so the result is JSON-safe.

    pefile returns some fields (section names, StringTable keys, ...) as bytes;
    this is a safety net so the engine always emits valid JSON.
    """
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            nk = k.decode('utf-8', errors='replace') if isinstance(k, bytes) else k
            out[nk] = _sanitize(v)
        return out
    if isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    if isinstance(obj, (list, tuple)):
        return [_sanitize(x) for x in obj]
    return obj


def analyze(file_path):
    results = {}
    # signature first (matches the classic engine's ordering)
    try:
        results['signature'] = get_signature(file_path)
    except Exception as e:
        log.exception("signature analysis failed")
        results['signature'] = {'error': str(e)}

    # PE analysis (graceful on non-PE input)
    try:
        pe = MalPEFile(file_path, peid_db_path=PEID_DB)
        results.update(pe.run())
    except Exception as e:
        log.exception("PE analysis failed")
        results.setdefault('error', str(e))

    # clean any bytes fields before rendering/storing
    results = _sanitize(results)

    # markdown rendering (part of the stored document)
    try:
        results['markdown'] = json2markdown(results)
    except Exception as e:
        log.exception("failed to render jinja template")
        results['markdown'] = str(e)

    return results


def main():
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    if len(sys.argv) < 2:
        log.error("no file supplied")
        print(json.dumps({"error": "no file supplied"}))
        return 1

    file_path = sys.argv[1]
    if not os.path.exists(file_path):
        log.error("file does not exist: %s", file_path)
        print(json.dumps({"error": "file does not exist: %s" % file_path}))
        return 1

    results = analyze(file_path)
    print(json.dumps(results))
    return 0


if __name__ == '__main__':
    sys.exit(main())
