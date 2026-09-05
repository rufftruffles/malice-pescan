# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pescan
# See the file 'LICENSE' for copying permission.
#
# Modernized (Python 3.12) Authenticode signature analysis. The classic engine
# used the `signify` library (dead: depends on pycrypto v2.7a1). This port uses
# `asn1crypto` (pure-Python, maintained) to parse the PKCS#7 SignedData /
# X.509 certificate table and a pure-Python PKCS#1 v1.5 RSA verification.
#
# The result shape matches the classic `signature` object:
#   {"heuristic": "..."}  or  {"error": "..."}
#   plus, when a certificate table is present:
#   {"certs": [{"signer": [{...}], "other": [{...}]}]}
# where each cert is {cert_version, cert_serial_no, cert_issuer, cert_subject,
# cert_valid_from, cert_valid_to}.
#
# Heuristics (matching the classic strings):
#   - "MZ header not found"                          (not a PE at all)
#   - "No file signature data found"                 (PE, no cert table)
#   - "Signature data found in PE but doesn't match
#      the program data. ..."                        (authenti-hash mismatch)
#   - "signature verification failed"                (RSA check failed)
#   - "This PE appears is self-signed"               (signer issuer == subject)
#   - "This PE appears to have a legitimate signature"

import hashlib

import pefile
from asn1crypto import cms

# DER DigestInfo AlgorithmIdentifier prefixes for common hash algorithms.
_DIGEST_INFO = {
    'md5': b'\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10',
    'sha1': b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14',
    'sha256': b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20',
    'sha384': b'\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30',
    'sha512': b'\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40',
}

# X.500 attribute name -> short DN token.
_RDN_SHORT = {
    'common_name': 'CN',
    'surname': 'SN',
    'serial_number': 'SERIALNUMBER',
    'country_name': 'C',
    'locality_name': 'L',
    'state_or_province_name': 'ST',
    'street_address': 'STREET',
    'organization_name': 'O',
    'organizational_unit_name': 'OU',
    'title': 'TITLE',
    'dn_qualifier': 'DNQ',
    'postal_code': 'POSTALCODE',
    'email_address': 'EMAIL',
    'domain_component': 'DC',
}


def _name_to_dn(name):
    """Format an asn1crypto x509.Name as a readable 'CN=...,O=...' string."""
    nat = name.native
    parts = []
    for k, v in nat.items():
        short = _RDN_SHORT.get(k, k.upper())
        if isinstance(v, (list, tuple)):
            v = ','.join(str(x) for x in v)
        parts.append('%s=%s' % (short, v))
    return ','.join(parts)


def _sec_table(pe, data):
    """Return (file_offset, table_bytes) of the certificate table, or (None, None)."""
    sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # IMAGE_DIRECTORY_ENTRY_SECURITY
    if not sec.Size or not sec.VirtualAddress:
        return None, None
    off = sec.VirtualAddress  # for the security dir this is a file offset
    return off, data[off:off + sec.Size]


def _sec_entry_offset(pe):
    """File offset of the 8-byte security data-directory entry."""
    magic = pe.OPTIONAL_HEADER.Magic
    data_dir_off = 96 if magic == 0x10b else 112  # PE32 vs PE32+
    return pe.DOS_HEADER.e_lfanew + 24 + data_dir_off + 4 * 8


def authenticode_hash(data, pe, algo):
    """Authenti-hash: hash the file skipping the security dir entry + cert table."""
    off, table = _sec_table(pe, data)
    entry_off = _sec_entry_offset(pe)
    h = hashlib.new(algo)
    h.update(data[:entry_off])
    h.update(data[entry_off + 8:off])
    h.update(data[off + len(table):])
    return h.digest()


def _rsa_verify(modulus, exponent, sig, data, algo):
    """Verify a PKCS#1 v1.5 RSA signature over `data` using hash `algo`.

    Returns True/False, or None if the digest algorithm is unsupported.
    """
    di = _DIGEST_INFO.get(algo)
    if di is None:
        return None
    h = hashlib.new(algo)
    h.update(data)
    digest_info = di + h.digest()
    k = (modulus.bit_length() + 7) // 8
    sig_int = int.from_bytes(sig, 'big')
    m = pow(sig_int, exponent, modulus)
    em = m.to_bytes(k, 'big')
    if em[0] != 0 or em[1] != 1:
        return False
    i = 2
    while i < len(em) and em[i] == 0xFF:
        i += 1
    if i >= len(em) - 1 or em[i] != 0:
        return False
    return em[i + 1:] == digest_info


def _cert_info(cert):
    tbs = cert['tbs_certificate']
    return {
        'cert_version': tbs['version'].native,
        'cert_serial_no': str(tbs['serial_number'].native),
        'cert_issuer': _name_to_dn(tbs['issuer']),
        'cert_subject': _name_to_dn(tbs['subject']),
        'cert_valid_from': str(tbs['validity']['not_before'].native),
        'cert_valid_to': str(tbs['validity']['not_after'].native),
    }


def get_signature(file_path):
    data = open(file_path, 'rb').read()
    sig = {}

    # Not a PE at all (matches the classic signify "MZ header not found").
    if len(data) < 2 or data[0:2] != b'MZ':
        sig['error'] = 'MZ header not found'
        return sig

    try:
        pe = pefile.PE(data=data)
    except pefile.PEFormatError as e:
        sig['error'] = str(e)
        return sig

    off, table = _sec_table(pe, data)
    if table is None:
        sig['heuristic'] = 'No file signature data found'
        return sig

    try:
        # Skip the 8-byte WIN_CERTIFICATE header to reach the PKCS#7 ContentInfo.
        ci = cms.ContentInfo.load(table[8:])
        sd = ci['content']
    except Exception as e:
        sig['error'] = 'failed to parse certificate table: %s' % e
        return sig

    # Collect the X.509 certificates.
    certs = []
    for c in sd['certificates']:
        if c.name == 'certificate':
            certs.append(c.chosen)
    if not certs:
        sig['error'] = 'no certificates found in signature'
        return sig

    algo = sd['digest_algorithms'][0]['algorithm'].native

    # spc_message_digest (the stored authenti-hash) + signer serial.
    spc_digest = None
    signer_serial = None
    for si in sd['signer_infos']:
        sid = si['sid']
        if sid.name == 'issuer_and_serial_number':
            signer_serial = sid.chosen['serial_number'].native
        sa = si['signed_attrs']
        if sa is not None:
            for attr in sa:
                if 'message_digest' in attr['type'].native:
                    spc_digest = attr['values'][0].native

    # Identify the signer certificate by serial (fall back to the first cert).
    signer = None
    for cert in certs:
        if cert['tbs_certificate']['serial_number'].native == signer_serial:
            signer = cert
            break
    if signer is None:
        signer = certs[0]
    others = [c for c in certs if c is not signer]
    certs_block = [{'signer': [_cert_info(signer)],
                    'other': [_cert_info(c) for c in others]}]

    # 1. Authenticode hash check (detects copied/tampered signatures).
    try:
        computed = authenticode_hash(data, pe, algo)
    except Exception as e:
        sig['error'] = 'failed to compute authenticode hash: %s' % e
        return sig
    if spc_digest is not None and computed != spc_digest:
        sig['heuristic'] = (
            "Signature data found in PE but doesn't match the program data. "
            "This is either due to malicious copying of signature data or an error in transmission.")
        sig['certs'] = certs_block
        return sig

    # 2. RSA signature verification over the signed attributes.
    tbs = signer['tbs_certificate']
    spki = tbs['subject_public_key_info']
    if spki['algorithm'].native != 'rsa':
        sig['error'] = 'unsupported signature algorithm: %s' % spki['algorithm'].native
        return sig
    modulus = spki['public_key']['modulus'].native
    exponent = spki['public_key']['public_exponent'].native

    si = list(sd['signer_infos'])[0]
    signed_attrs = si['signed_attrs']
    if signed_attrs is None:
        sig['error'] = 'signed attributes missing (cannot verify)'
        return sig
    ok = _rsa_verify(modulus, exponent, si['signature'].native,
                     signed_attrs.dump(), algo)
    if ok is None:
        sig['error'] = 'unsupported digest algo: %s' % algo
        return sig
    if not ok:
        sig['error'] = 'signature verification failed'
        return sig

    # 3. Self-signed vs legitimate.
    if str(tbs['issuer'].native) == str(tbs['subject'].native):
        sig['heuristic'] = 'This PE appears is self-signed'
    else:
        sig['heuristic'] = 'This PE appears to have a legitimate signature'
    sig['certs'] = certs_block
    return sig
