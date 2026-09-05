# -*- coding: utf-8 -*-
# This file is part of MaliceIO - https://github.com/malice-plugins/pescan
# See the file 'LICENSE' for copying permission.
#
# Modernized (Python 3.12) PE analyzer. Ported from the classic
# malice/__init__.py (MalPEFile). The signature analysis moved to
# signature.py; everything else (info, debug, imports, exports, resources,
# version info, strings, imphash, compile time, PEiD, sections, language,
# pehash, entry point, slack space) is preserved with the same result keys.

import datetime
import logging
import re
import time
from collections.abc import Iterable
from os import path

import pefile
import peutils

from pehash import calculate_pehash
from utils import get_entropy, get_md5, get_sha256, get_type, safe_str, sha256_checksum
from lcid import LCID

log = logging.getLogger(__name__)


class MalPEFile(object):

    def __init__(self, file_path, peid_db_path, should_dump=False, dump_path=None):
        self.file = file_path
        self.sha256 = sha256_checksum(self.file)
        with open(file_path, 'rb') as fh:
            self.data = fh.read()
        self.peid_db = peid_db_path
        self.dump = None
        self.pe = None
        self.results = {}
        if not path.exists(self.file):
            raise Exception("file does not exist: {}".format(self.file))
        if should_dump:
            if path.isdir(dump_path):
                self.dump = dump_path
            else:
                log.error("folder does not exist: {}".format(dump_path))
                self.dump = None

    def info(self):
        info = {}
        if hasattr(self.pe, 'OriginalFilename'):
            info['original_filename'] = self.pe.OriginalFilename
        if hasattr(self.pe, 'FileDescription'):
            info['file_description'] = self.pe.FileDescription
        if hasattr(self.pe, 'OPTIONAL_HEADER'):
            info['image_base'] = self.pe.OPTIONAL_HEADER.ImageBase
            info['size_of_image'] = self.pe.OPTIONAL_HEADER.SizeOfImage
            info['linker_version'] = "{:02d}.{:02d}".format(
                self.pe.OPTIONAL_HEADER.MajorLinkerVersion,
                self.pe.OPTIONAL_HEADER.MinorLinkerVersion)
            info['os_version'] = "{:02d}.{:02d}".format(
                self.pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                self.pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)
            data = []
            for data_directory in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                if data_directory.Size or data_directory.VirtualAddress:
                    data.append({
                        'name': data_directory.name[len("IMAGE_DIRECTORY_ENTRY_"):],
                        'virtual_address': hex(data_directory.VirtualAddress),
                        'size': data_directory.Size
                    })
            self.results['data_directories'] = data
        if hasattr(self.pe, 'FILE_HEADER'):
            info['number_of_sections'] = self.pe.FILE_HEADER.NumberOfSections
            info['machine_type'] = "{} ({})".format(
                hex(self.pe.FILE_HEADER.Machine),
                pefile.MACHINE_TYPE.get(self.pe.FILE_HEADER.Machine, "UNKNOWN"))
        if hasattr(self.pe, 'RICH_HEADER') and self.pe.RICH_HEADER is not None:
            rich_header_info = []
            values_list = self.pe.RICH_HEADER.values
            for i in range(0, len(values_list) // 2):
                rich_header_info.append({
                    'tool_id': values_list[2 * i] >> 16,
                    'version': values_list[2 * i] & 0xFFFF,
                    'times used': values_list[2 * i + 1]
                })
            self.results['rich_header_info'] = rich_header_info
        self.results['info'] = info

    def debug(self):
        if hasattr(self.pe, 'DebugTimeDateStamp'):
            debug = {}
            debug['time_date_stamp'] = "%s" % time.ctime(self.pe.DebugTimeDateStamp)
            if hasattr(self.pe, 'pdb_filename') and self.pe.pdb_filename:
                debug['pdb_filename'] = safe_str(self.pe.pdb_filename)
            self.results['debug'] = debug

    def imports(self):
        imports = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT') and len(self.pe.DIRECTORY_ENTRY_IMPORT) > 0:
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                try:
                    dll = safe_str(entry.dll)
                    log.info("DLL: {0}".format(dll))
                    dlls = {dll: []}
                    for symbol in entry.imports:
                        name = safe_str(symbol.name)
                        dlls[dll].append(dict(address=hex(symbol.address), name=name))
                    imports.append(dlls)
                except Exception:
                    continue
        self.results['imports'] = imports

    def exports(self):
        exports = []
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT') and \
                self.pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp is not None:
            for symbol in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                exports.append(dict(
                    address=hex(self.pe.OPTIONAL_HEADER.ImageBase + symbol.address),
                    name=safe_str(symbol.name),
                    ordinal=symbol.ordinal))
            self.results['exports'] = exports

            # get export module name
            section = self.pe.get_section_by_rva(self.pe.DIRECTORY_ENTRY_EXPORT.struct.Name)
            offset = section.get_offset_from_rva(self.pe.DIRECTORY_ENTRY_EXPORT.struct.Name)
            self.pe.ModuleName = self.pe.__data__[offset:offset + self.pe.__data__[offset:].find(b'\x00')]
            self.results['exports_module_Name'] = safe_str(self.pe.ModuleName)
            self.results['exports_timestamp'] = time.ctime(self.pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp)

    def entrypoint(self):
        self.results['info']['entrypoint'] = hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    def compiletime(self):
        self.results['info']['compiletime'] = {
            'unix': self.pe.FILE_HEADER.TimeDateStamp,
            'datetime': '{}'.format(datetime.datetime.utcfromtimestamp(self.pe.FILE_HEADER.TimeDateStamp))
        }

    def peid(self):
        self.results['peid'] = []

        def get_signatures():
            with open(self.peid_db, 'rt', encoding='ISO-8859-1') as f:
                sig_data = f.read()
            return peutils.SignatureDatabase(data=sig_data)

        def get_matches(pe, signatures):
            return signatures.match_all(pe, ep_only=True)

        try:
            peid_matches = get_matches(self.pe, get_signatures())
        except Exception as e:
            log.error("PEiD matching failed: %s", e)
            peid_matches = None

        if peid_matches:
            for sig in peid_matches:
                if type(sig) is list:
                    self.results['peid'].append(sig[0])
                else:
                    self.results['peid'].append(sig)
        else:
            self.results['peid'].append("No PEiD signatures matched.")

    def resources(self):
        self.results['resources'] = []

        def get_resources(pe):
            resources = []
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                count = 1
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    try:
                        if resource_type.name is not None:
                            name = str(resource_type.name)
                        else:
                            name = str(pefile.RESOURCE_TYPE.get(resource_type.struct.Id, "UNKNOWN"))
                        if name is None:
                            name = str(resource_type.struct.Id)

                        if hasattr(resource_type, 'directory'):
                            for resource_id in resource_type.directory.entries:
                                if hasattr(resource_id, 'directory'):
                                    for resource_lang in resource_id.directory.entries:
                                        data = pe.get_data(resource_lang.data.struct.OffsetToData,
                                                           resource_lang.data.struct.Size)
                                        entropy = get_entropy(data)
                                        filetype = get_type(data)
                                        md5 = get_md5(data)
                                        sha256 = get_sha256(data)
                                        language = pefile.LANG.get(resource_lang.data.lang, None)
                                        language_desc = LCID.get(resource_lang.id, 'unknown language')
                                        sublanguage = pefile.get_sublang_name_for_lang(
                                            resource_lang.data.lang, resource_lang.data.sublang)
                                        offset = ('%-8s' % hex(resource_lang.data.struct.OffsetToData)).strip()
                                        size = ('%-8s' % hex(resource_lang.data.struct.Size)).strip()

                                        resource = [
                                            count, name, offset, md5, sha256, size, filetype, entropy, language,
                                            sublanguage, language_desc
                                        ]

                                        # Dump resources if requested
                                        if self.dump and pe == self.pe:
                                            folder = self.dump
                                            resource_path = path.join(
                                                folder, '{0}_{1}_{2}'.format(self.sha256, offset, name))
                                            resource.append(resource_path)
                                            with open(resource_path, 'wb') as resource_handle:
                                                resource_handle.write(data)

                                        resources.append(resource)
                                        count += 1
                    except Exception as e:
                        log.error(e)
                        continue
            return resources

        resources = get_resources(self.pe)
        if not resources:
            log.warning("No resources found")
            return

        for resource in resources:
            self.results['resources'].append({
                'id': resource[0],
                'name': resource[1],
                'offset': resource[2],
                'md5': resource[3],
                'sha256': resource[4],
                'size': resource[5],
                'type': resource[6],
                'entropy': resource[7],
                'language': resource[8],
                'sublanguage': resource[9],
                'language_desc': resource[10],
            })

    def resource_versioninfo(self):
        if hasattr(self.pe, 'FileInfo'):
            pe_resource_verinfo_res_list = []
            for file_info in self.pe.FileInfo:
                if not isinstance(file_info, Iterable):
                    file_info = [file_info]
                for info in file_info:
                    pe_resource_verinfo_res = {}
                    if info.name == "StringFileInfo":
                        if len(info.StringTable) > 0:
                            lang_id = "0"
                            try:
                                if "LangID" in info.StringTable[0].entries:
                                    lang_id = info.StringTable[0].get("LangID")
                                    if not int(lang_id, 16) >> 16 == 0:
                                        pe_resource_verinfo_res['lang_id'] = '{} ({})'.format(
                                            lang_id, LCID[int(lang_id, 16) >> 16])
                                    else:
                                        pe_resource_verinfo_res['lang_id'] = "{} (NEUTRAL)".format(lang_id)
                            except (ValueError, KeyError):
                                pe_resource_verinfo_res['lang_id'] = '{} is invalid'.format(lang_id)

                            for entry in info.StringTable[0].entries.items():
                                key = safe_str(entry[0])
                                if key == 'OriginalFilename':
                                    pe_resource_verinfo_res['original_filename'] = safe_str(entry[1])
                                elif key == 'FileDescription':
                                    pe_resource_verinfo_res['file_description'] = safe_str(entry[1])
                                else:
                                    if len(safe_str(entry[1])) > 0:
                                        pe_resource_verinfo_res[key.lower()] = safe_str(entry[1])
                        pe_resource_verinfo_res_list.append(pe_resource_verinfo_res)
            if len(pe_resource_verinfo_res_list) > 1:
                self.results['resource_versioninfo'] = pe_resource_verinfo_res_list
            else:
                self.results['resource_versioninfo'] = pe_resource_verinfo_res_list[0]

    def resource_strings(self):
        BYTE = 1
        WORD = 2
        DWORD = 4

        DS_SETFONT = 0x40

        DIALOG_LEAD = DWORD + DWORD + WORD + WORD + WORD + WORD + WORD
        DIALOG_ITEM_LEAD = DWORD + DWORD + WORD + WORD + WORD + WORD + WORD

        DIALOGEX_LEAD = WORD + WORD + DWORD + DWORD + DWORD + WORD + WORD + WORD + WORD + WORD
        DIALOGEX_TRAIL = WORD + WORD + BYTE + BYTE
        DIALOGEX_ITEM_LEAD = DWORD + DWORD + DWORD + WORD + WORD + WORD + WORD + DWORD
        DIALOGEX_ITEM_TRAIL = WORD

        ITEM_TYPES = {
            0x80: "BUTTON",
            0x81: "EDIT",
            0x82: "STATIC",
            0x83: "LIST BOX",
            0x84: "SCROLL BAR",
            0x85: "COMBO BOX"
        }

        if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            tags = []
            for dir_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if dir_type.name is None:
                    if dir_type.id in pefile.RESOURCE_TYPE:
                        dir_type.name = pefile.RESOURCE_TYPE[dir_type.id]
                for nameID in dir_type.directory.entries:
                    if nameID.name is None:
                        nameID.name = hex(nameID.id)
                    for language in nameID.directory.entries:
                        strings = []
                        if str(dir_type.name) == "RT_DIALOG":
                            data_rva = language.data.struct.OffsetToData
                            size = language.data.struct.Size
                            data = self.pe.get_memory_mapped_image()[data_rva:data_rva + size]

                            offset = 0
                            if self.pe.get_word_at_rva(data_rva + offset) == 0x1 \
                                    and self.pe.get_word_at_rva(data_rva + offset + WORD) == 0xFFFF:
                                # Use Extended Dialog Parsing
                                offset += DIALOGEX_LEAD
                                if data[offset:offset + 2] == b"\xFF\xFF":
                                    offset += DWORD
                                else:
                                    offset += WORD
                                if data[offset:offset + 2] == b"\xFF\xFF":
                                    offset += DWORD
                                else:
                                    offset += WORD

                                window_title = self.pe.get_string_u_at_rva(data_rva + offset)
                                if len(window_title) != 0:
                                    strings.append(("DIALOG_TITLE", window_title))
                                offset += len(window_title) * 2 + WORD

                                offset += DIALOGEX_TRAIL
                                offset += len(self.pe.get_string_u_at_rva(data_rva + offset)) * 2 + WORD

                                if (offset % 4) != 0:
                                    offset += WORD

                                while True:
                                    if offset >= size:
                                        break
                                    offset += DIALOGEX_ITEM_LEAD

                                    if self.pe.get_word_at_rva(data_rva + offset) == 0xFFFF:
                                        offset += WORD
                                        item_type = ITEM_TYPES[self.pe.get_word_at_rva(data_rva + offset)]
                                        offset += WORD
                                    else:
                                        item_type = self.pe.get_string_u_at_rva(data_rva + offset)
                                        offset += len(item_type) * 2 + WORD

                                    item_text = self.pe.get_string_u_at_rva(data_rva + offset)
                                    if len(item_text) != 0:
                                        strings.append((item_type, item_text))
                                    offset += len(item_text) * 2 + WORD

                                    extra_bytes = self.pe.get_word_at_rva(data_rva + offset)
                                    offset += extra_bytes + DIALOGEX_ITEM_TRAIL

                                    if (offset % 4) != 0:
                                        offset += WORD
                            else:
                                # Non-extended Dialog Parsing
                                style = self.pe.get_word_at_rva(data_rva + offset)

                                offset += DIALOG_LEAD
                                if data[offset:offset + 2] == b"\xFF\xFF":
                                    offset += DWORD
                                else:
                                    offset += len(self.pe.get_string_u_at_rva(data_rva + offset)) * 2 + WORD
                                if data[offset:offset + 2] == b"\xFF\xFF":
                                    offset += DWORD
                                else:
                                    offset += len(self.pe.get_string_u_at_rva(data_rva + offset)) * 2 + WORD

                                window_title = self.pe.get_string_u_at_rva(data_rva + offset)
                                if len(window_title) != 0:
                                    strings.append(("DIALOG_TITLE", window_title))
                                offset += len(window_title) * 2 + WORD

                                if (style & DS_SETFONT) != 0:
                                    offset += WORD
                                    offset += len(self.pe.get_string_u_at_rva(data_rva + offset)) * 2 + WORD

                                if (offset % 4) != 0:
                                    offset += WORD

                                while True:
                                    if offset >= size:
                                        break
                                    offset += DIALOG_ITEM_LEAD

                                    if self.pe.get_word_at_rva(data_rva + offset) == 0xFFFF:
                                        offset += WORD
                                        item_type = ITEM_TYPES[self.pe.get_word_at_rva(data_rva + offset)]
                                        offset += WORD
                                    else:
                                        item_type = self.pe.get_string_u_at_rva(data_rva + offset)
                                        offset += len(item_type) * 2 + WORD

                                    if self.pe.get_word_at_rva(data_rva + offset) == 0xFFFF:
                                        offset += DWORD
                                    else:
                                        item_text = self.pe.get_string_u_at_rva(data_rva + offset)
                                        if len(item_text) != 0:
                                            strings.append((item_type, item_text))
                                        offset += len(item_text) * 2 + WORD

                                    extra_bytes = self.pe.get_word_at_rva(data_rva + offset)
                                    offset += extra_bytes + WORD

                                    if (offset % 4) != 0:
                                        offset += WORD

                        elif str(dir_type.name) == "RT_STRING":
                            data_rva = language.data.struct.OffsetToData
                            size = language.data.struct.Size
                            data = self.pe.get_memory_mapped_image()[data_rva:data_rva + size]
                            offset = 0
                            while True:
                                if offset >= size:
                                    break
                                ustr_length = self.pe.get_word_from_data(data[offset:offset + 2], 0)
                                offset += 2
                                if ustr_length == 0:
                                    continue
                                ustr = self.pe.get_string_u_at_rva(data_rva + offset, max_length=ustr_length)
                                offset += ustr_length * 2
                                strings.append((None, ustr))

                        if len(strings) > 0:
                            success = False
                            try:
                                comment = "%s (id:%s - lang_id:0x%04X [%s])" % (
                                    str(dir_type.name), str(nameID.name), language.id, LCID[language.id])
                            except KeyError:
                                comment = "%s (id:%s - lang_id:0x%04X [Unknown language])" % (
                                    str(dir_type.name), str(nameID.name), language.id)
                            log.debug("PE: STRINGS - %s" % comment)
                            for idx in range(len(strings)):
                                try:
                                    tag_value = strings[idx][1]
                                    tag_value = tag_value.replace('\r', ' ').replace('\n', ' ')
                                    if strings[idx][0] is not None:
                                        tags.append(strings[idx][0])
                                    else:
                                        tags.append(tag_value)
                                    success = True
                                except Exception:
                                    pass
                            if success:
                                self.results['resource_strings'] = tags

    def slack_space(self):
        if 'calculated_file_size' in self.results.get('info', {}) \
                and self.results['info']['calculated_file_size'] > 0 \
                and (len(self.pe.__data__) > self.results['info']['calculated_file_size']):
            slack_size = len(self.pe.__data__) - self.results['info']['calculated_file_size']
            if self.dump:
                slack_path = path.join(self.dump, '{}_slack.bin'.format(self.sha256))
                with open(slack_path, 'wb') as shandle:
                    shandle.write(self.pe.__data__[
                        self.results['info']['calculated_file_size']:
                        self.results['info']['calculated_file_size'] + slack_size])

    def imphash(self):
        self.results['imphash'] = self.pe.get_imphash()

    def security(self):
        # The classic engine's Authenticode verification lived here but was
        # fully commented out (dead). Signature analysis is now in signature.py.
        pass

    def language(self):

        def get_iat(pe):
            iat = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for peimport in pe.DIRECTORY_ENTRY_IMPORT:
                    iat.append(safe_str(peimport.dll))
            return iat

        def check_module(iat, match):
            for imp in iat:
                if imp.find(match) != -1:
                    return True
            return False

        def is_cpp(data, cpp_count):
            for line in data:
                if b'type_info' in line or b'RTTI' in line:
                    cpp_count += 1
                    break
            if cpp_count == 2:
                return True
            return False

        def is_delphi(data):
            for line in data:
                if b'Borland' in line:
                    p = line.split(b'\\')
                    for pp in p:
                        if b'Delphi' in pp:
                            return True
            return False

        def is_vbdotnet(data):
            for line in data:
                if b'Compiler' in line:
                    stuff = line.split(b'.')
                    if b'VisualBasic' in stuff:
                        return True
            return False

        def is_autoit(data):
            for line in data:
                if b'AU3!' in line:
                    return True
            return False

        def is_packed(pe):
            for section in pe.sections:
                if section.get_entropy() > 7:
                    return True
            return False

        def get_strings(content):
            regexp = b'[\x30-\x39\x41-\x5f\x61-\x7a\-\.:]{4,}'
            return re.findall(regexp, content)

        def find_language(iat, sample, content):
            dotnet = False
            cpp_count = 0
            found = None

            if check_module(iat, 'VB'):
                log.info("{0} - Possible language: Visual Basic".format(sample))
                return 'Visual Basic'

            if check_module(iat, 'mscoree.dll') and not found:
                dotnet = True
                found = '.NET'

            if not found and (check_module(iat, 'msvcr') or check_module(iat, 'MSVCR') or check_module(iat, 'c++')):
                cpp_count += 1

            if not found:
                data = get_strings(content)
                if is_cpp(data, cpp_count) and not found:
                    found = 'CPP'
                if not found and cpp_count == 1:
                    found = 'C'
                if not dotnet and is_delphi(data) and not found:
                    found = 'Delphi'
                if dotnet and is_vbdotnet(data):
                    found = 'Visual Basic .NET'
                if is_autoit(data) and not found:
                    found = 'AutoIt'
            return found

        self.results['is_packed'] = is_packed(self.pe)
        if self.results['is_packed']:
            log.warning("Probably packed, the language guess might be unreliable")
        self.results['language'] = find_language(get_iat(self.pe), self.file, self.data)

    def sections(self):
        sections = []
        for section in self.pe.sections:
            section_name = safe_str(section.Name)
            section_name = section_name.replace('\x00', '')

            # calculated file size (running max over sections)
            self.results['info']['calculated_file_size'] = int(section.VirtualAddress) + int(section.Misc_VirtualSize)

            sections.append({
                'name': section_name,
                'rva': hex(section.VirtualAddress),
                'virtual_size': hex(section.Misc_VirtualSize),
                'pointer_to_raw_data': section.PointerToRawData,
                'raw_data_size': section.SizeOfRawData,
                'entropy': section.get_entropy(),
                'md5': section.get_hash_md5(),
            })
        self.results['sections'] = sections

    def pehash(self):
        self.results['pehash'] = calculate_pehash(self.file)

    def run(self):
        try:
            self.pe = pefile.PE(self.file)

            # run all the analysis
            self.info()
            self.debug()
            self.imports()
            self.exports()
            self.resources()
            self.resource_versioninfo()
            self.resource_strings()
            self.imphash()
            self.compiletime()
            self.peid()
            self.security()
            self.sections()
            self.language()
            self.pehash()
            self.entrypoint()
            self.slack_space()

        except pefile.PEFormatError as e:
            log.error("Unable to parse PE file: {0}".format(e))
            # A plain "not a PE" (no DOS magic) is a graceful no-op, matching
            # the classic engine; any other parse failure is reported.
            if getattr(e, 'value', str(e)) != "DOS Header magic not found.":
                self.results['error'] = "this file looks like a PE but failed loading inside PE file. [{}]".format(str(e))
        except Exception as e:
            log.exception(e)

        return self.results
