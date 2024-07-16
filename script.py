import ctypes
import re
import unicodedata
from dataclasses import dataclass
from typing import Callable, List

import ida_bytes
import ida_typeinf
from ida_segment import get_segm_name, get_segm_qty, getnseg
from idautils import Segments


def get_string_from_ptr(addr, sz, read_ptr):
    sz = ctypes.c_long(sz).value
    if sz > 0xFFFF or sz < 10:
         return None

    try:
        b = ida_bytes.get_bytes(read_ptr(addr), sz)
        return b.decode('utf-8')

    except:
        pass

    return None

def slugify(value, allow_unicode=False):
    """
    Taken from https://github.com/django/django/blob/master/django/utils/text.py
    Convert to ASCII if 'allow_unicode' is False. Convert spaces or repeated
    dashes to single dashes. Remove characters that aren't alphanumerics,
    underscores, or hyphens. Convert to lowercase. Also strip leading and
    trailing whitespace, dashes, and underscores.
    """
    value = str(value)
    if allow_unicode:
        value = unicodedata.normalize("NFKC", value)
    else:
        value = (
            unicodedata.normalize("NFKD", value)
            .encode("ascii", "ignore")
            .decode("ascii")
        )
    value = re.sub(r"[^\w\s-]", "_", value.lower())
    return re.sub(r"[-\s]+", "_", value).strip("-_")

@dataclass
class RustStringSlice:
    content: str
    size: int

    @classmethod
    def type_name(cls) -> str:
        return "RustStringSlice"

    @classmethod
    def type_repr(cls) -> str:
        return r'''
typedef struct _RustStringSlice
{
    char* address;
    int64_t length;
} RustStringSlice;
'''


@dataclass
class RustPanicLocation:
    file: RustStringSlice
    line: int
    col: int

    @classmethod
    def type_name(cls) -> str:
        return "CorePanicLocation"

    @classmethod
    def type_repr(cls) -> str:
        return r"""
typedef struct _CorePanicLocation
{
    RustStringSlice file;
    uint32_t line;
    uint32_t col;
} _CorePanicLocation;
"""

def determine_col_line_order(panic_locations: List[RustPanicLocation]):
    if len(panic_locations) == 0:
        return

    col_greater_than_line = 0
    for panic_loc in panic_locations:
        if panic_loc.col > panic_loc.line:
            col_greater_than_line += 1

    if col_greater_than_line >= len(panic_locations) // 2:
        print('Warning: Cols and lines are reversed')

def set_type(ea, type_str):
    apply_type(ea, parse_decl(type_str, 0)  , 0)

def find_panic_location_in_segm(get_segm_info: Callable) -> List[RustPanicLocation]:
    start, end, size_of_ptr, read_ptr = get_segm_info()
    panic_locations = []
    size_of_struct = size_of_ptr * 3
    for i in range(start, end - size_of_struct, 4):
        rust_string = get_string_from_ptr(i, read_ptr(i + size_of_ptr), read_ptr)
        if rust_string:
            line = ida_bytes.get_dword(i + size_of_ptr * 2)
            col = ida_bytes.get_dword(i + size_of_ptr * 2 + 4)
            if (line > 0 and line < 0xFFFF) and (col > 0 and col < 0xFFFF):
                print(hex(i), rust_string, line, col, f'{slugify(f"CORE_PANIC_LOCATION___{rust_string}_{line}_{col}")}')
                set_name(i, slugify(f"CORE_PANIC_LOCATION___{rust_string}_{line}_{col}"), SN_NOCHECK | SN_NOWARN)
                panic_locations.append(
                    RustPanicLocation(rust_string, line, col)
                )
                set_type(i, f"struct {RustPanicLocation.type_name()};")

    determine_col_line_order(panic_locations)

    return panic_locations

def save_type(string: str, name: str):
    t = ida_typeinf.tinfo_t()
    ida_typeinf.parse_decl(t, None, string, 0)
    ida_typeinf.save_tinfo(t, None, 0, name, ida_typeinf.NTF_COPY | ida_typeinf.NTF_TYPE)

def get_segm_info(segm):
    if segm.is_16bit():
        size_of_ptr = 2
        read_ptr = ida_bytes.get_word

    if segm.is_32bit():
        size_of_ptr = 4
        read_ptr = ida_bytes.get_dword

    if segm.is_64bit():
        size_of_ptr = 8
        read_ptr = ida_bytes.get_qword

    start = segm.start_ea
    end = segm.start_ea + segm.size()

    return start, end, size_of_ptr, read_ptr

save_type(RustStringSlice.type_repr(), RustStringSlice.type_name())
save_type(RustPanicLocation.type_repr(), RustPanicLocation.type_name())

segments = [getnseg(n) for n in range(get_segm_qty())]
rdata_segment = next(iter([s for s in segments if get_segm_name(s) == '.rdata']), None)
rdata_exists = rdata_segment is not None

if rdata_exists:
    s = rdata_segment
    find_panic_location_in_segm(lambda: get_segm_info(s))

else:
    for n in range(get_segm_qty()):
        results = find_panic_location_in_segm(lambda: get_segm_info(getnseg(n)))
        if len(results) > 10:
            break
