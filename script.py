import ctypes
import re
import unicodedata
from dataclasses import dataclass
from typing import Callable, List

from rustbininfo import Crate
from requests import get
import ida_bytes
import ida_typeinf
from ida_segment import get_segm_name, get_segm_qty, getnseg
from idautils import Segments

found_crates = {}
def _guess_dependencies(content: bytes):
    regexes = [
        rb"index.crates.io.[^\\\/]+.([^\\\/]+)",
        rb"registry.src.[^\\\/]+.([^\\\/]+)",
        rb"rust.deps.([^\\\/]+)",
    ]
    result = []
    for reg in regexes:
        res = re.findall(reg, content)
        if len(set(res)) > len(result):
            result = set(res)

    return result

def _guess_path(content: bytes) -> bytes:
    regexes = [
        rb"index.crates.io.[^\\\/]+.[^\\\/]+.([ -~]*\.rs)",
        rb"registry.src.[^\\\/]+.[^\\\/]+.([ -~]*\.rs)",
        rb"rust.deps.[^\\\/]+.([ -~]*\.rs)",
    ]
    result = []
    for reg in regexes:
        res = re.findall(reg, content)
        if len(res) != 0:
            return res[0]

    return result

def guess_url(s, line, col):
    github_url, fn_name, current_line = None, None, None
    dep_name_list = _guess_dependencies(s.encode())
    if not dep_name_list:
        return github_url, fn_name, current_line
    dep_name = dep_name_list.pop().decode()

    path = _guess_path(s.encode())
    if path:
        path = path.replace(b'\\', b'/').decode()

    c = Crate.from_depstring(dep_name)
    if str(c) not in found_crates.keys():

        c.metadata
        found_crates[str(c)] = None
        crate = c
        seeked_tags = [
            f"{crate.name}-{crate.version}",
            f"{crate.name}-v{crate.version}",
            f"{crate.name}_{crate.version}",
            f"{crate.name}_v{crate.version}",
            f"{crate.version}",
            f"v{crate.version}",
        ]

        for tag in seeked_tags:
            url = f'{c.repository.rstrip(".git")}/tree/{tag}/'
            res = get(url)
            if res.status_code == 200:
                found_crates[str(c)] = url
                break
        
    if found_crates[str(c)] is not None:
        # res = get(f'{url}/{path}')
        github_url = f'{found_crates[str(c)]}{path}/#L{line}'
        url = github_url
        url = f'{url}/{path}#L{line}'.replace('github.com', 'raw.githubusercontent.com').replace('/tree/', '/').replace('/blob/', '/')
        res = get(url)

        if res.status_code == 200:
            raw_url = url

            current_line = res.text.splitlines()[line-1]
            rule = rb'^\s*(pub)*(\(crate\))*\s*fn\s'
            for line in res.text.splitlines()[:line-1:-1]:
                if re.match(rule.decode(), line):
                    # print(line, current_line)
                    fn_name = line
                    break
        
    return (github_url, fn_name, current_line)
        
    

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
                # print(hex(i), rust_string, line, col, f'{slugify(f"CORE_PANIC_LOCATION___{rust_string}_{line}_{col}")}')
                github_url, fn_name, cur_line =  guess_url(rust_string, line, col)
                if github_url:
                    set_cmt(i, f'\n{github_url}\nFunction name: {fn_name}\nPanic line:{cur_line}', 0)
                    print(hex(i))
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


print(found_crates)