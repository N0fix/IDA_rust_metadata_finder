import contextlib
import ctypes
from dataclasses import dataclass

from construct import ExprAdapter, ExprValidator, GreedyBytes, Int32ul, Int64ul, Struct, ValidationError

from rusthelper.impl.generic import Segment, Tool
from rusthelper.impl.ida_impl import (
    IDAImpl,
    PlugView,  # RustHelper
    format_for_GUI,
)
from rusthelper.model import (
    Data,
    PanicInfo,
    PanicInfoDep,
    PanicInfoSource,
    PanicInfoStdlib,
    RawPanicInfo,
    RustSourcePathTransformer,
)
from rusthelper.rust_doc_fetcher import fetch_native_source_code, fetch_source_code
from rusthelper.rust_parser import RustFunction, parse_rust_source
from rusthelper.utils import slugify

dis = IDAImpl()


def get_string(dis, addr, sz):
    sz = ctypes.c_long(sz).value
    if sz > 0xFFFF or sz < 8:
        return None

    with contextlib.suppress(UnicodeDecodeError):
        if b := dis.get_bytes(addr, sz):
            return b.decode("utf-8")

    return None


panic_struct_parser = Struct(
    "str_addr" / ExprValidator(Int64ul if dis.get_ptrsize() == 8 else Int32ul, lambda obj_, _: obj_ > 0x1000),  # noqa: PLR2004
    "str_len" / ExprValidator(Int64ul if dis.get_ptrsize() == 8 else Int32ul, lambda obj_, _: 0 <= obj_ < 0xFFFF),  # noqa: PLR2004
    "line" / ExprValidator(Int32ul, lambda obj_, _: 0 < obj_ < 0xFFFF),  # noqa: PLR2004
    "col" / ExprValidator(Int32ul, lambda obj_, _: 0 < obj_ < 0xFFFF),  # noqa: PLR2004
    "panic_string"
    / ExprValidator(
        ExprAdapter(
            GreedyBytes,
            decoder=lambda _, context: get_string(dis, context.str_addr, context.str_len),
            encoder=None,
        ),
        lambda obj_, _: obj_ is not None,
    ),
)


@dataclass
class RustStringSlice:
    content: str
    size: int

    @classmethod
    def type_name(cls) -> str:
        return "RustStringSlice"

    @classmethod
    def type_repr(cls) -> str:
        return rf"""
typedef struct _RustStringSlice
{{
    char* address;
    {"int64_t" if dis.get_ptrsize() == 8 else "int32_t"} length;
}} RustStringSlice;
"""


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


def determine_col_line_order(panic_locations: list[RustPanicLocation]):
    if len(panic_locations) == 0:
        return

    col_greater_than_line = 0
    for panic_loc in panic_locations:
        if panic_loc.col > panic_loc.line:
            col_greater_than_line += 1

    if col_greater_than_line >= len(panic_locations) // 2:
        print("Warning: Cols and lines are reversed")  # Should never happen


def get_rust_func_from_source(source_code: str, line: int) -> RustFunction | None:
    funcs, impls, macros = parse_rust_source(source_code.encode())
    all_funcs = funcs + macros

    for impl in impls:
        all_funcs += impl.fns

    for fn in all_funcs:
        try:
            # print(fn.start, fn.end, fn.name)
            if not (fn.start <= line <= fn.end):
                continue

            return fn

        except ValueError:
            pass

    return None


def get_associated_fn(code: str, line: int) -> RustFunction | None:
    fn: RustFunction | None = get_rust_func_from_source(code, line)
    return fn


def get_panic_info_from_raw(panic_struct: RawPanicInfo) -> list[PanicInfo]:
    panic_info_list: list[PanicInfo] = []

    for ref in dis.get_xrefs(panic_struct.struct_addr):
        rust_string = panic_struct.panic_string.replace("\\", "/")
        panic_info_list.extend(
            [
                panic_struct.to_PanicInfo(ref=ref, path=rust_string),
            ],
        )

    return panic_info_list


def specialize_panic_info(panic_infos: list[PanicInfo]) -> list[PanicInfoDep | PanicInfoSource | PanicInfoStdlib]:
    res: list[PanicInfoDep | PanicInfoSource | PanicInfoStdlib] = []

    for info in panic_infos:
        rpt = RustSourcePathTransformer.from_panic_string(dis.get_executable_as_bytes(), info.path)

        # e.g src/main.rs
        if info.path.startswith(("src", "/src")):
            res.append(info.to_PanicInfoSource())
            continue

        info.path = rpt._particle
        url = rpt.get_url()

        if not rpt.is_native():
            if f := get_associated_fn(fetch_source_code(url), info.line):
                res.append(info.to_PanicInfoDep(f, url, rpt._crate))

        elif f := get_associated_fn(fetch_native_source_code(url), info.line):
            res.append(info.to_PanicInfoStdlib(f, url))

        else:
            print(f"WARNING: no function matched. Context: {info=}")
            print(f"See {rpt.get_viewable_url()}#L{info.line}")
            print(f"Was native? {rpt.is_native()}")
    return res


def find_panic_location_in_segm(segment: Segment) -> list[RawPanicInfo]:
    """Find panic info structures in a segment.

    Args:
        segment (Segment): Segment to search.

    Returns:
        list[RawPanicInfo]: Panic info structs.

    """
    panic_locations: list[RawPanicInfo] = []
    size_of_panic_struct = 24 if dis.get_ptrsize() == 8 else 16

    for i in range(segment.start, segment.end - size_of_panic_struct, 4):
        start_off = i - segment.start
        with contextlib.suppress(ValidationError):
            res = panic_struct_parser.parse(segment.content[start_off : start_off + size_of_panic_struct])
            panic_locations.extend(
                [RawPanicInfo(struct_addr=i, line=res.line, col=res.col, panic_string=str(res.panic_string))],
            )

    return panic_locations


def parse_panic_structs_from_exe(dis: Tool) -> list[RawPanicInfo]:
    """Find panic info structures in the executable.

    Args:
        dis (Tool): Disassembler tool wrapper.

    Returns:
        list[RawPanicInfo]: Panic info structs.

    """
    segments: list[Segment] = dis.get_segments()
    high_probability_segments: list[Segment] = [
        s for s in [dis.get_segment(".rdata"), dis.get_segment(".data.rel.ro")] if s is not None
    ]
    locs = []
    for seg in high_probability_segments:
        locs: list[RawPanicInfo] = find_panic_location_in_segm(seg)
        if len(locs) > 10:
            return locs

    # If not found in high probability segments, iterate over all segments
    for n in range(len(segments)):
        locs.extend(find_panic_location_in_segm(segments[n]))

    return locs


def rename_panics(dis: Tool, panic_structs: list[RawPanicInfo]) -> None:
    """Rename panic structs in disassembly.

    Args:
        dis (Tool): Disassembler wrapper.
        panic_structs (list[RawPanicInfo]): Panic structs.

    Usage:
        >>> panic_structs: list[Struct] = parse_panic_structs_from_exe(dis)
        >>> rename_panics(panic_structs)

    """
    for panic in panic_structs:
        slugged_panic = slugify(f"CORE_PANIC_LOCATION___{panic.panic_string}_{panic.line}_{panic.col}")
        dis.set_name(panic.struct_addr, slugged_panic)


def retype_panics(dis: Tool, panic_structs: list[RawPanicInfo]) -> None:
    """Retype panic structs in disassembly.

    Args:
        dis (Tool): Disassembler wrapper.
        panic_structs (list[RawPanicInfo]): Panic structs.

    Usage:
        >>> panic_structs: list[Struct] = parse_panic_structs_from_exe(dis)
        >>> retype_panics(panic_structs)

    """
    dis.register_type(RustStringSlice.type_repr(), RustStringSlice.type_name())
    dis.register_type(RustPanicLocation.type_repr(), RustPanicLocation.type_name())

    for panic in panic_structs:
        dis.set_type(panic.struct_addr, f"struct {RustPanicLocation.type_name()};")


def comment_locations(dis: Tool, locs: list[PanicInfo]) -> None:
    """Put a comment in disassembler or decompiler code.

    Args:
        dis (Tool): Disassembler wrapper.
        locs (list[PanicInfo]): List of panic info.

    """
    for l in locs:
        if not dis.set_cmt(l.ref, str(l)):
            print(f"Could not set comment on {l.ref:x}")


def show_menu(dis: Tool, locs: list[PanicInfo]):
    data = {}
    for l in locs:
        fn = dis.get_fn(l.ref)

        if fn is None:
            continue

        if data.get(fn.start_ea, None) is None:
            data[fn.start_ea] = Data(ea=fn.start_ea, name=dis.get_fn_name(fn.start_ea))

        data[fn.start_ea].tags.extend([l])

    data = format_for_GUI(data)
    plg = PlugView(data)
    plg.Show("Rust panic info")


class RustMetadataFinder:
    def run(self):
        panic_info: list[PanicInfo] = self.get_panic_info()
        print(f"Got {len(panic_info)} entries before spe")
        specialized_info = specialize_panic_info(panic_info)

        comment_locations(dis, specialized_info)
        show_menu(dis, specialized_info)

    def get_panic_info(self) -> list[PanicInfo]:
        panic_structs: list[Struct] = parse_panic_structs_from_exe(dis)
        rename_panics(dis, panic_structs)
        retype_panics(dis, panic_structs)

        panic_info: list[PanicInfo] = []
        for p in panic_structs:
            panic_info.extend(get_panic_info_from_raw(p))

        return panic_info


if __name__ == "__main__":
    r = RustMetadataFinder()
    r.run()
