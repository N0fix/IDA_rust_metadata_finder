import pathlib
from typing import Any

import ida_allins
import ida_bytes
import ida_funcs
import ida_hexrays
import ida_typeinf
import idaapi
import idautils
import idc
from ida_segment import get_segm_name, get_segm_qty, getnseg
from idaapi import PluginForm
from idautils import XrefsTo
from pydantic import BaseModel
from PyQt5 import QtCore, QtGui
from PyQt5.QtWidgets import QTreeView, QVBoxLayout

from rusthelper.model import PanicInfoDep, PanicInfoSource, PanicInfoStdlib

from .generic import Segment, Tool


class IDASegment(Segment):
    _seg: Any
    start: int
    end: int
    content: bytes

    def __init__(self, segm):
        self._seg = segm
        if self.is_16bit():
            self.size_of_ptr = 2
            self.read_ptr = ida_bytes.get_word

        if self.is_32bit():
            self.size_of_ptr = 4
            self.read_ptr = ida_bytes.get_dword

        if self.is_64bit():
            self.size_of_ptr = 8
            self.read_ptr = ida_bytes.get_qword

        self.start = segm.start_ea
        self.end = segm.start_ea + segm.size()
        self.content = ida_bytes.get_bytes(self.start, segm.size())

    def read_ptr(self, *args, **kwargs):
        if self.is_16bit():
            return ida_bytes.get_word(*args)

        if self.is_32bit():
            return ida_bytes.get_dword(*args)

        if self.is_64bit():
            return ida_bytes.get_qword(*args)

    def is_16bit(self):
        return self._seg.is_16bit()

    def is_32bit(self):
        return self._seg.is_32bit()

    def is_64bit(self):
        return self._seg.is_64bit()


class IDAImpl(Tool):
    def get_word(self, address: int) -> int:
        return ida_bytes.get_word(address)

    def get_dword(self, address: int) -> int:
        return ida_bytes.get_dword(address)

    def get_qword(self, address: int) -> int:
        return ida_bytes.get_qword(address)

    def get_bytes(self, address: int, size: int) -> int:
        return ida_bytes.get_bytes(address, size)

    def set_type(self, address: int, type_name: str) -> None:
        idc.apply_type(address, idc.parse_decl(type_name, 0), 0)

    def set_name(self, address: int, name: str) -> None:
        idc.set_name(address, name, idc.SN_NOCHECK | idc.SN_NOWARN)

    def register_type(self, c_typedef: str, type_name: str) -> None:
        t = ida_typeinf.tinfo_t()
        ida_typeinf.parse_decl(t, None, c_typedef, 0)
        ida_typeinf.save_tinfo(t, None, 0, type_name, ida_typeinf.NTF_COPY | ida_typeinf.NTF_TYPE)

    def register_types(self, decls: str):
        idaapi.parse_decls(None, decls, None, idaapi.convert_pt_flags_to_hti(idaapi.PT_TYP))

    def get_segments(self) -> list[IDASegment]:
        return [IDASegment(getnseg(n)) for n in range(get_segm_qty())]

    def get_segment(self, name) -> IDASegment | None:
        segments = self.get_segments()
        return next(iter([s for s in segments if self.get_segment_name(s) == name]), None)

    def get_segment_name(self, segment: IDASegment) -> str:
        return get_segm_name(segment._seg)

    def get_xrefs(self, ea: int) -> list[int]:
        return [x.frm for x in XrefsTo(ea)]

    def set_cmt(self, address: int, cmt: str, decomp: bool = True) -> bool:
        idc.set_cmt(address, cmt, 0)
        if not decomp:
            return False

        # https://hex-rays.com/blog/coordinate-system-for-hex-rays
        def _try_cmt_hexrays(cmt_address: int, cmt: str) -> bool:
            cfunc = ida_hexrays.decompile(cmt_address)
            if not cfunc:
                return False

            tl = ida_hexrays.treeloc_t()
            tl.ea = cmt_address
            tl.itp = ida_hexrays.ITP_BLOCK1
            cfunc.set_user_cmt(tl, cmt)
            cfunc.save_user_cmts()
            unused = cfunc.__str__()
            if cfunc.has_orphan_cmts():
                cfunc.del_orphan_cmts()
                return False

            return True

        # Get next call not far from instruction
        for i, ea in enumerate(idautils.Heads(address)):
            if i == 20:
                return False

            insn = idaapi.insn_t()
            length = idaapi.decode_insn(insn, ea)

            if _try_cmt_hexrays(insn.ea, cmt):
                return True

            if insn.itype == ida_allins.NN_call:
                break

        return False

    def get_fn(self, address: int) -> Any:
        return ida_funcs.get_func(address)

    def get_fn_name(self, address: int) -> str:
        return ida_funcs.get_func_name(address)

    def get_executable_filepath(self) -> pathlib.Path:
        return pathlib.Path(idc.get_input_file_path())

    def get_executable_as_bytes(self) -> bytes:
        if getattr(self, f"{self.get_executable_filepath()}_content", None):
            return getattr(self, f"{self.get_executable_filepath()}_content")

        setattr(self, f"{self.get_executable_filepath()}_content", self.get_executable_filepath().read_bytes())
        return getattr(self, f"{self.get_executable_filepath()}_content")

    def get_ptrsize(self):
        info = idaapi.get_inf_structure()
        ptr_size = None
        if info.is_64bit():
            ptr_size = 8
        elif info.is_32bit():
            ptr_size = 4
        return ptr_size


def inf_is_64bit():
    return (idaapi.inf_is_64bit if idaapi.IDA_SDK_VERSION >= 900 else idaapi.cvar.inf.is_64bit)()


def get_addr_width():
    return "16" if inf_is_64bit() else "8"


class ListEntry(BaseModel):
    parts: list[Any]


class FolderList(BaseModel):
    title: str
    elements: list[ListEntry]


class ListView(BaseModel):
    cols: list[str]
    lines: list[FolderList]


class PlugView(PluginForm):
    ADDR_ROLE = QtCore.Qt.UserRole + 1

    def __init__(self, data: ListView):
        super(PlugView, self).__init__()
        self._data = data

    def OnCreate(self, form):
        """Called when the widget is created"""
        # Get parent widget
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

    def PopulateForm(self):
        # Create layout
        layout = QVBoxLayout()

        self.tv = QTreeView()
        self.tv.setExpandsOnDoubleClick(False)
        self.tv.doubleClicked.connect(self.on_navigate_to_method_requested)

        root_layout = QVBoxLayout(self.parent)

        root_layout.addWidget(self.tv)

        # make our created layout the dialogs layout
        self.parent.setLayout(root_layout)

        self._model = QtGui.QStandardItemModel()
        self._init_model()
        self.tv.setModel(self._model)

        self.tv.setColumnWidth(0, 200)
        self.tv.setColumnWidth(1, 300)
        self.tv.header().setStretchLastSection(True)

        self.tv.expandAll()

    def on_navigate_to_method_requested(self, index):
        addr = index.data(role=self.ADDR_ROLE)
        print(self.ADDR_ROLE, addr)
        if isinstance(addr, int) and addr is not None:
            idaapi.jumpto(addr)

        if isinstance(addr, str):
            idaapi.jumpto(idaapi.get_name_ea(0, addr))

    def _tv_init_header(self, model):
        for idx, col in enumerate(self._data.cols):
            item_header = QtGui.QStandardItem(col)
            model.setHorizontalHeaderItem(idx, item_header)

    def _tv_make_tag_item(self, fl: FolderList):
        rv = QtGui.QStandardItem(fl.title)

        rv.setEditable(False)
        return [rv, QtGui.QStandardItem(), QtGui.QStandardItem()]

    def _tv_make_ref_item(self, entry: ListEntry):
        items = []
        for ent in entry.parts:
            name = hex(ent) if isinstance(ent, int) else str(ent)
            item = QtGui.QStandardItem(name)
            item.setEditable(False)
            item.setData(ent, self.ADDR_ROLE)
            items.append(item)

        return items

    def _init_model(self):
        self._model.clear()

        root_node = self._model.invisibleRootItem()
        self._tv_init_header(self._model)
        for line in self._data.lines:
            item_tag_list = self._tv_make_tag_item(line)
            item_tag = item_tag_list[0]
            root_node.appendRow(item_tag_list)
            for elem in line.elements:
                item_tag.appendRow(self._tv_make_ref_item(elem))

    def OnClose(self, form):
        """Called when the widget is closed"""


def format_for_GUI(_data) -> ListView:
    d = {}
    for address, data in _data.items():
        for t in data.tags:
            if isinstance(t, PanicInfoStdlib):
                title_name = "[RUST STDLIB]"

            elif isinstance(t, PanicInfoDep):
                title_name = str(t.crate)

            elif isinstance(t, PanicInfoSource):
                title_name = t.path

            else:
                title_name = f"UNKN type {t}, {t.path}, {type(t)}"

            if d.get(title_name) is None:
                d[title_name] = set()

            d[title_name].add((address, data))

    lv = ListView(cols=["Address", "Function", "Panics"], lines=set())
    for key in sorted(d):
        fl = FolderList(title=key, elements=[])

        for ref in d[key]:
            address, data = ref
            tag_set = set()
            for l in data.tags:
                tag_set.add(l.short_str().strip())

            final_refs = ", ".join(tag_set)
            fl.elements.append(
                ListEntry(
                    parts=[data.ea, data.name, final_refs],
                ),
            )

        lv.lines.append(fl)

    return lv


# class RetypeHandler(idaapi.action_handler_t):
#     def __init__(self):
#         idaapi.action_handler_t.__init__(self)

#     def activate(self, ctx):
#         # vdui = ida_hexrays.open_pseudocode(here(), ida_hexrays.OPF_REUSE);
#         vdui = ida_hexrays.get_widget_vdui(ctx.widget)
#         lv = vdui.item.it.to_specific_type.get_v()
#         if lv is None:
#             print("item was none", vdui.item.get_lvar())
#             lv = vdui.item.get_lvar()

#         else:
#             lv = lv.getv()
#         print(f"Retyping {lv.name} to Result<{lv.type()}>")
#         t = ida_typeinf.tinfo_t()
#         result_type = self._create_type(str(lv.type()))
#         if result_type is None:
#             return
#         found_type = t.get_named_type(None, result_type)
#         if not found_type:
#             print("Type not found")
#             return

#         vdui.set_lvar_type(lv, t)

#     # This action is always available.
#     def update(self, ctx):
#         return idaapi.AST_ENABLE_ALWAYS

# PLUGIN_NAME = "ARustHelper"

# # Add context menu actions
# class ContextMenuHooks(idaapi.UI_Hooks):
#     def finish_populating_widget_popup(self, form, popup):
#         idaapi.attach_action_to_popup(form, popup, RustHelper.retype_action_name, "%s/" % (PLUGIN_NAME))

# class RustHelper(idaapi.plugin_t):
#     retype_action_name = "%s:Retype to Result<T>" % (PLUGIN_NAME)
#     retype_menu_path = "Edit/%s/" % (PLUGIN_NAME)
#     wanted_name = PLUGIN_NAME
#     wanted_hotkey = ""
#     comment = "%s Plugin for IDA" % (PLUGIN_NAME)
#     menu = None
#     flags = 0

#     def init(self):
#         # Check whether the decompiler is available
#         if not ida_hexrays.init_hexrays_plugin():
#             print("Decompiler not available")
#             return idaapi.PLUGIN_SKIP
#         # Variable renaming action
#         retype_action = idaapi.action_desc_t(
#             self.retype_action_name,
#             "Retype to Result<T>",
#             RetypeResultHandler(),
#             "SHIFT+ALT+R",
#             "Tooltip",
#         )
#         idaapi.register_action(retype_action)
#         idaapi.attach_action_to_menu(self.retype_menu_path, self.retype_action_name, idaapi.SETMENU_APP)

#         self.menu = ContextMenuHooks()
#         self.menu.hook()
#         # self.set_types()
#         print("Plugin rdy")
#         return idaapi.PLUGIN_KEEP

# def term(self):
#     idaapi.detach_action_from_menu(self.retype_menu_path, self.retype_action_name)
#     if self.menu:
#         self.menu.unhook()
