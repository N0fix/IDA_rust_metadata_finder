import pathlib
from abc import ABCMeta, abstractmethod
from typing import Any


class Segment(metaclass=ABCMeta):
    start: int
    end: int
    size_of_ptr: int

    @abstractmethod
    def read_ptr(self): ...

    @abstractmethod
    def is_16bit(self): ...

    @abstractmethod
    def is_32bit(self): ...

    @abstractmethod
    def is_64bit(self): ...


class Tool(metaclass=ABCMeta):
    @abstractmethod
    def get_word(self, address: int) -> int: ...

    @abstractmethod
    def get_dword(self, address: int) -> int: ...

    @abstractmethod
    def get_qword(self, address: int) -> int: ...

    @abstractmethod
    def get_bytes(self, address: int, size: int) -> int: ...

    @abstractmethod
    def set_type(self, address: int, type_name: str) -> None: ...

    @abstractmethod
    def set_name(self, address: int, name: str) -> None: ...

    @abstractmethod
    def register_type(self, c_typedef: str, type_name: str) -> None: ...

    @abstractmethod
    def get_segment(self, name: str) -> Segment | None: ...

    @abstractmethod
    def get_segments(self) -> list[Segment]: ...

    @abstractmethod
    def get_segment_name(self, segment: Segment) -> str: ...

    @abstractmethod
    def get_xrefs(self) -> list: ...

    @abstractmethod
    def set_cmt(self, address: int, cmt: str, decomp: bool) -> bool: ...

    @abstractmethod
    def get_fn(self, address: int) -> Any: ...

    @abstractmethod
    def get_fn_name(self, address: int) -> Any: ...

    @abstractmethod
    def get_executable_filepath(self) -> pathlib.Path: ...

    @abstractmethod
    def get_executable_as_bytes(self) -> bytes: ...
