import re
from typing import Any

from pydantic import BaseModel
from rustbininfo import Crate

from rusthelper.extra_info import get_executable_rustc_version, get_rustc_commit, guess_dependencies

DOC_RS_URL: str = "https://docs.rs/crate/"
RAW_GH_URL: str = "https://raw.githubusercontent.com/rust-lang/rust/"
GH_URL: str = "https://github.com/rust-lang/rust/"


def sub_idx(a, b):
    r = a - b
    if r < 0:
        return 0

    return r


# class Crate(BaseModel):
#     name: str
#     version: str

#     @classmethod
#     def from_depstring(cls, dep_str: str) -> "Crate":
#         try:
#             name, version = dep_str.rsplit("-", 1)
#             obj = cls(
#                 name=name,
#                 version=str(semver.Version.parse(version)),
#             )

#         except:  # noqa E722
#             name, version, patch = dep_str.rsplit("-", 2)
#             version += f"-{patch}"
#             obj = cls(
#                 name=name,
#                 version=str(semver.Version.parse(version)),
#             )

#         return obj

#     def __str__(self):
#         if self.version:
#             return f"{self.name}-{self.version}"

#         return f"{self.name}"

#     def __hash__(self):
#         return hash((self.name, self.version))


class RustSourcePathTransformer:
    _rustc_version: str | None = None
    _rustc_commit: str | None = None
    _particle: str | None = None

    def __init__(
        self,
        particle: str,
        rustc_version: str | None = None,
        rustc_commit: str | None = None,
        crate: Crate | None = None,
    ):
        self._particle = particle
        self._rustc_version = rustc_version
        self._rustc_commit = rustc_commit
        self._crate = crate

    @classmethod
    def from_panic_string(cls, executable: bytes, panic_str: str):
        deps = guess_dependencies(panic_str.encode("utf-8"))
        is_native = not bool(deps)

        if is_native:
            return cls._from_native(panic_str, executable)

        return cls._from_dep(panic_str)

    @classmethod
    def _from_native(cls, panic_str: str, executable: bytes):
        # /rustc/f6e511eec7342f59a25f7c0534f1dbea00d01b14/library/core/src/str/pattern.rs
        is_full_path = "rustc" in panic_str

        if is_full_path:
            len_to_path = len("/rustc/") + 40
            particle = panic_str[len_to_path:]

        # core/src/str/pattern.rs
        else:
            particle = (
                "/library/" + panic_str[panic_str.index("/library/") + len("/library/") :]
                if not panic_str.startswith("library") and "/library/" in panic_str
                else panic_str
            )

            particle = particle.replace("//", "/")

        _rustc_version = get_executable_rustc_version(executable)
        _rustc_commit = get_rustc_commit(executable)
        _particle = particle
        return cls(
            _particle,
            _rustc_version.decode() if _rustc_version else "",
            _rustc_commit.decode() if _rustc_commit else "",
            None,
        )

    @classmethod
    def _from_dep(cls, panic_str: str):
        dep = guess_dependencies(panic_str.encode("utf-8")).pop().decode()
        _crate = Crate.from_depstring(dep)
        _particle = re.sub(rf"^.*?{dep}", "", panic_str)
        return cls(_particle, None, None, _crate)

    def _get_version(self) -> str:
        if self._rustc_version:
            return self._rustc_version

        return self._rustc_commit

    def is_native(self):
        return not self._crate

    def get_url(self) -> str:
        if self.is_native():
            return self._urljoin(RAW_GH_URL, *[self._get_version(), self._particle])

        return self._urljoin(
            DOC_RS_URL,
            *[f"{self._crate.name}/", f"{self._crate.version}/", "source/", self._particle],
        )

    def get_viewable_url(self) -> str:
        url = self.get_url()
        if self.is_native():
            return url.replace(RAW_GH_URL, GH_URL).replace("/rust/", "/rust/blob/")

        return url

    def _urljoin(self, base: str, *parts: str) -> str:
        for part in filter(None, parts):
            base = "{}/{}".format(base.rstrip("/"), part.lstrip("/"))
        return base

    @classmethod
    def cls_get_viewable_url(cls, url: str, line: int | None = None) -> str:
        if RAW_GH_URL in url:
            url = url.replace(RAW_GH_URL, GH_URL).replace("/rust/", "/rust/blob/")

        if not line:
            return url

        if GH_URL in url:
            url += f"#L{line}"

        elif DOC_RS_URL in url:
            url += f"#{line}"

        return url


class RustFunction(BaseModel):
    name: str
    text: str
    start: int
    end: int
    return_type: str | None = None
    params: list = ()
    parent: Any | None = None
    macro: bool = False

    def _repr_macro(self) -> str:
        return f"{self.name}!{''.join(self.params)}"

    def __str__(self) -> str:
        if self.macro:
            return self._repr_macro()

        return f"fn {self.name}{''.join(self.params)}{' -> ' if self.return_type else ''}{self.return_type if self.return_type else ''}"

    def get_idx_repr(self, index: int, A: int = 7, B: int = 5) -> str:
        if not (self.start <= index <= self.end):
            raise ValueError

        idx = index - self.start
        lines = self.text.splitlines()
        s = ""
        start = sub_idx(idx, B)

        for i, line in enumerate(lines[start : idx + A]):
            line_nb = i + start + self.start
            panic_str = "PANIC -->"
            prepand = f"{line_nb: 4d}" + (len(panic_str) - len(f"{line_nb: 4d}")) * " "
            if line_nb == index:
                s += panic_str + line + "\n"

            else:
                s += prepand + line + "\n"

        if idx - B < 0:
            s += f"\n\t{' ' * len(panic_str)}...\n"

        if idx + A > len(lines):
            s = f"\t{' ' * len(panic_str)}...\n" + s

        return s


class RawPanicInfo(BaseModel):
    struct_addr: int
    line: int
    col: int
    panic_string: str

    def to_PanicInfo(self, ref, path) -> "PanicInfo":
        base_args = dict(self)
        return PanicInfo(
            **base_args,
            ref=ref,
            path=path,
        )


class PanicInfo(RawPanicInfo):
    ref: int
    path: str

    def as_key(self) -> str:
        return f"{self.crate}-{self.path}-{self.line}"

    def short_str(self) -> str:
        s = f"{self.path} (line {self.line})\n"
        return s

    def to_PanicInfoSource(self) -> "PanicInfoSource":
        base_args = dict(self)
        return PanicInfoSource(**base_args)

    def to_PanicInfoDep(self, f: RustFunction, url: str, crate: Crate) -> "PanicInfoDep":
        base_args = dict(self)
        return PanicInfoDep(
            **base_args,
            f=f,
            url=url,
            crate=crate,
        )

    def to_PanicInfoStdlib(self, f: RustFunction, url: str) -> "PanicInfoStdlib":
        base_args = dict(self)
        return PanicInfoStdlib(
            **base_args,
            f=f,
            url=url,
        )


class PanicInfoStdlib(PanicInfo):
    f: RustFunction
    url: str

    def __str__(self):
        s = ""
        c_name = "rust_stdlib"
        s += f"Fetched from {RustSourcePathTransformer.cls_get_viewable_url(self.url, self.line)}\n"

        path = self.path.replace("/", "::").replace("\\", "::")
        s += f"{self.f.get_idx_repr(self.line)}\n"

        if self.f.parent:
            parent = f"{self.f.parent.impl}{' for ' + self.f.parent.impl_for if self.f.parent.impl_for else ''}"
            s += f"{parent}::{self.f.name}\n"

        s += f"({c_name} {path}) {self.f}\n"

        return s

    def short_str(self) -> str:
        s = ""
        if not self.f:
            return f"{self.path} (line {self.line})"

        if self.f.parent:
            path = self.path.replace("/", "::").replace("\\", "::")
            parent = f"{self.f.parent.impl}{' for ' + self.f.parent.impl_for if self.f.parent.impl_for else ''}"
            s += f"{parent}::{self.f.name}\n"
        else:
            s += f"{self.f.name}\n"
        return s


class PanicInfoDep(PanicInfo):
    """Panic info from a dependency.

    This usually looks like /Users/user/.cargo/registry/src/index.crates.io-xxxx/block-buffer-0.11.2/src/lib.rs.
    """

    f: RustFunction
    url: str
    crate: Crate

    def __str__(self) -> str:
        s = ""
        c_name = self.crate.name
        s += f"Fetched from {RustSourcePathTransformer.cls_get_viewable_url(self.url, self.line)}\n"

        path = self.path.replace("/", "::").replace("\\", "::")
        s += f"{self.f.get_idx_repr(self.line)}\n"

        if self.f.parent:
            parent = f"{self.f.parent.impl}{' for ' + self.f.parent.impl_for if self.f.parent.impl_for else ''}"
            s += f"{parent}::{self.f.name}\n"

        s += f"({c_name}{path}) {self.f}\n"

        return s

    def short_str(self) -> str:
        s = ""
        if not self.f:
            return f"{self.path} (line {self.line})"

        if self.f.parent:
            path = self.path.replace("/", "::").replace("\\", "::")
            parent = f"{self.f.parent.impl}{' for ' + self.f.parent.impl_for if self.f.parent.impl_for else ''}"
            s += f"{parent}::{self.f.name}\n"
        else:
            s += f"{self.f.name}\n"
        return s


class PanicInfoSource(PanicInfo):
    """Panic info representing source code.

    This usually are src/main.rs panics, or other panic that is not rust stdlib or a dependency.
    """

    def __str__(self):
        s = ""
        s += f"{self.path} (line {self.line})\n"

        return s

    @classmethod
    def from_raw_panic_info(cls, ref: int, panic_struct: RawPanicInfo) -> "PanicInfoSource":
        cls(
            line=panic_struct.line,
            col=panic_struct.col,
            ref=ref,
        )


class Data(BaseModel):
    ea: int = 0
    name: str = ""
    tags: list[PanicInfo] = []

    def __hash__(self):
        return hash((self.name, "".join([str(t) for t in self.tags])))
