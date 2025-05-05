import re


def guess_dependencies(content: bytes) -> set:
    regexes = [
        # "/index.crates.io-6f17d22bba15001f/rayon-core-1.12.1/src/job.rs
        rb"index.crates.io.[^\\\/]+.([a-zA-Z0-9_-]+-[a-zA-Z0-9._-]+)",
        # \registry\src\github.com-1ecc6299db9ec823\aho-corasick-0.7.15\src\ahocorasick.rs
        rb"registry.src.[^\\\/]+.([a-zA-Z0-9_-]+-[a-zA-Z0-9._-]+)",
        # /rust/deps\indexmap-2.2.6\src\map\core.rs
        rb"rust.deps.([a-zA-Z0-9_-]+-[a-zA-Z0-9._-]+)",
        # crate-1.0.0\src\lib.rs
        rb"\x00([a-z0-9_-]+-[a-zA-Z0-9._-]+)[\\/][a-z]",
    ]
    result = set()
    for reg in regexes:
        res = re.findall(reg, content)
        result.update(res)

    return result


def get_rustc_commit(panic_string: bytes) -> bytes | None:
    """Find and returns rustc commit of a given rust panic string.

    Args:
        panic_string (pathlib.Path): str

    Returns:
        str | None: None if no rustc commit could be found.

    """
    res = re.search(b"rustc/([a-z0-9]{40})", panic_string)

    if res is None:
        return None

    return res.group(1)


def get_executable_rustc_version(executable: bytes) -> str | None:
    if getattr(get_executable_rustc_version, "path", None):
        return getattr(get_executable_rustc_version, "path", None)

    path = get_rustc_commit(executable)
    get_executable_rustc_version.path = path
    return path
