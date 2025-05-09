import pathlib
import re

import httpx
from bs4 import BeautifulSoup
from rustbininfo import Crate
from xdg_base_dirs import xdg_data_home

from rusthelper.caching_mod import cache


def html_decode(s):
    """Returns the ASCII decoded version of the given HTML string. This does
    NOT remove normal HTML tags like <p>.
    """
    htmlCodes = (
        ("'", "&#39;"),
        ('"', "&quot;"),
        (">", "&gt;"),
        ("<", "&lt;"),
        ("&", "&amp;"),
    )
    for code in htmlCodes:
        s = s.replace(code[1], code[0])
    return s


def get_request(url: str) -> str:
    result = httpx.get(url)
    if result.status_code != 200:
        raise ValueError

    return result.text


def _get_rust_code_from_docsrs(url: str) -> str:
    try:
        r = get_request(url)

    except ValueError:
        print(f"WARNING: no response from {url}")
        return ""

    if not r:
        return ""

    try:
        soup = BeautifulSoup(r, "html.parser")
        extracted = str(soup.find_all("code")[1])[len("<code>") : -len("</code>")]

        extracted = re.sub(r"<span [\s\S]*?>", "", extracted)
        extracted = re.sub(r"</span>", "", extracted)

        unescaped = html_decode(extracted)
        return unescaped

    except IndexError as e:
        print(f"Failed to parse {e}")
        return ""


def _get_rust_code_from_raw_github(url: str) -> str:
    try:
        return get_request(url)

    except ValueError:
        print(f"WARNING: no response from {url}")
        return ""


# @cache.cache()
# def fetch_source_code(url: str) -> str:
# return _get_rust_code_from_docsrs(url)


def fetch_source_code(crate: Crate, particle: str) -> str:
    cache_dir = pathlib.Path(xdg_data_home()) / "metadata_fetcher"
    cache_dir.mkdir(exist_ok=True)
    expected_path = pathlib.Path(cache_dir / f"{crate}")
    archive = pathlib.Path(f"{expected_path}.tar.gz")
    if not archive.exists():
        print("Downloading ", crate)
        try:
            expected_path = crate.download_untar(destination_directory=cache_dir)

        except:
            import shutil

            shutil.rmtree(expected_path)

    return pathlib.Path(f"{expected_path}/{particle}").read_text()


@cache.cache()
def fetch_native_source_code(url: str) -> str:
    return _get_rust_code_from_raw_github(url)
