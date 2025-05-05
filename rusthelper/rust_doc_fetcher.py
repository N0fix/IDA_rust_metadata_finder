import re

import httpx
from bs4 import BeautifulSoup

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


@cache.cache()
def fetch_source_code(url: str) -> str:
    return _get_rust_code_from_docsrs(url)


@cache.cache()
def fetch_native_source_code(url: str) -> str:
    return _get_rust_code_from_raw_github(url)
