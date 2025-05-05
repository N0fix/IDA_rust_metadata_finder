import pathlib
from dataclasses import dataclass

import tree_sitter_rust as tsrust
from tree_sitter import Language, Node, Parser, Tree

from rusthelper.model import RustFunction


@dataclass
class RustImpl:
    impl: str
    impl_for: None | str
    fns: list[RustFunction]

    def __str__(self) -> str:
        s = f"impl {self.impl}{' for ' + self.impl_for if self.impl_for else ''}\n"
        for f in self.fns:
            s += f"\t{f}\n"
        # s += f'fn {self.name}{"".join(self.params)}{" -> " if self.return_type else ""}{self.return_type if self.return_type else ""}'
        return s

    @classmethod
    def from_node(cls, node):
        fns = []
        impl, impl_for = None, None

        scope_ident = [c for c in node.children if c.type == "scoped_type_identifier"]
        identifier = [c for c in node.children if c.type == "type_identifier"]
        f = None
        i = None
        if identifier:
            if len(identifier) > 1:
                f = identifier[1].text.decode()

            elif scope_ident:
                i = scope_ident[0].text.decode()
                f = identifier[0].text.decode()

            else:
                i = identifier[0].text.decode()

        for_clause = [c for c in node.children if c.type == "generic_type"]
        if for_clause:
            f = for_clause[0].text.decode()

        if i and f:
            impl = i
            impl_for = f

        if i and not f:
            impl = i
            impl_for = None

        if not i and f:
            impl = f
            impl_for = None

        for child in node.named_children:
            if child.type == "declaration_list":
                for l in child.named_children:
                    if l.type == "function_item":
                        func = get_fn(l)
                        func.parent = cls(impl, impl_for, [])  # f"impl {impl}{' for ' + impl_for if impl_for else ''}"
                        fns.append(func)

        return cls(impl, impl_for, fns)


def get_fn(node) -> RustFunction:
    params = []
    name = ""
    text = node.text.decode().replace("\t", "  ")
    return_type = None
    return_types = list(node.children_by_field_name("return_type"))
    if return_types:
        return_type = next(iter(return_types)).text.decode()

    for fn_node in node.children:
        if fn_node.type == "identifier":
            name = fn_node.text.decode()

        elif fn_node.type == "parameters":
            params.append(fn_node.text.decode())

    return RustFunction(
        name=name,
        params=params,
        text=text,
        return_type=return_type,
        start=node.start_point.row + 1,
        end=node.end_point.row + 1,
        parent=None,
    )


def get_fn_from_defs(tree):
    f = []

    def traverse_tree(node: Node):
        for n in node.children:
            if n.is_named and n.type == "function_item":
                f.append(get_fn(n))
            traverse_tree(n)

    traverse_tree(tree.root_node)

    return f


def get_traits(tree):
    for node in tree.root_node.children:
        if node.type == "trait_item":
            for c in node.children:
                if c.type == "type_identifier":
                    trait_name = c.text.decode()

                elif c.type == "declaration_list":
                    for trait_fn in c.children:
                        if trait_fn.type == "function_item":
                            func = get_fn(trait_fn)
                            print(f"{trait_name}::{func}")

    exit(1)


def get_macros(tree) -> list[RustFunction]:
    result = []

    def extract_macro(node: Node):
        name = ""
        params = []
        parent = None
        for children in node.children:
            if children.type == "identifier":
                name = f"{children.text.decode()}"

            if children.type == "scoped_identifier":
                name = children.child_by_field_name("path").text.decode()
                name += "::" + children.child_by_field_name("name").text.decode()

            if children.type == "token_tree":
                # Shitty
                params.extend([children.text.decode()])

        return RustFunction(
            name=name,
            params=params,
            text=node.text,
            return_type="",
            start=node.start_point.row + 1,
            end=node.end_point.row + 1,
            parent=None,
            macro=True,
        )

    def traverse_tree(node: Node):
        for n in node.children:
            if n.type == "macro_invocation":
                result.extend([extract_macro(n)])
            traverse_tree(n)

    traverse_tree(tree.root_node)
    return result


def print_elem(node, type):
    identifier = [c for c in node.children if c.type == type]
    if identifier:
        for _ in identifier:
            print(_.text.decode())


def get_impl(tree) -> list[RustImpl]:
    implements = []
    enums = [node for node in tree.root_node.children if node.type == "impl_item"]
    for e in enums:
        implements.append(RustImpl.from_node(e))

    return implements


def get_functions(rust_source_code: str):
    lang = Language(tsrust.language())
    parser = Parser(lang)

    content = rust_source_code
    tree = parser.parse(content)
    return get_fn_from_defs(tree)


def parse_rust_source(rust_source_code: str) -> tuple[list[RustFunction], list[RustImpl], list[RustFunction]]:
    lang = Language(tsrust.language())
    parser = Parser(lang)

    content = rust_source_code
    tree: Tree = parser.parse(content)

    return get_fn_from_defs(tree), get_impl(tree), get_macros(tree)  # , get_traits(tree)


if __name__ == "__main__":
    import sys

    source = sys.argv[1]
    fns, impl, macros = parse_rust_source(pathlib.Path(source).read_bytes())
    print("fns")
    for f in fns:
        print(f)

    print("impl")
    for f in impl:
        print(f)

    print("macros")
    for m in macros:
        print(m)
