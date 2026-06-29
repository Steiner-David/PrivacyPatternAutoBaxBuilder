import ast
import re


def _contains_name(code: str | None, name: str) -> bool:
    return re.search(rf"\b{re.escape(name)}\b", code or "") is not None


def _imports_name_from_module(header_code: str, module: str, name: str) -> bool:
    try:
        tree = ast.parse(header_code or "")
    except SyntaxError:
        pattern = (
            rf"from\s+{re.escape(module)}\s+import\s+"
            rf"(?:[^\n#]*\b{re.escape(name)}\b|[^\n#]*\*)"
        )
        return re.search(pattern, header_code or "") is not None

    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or node.module != module:
            continue
        for alias in node.names:
            if alias.name in {name, "*"} or alias.asname == name:
                return True
    return False


def ensure_import_line(header_code: str, import_line: str) -> str:
    """Insert an import into generated header code without breaking future imports."""
    header_code = header_code or ""
    import_line = import_line.rstrip()
    if not import_line or import_line in header_code.splitlines():
        return header_code

    lines = header_code.splitlines()
    insert_at = 0
    while insert_at < len(lines):
        stripped = lines[insert_at].strip()
        if stripped and not stripped.startswith("#"):
            break
        insert_at += 1

    try:
        tree = ast.parse(header_code)
    except SyntaxError:
        tree = None
    if tree and tree.body:
        first_node = tree.body[0]
        if (
            isinstance(first_node, ast.Expr)
            and isinstance(first_node.value, ast.Constant)
            and isinstance(first_node.value.value, str)
            and first_node.end_lineno is not None
        ):
            insert_at = max(insert_at, first_node.end_lineno)

    while insert_at < len(lines):
        stripped = lines[insert_at].strip()
        if not stripped or stripped.startswith("#"):
            insert_at += 1
            continue
        if stripped.startswith("from __future__ import "):
            insert_at += 1
            continue
        break

    lines.insert(insert_at, import_line)
    result = "\n".join(lines)
    if header_code.endswith("\n"):
        result += "\n"
    return result


def ensure_generated_test_runtime_imports(
    header_code: str, *code_blocks: str | None
) -> str:
    """Ensure generated tests can evaluate their runtime type annotations."""
    all_code = "\n".join([header_code or "", *[block or "" for block in code_blocks]])
    required_imports = {
        "AppInstance": ("scenarios.base", "from scenarios.base import AppInstance"),
        "PrivacyPattern": (
            "privacy_patterns",
            "from privacy_patterns import PrivacyPattern",
        ),
    }
    for name, (module, import_line) in required_imports.items():
        if _contains_name(all_code, name) and not _imports_name_from_module(
            header_code, module, name
        ):
            header_code = ensure_import_line(header_code, import_line)
    return header_code
