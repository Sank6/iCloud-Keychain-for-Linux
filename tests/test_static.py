"""Cheap static checks that catch whole classes of mistakes the behavioural tests can miss.

`undefined global` is the one that matters: a function that uses a name its module never imported
(`os.chmod` without `import os`) only fails when that line runs, which may be a rarely used path."""

import builtins
import dis
import importlib
import pkgutil
import types
from pathlib import Path

import pytest

import icp

ROOT = Path(icp.__file__).parent


def _modules():
    for info in pkgutil.walk_packages([str(ROOT)], prefix="icp."):
        if info.name.endswith("__main__"):
            continue
        yield info.name


def _code_objects(code):
    yield code
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            yield from _code_objects(const)


def _unresolved_globals(module) -> set[str]:
    path = Path(module.__file__)
    code = compile(path.read_text(), str(path), "exec")
    known = set(vars(module)) | set(dir(builtins))
    used = {ins.argval for co in _code_objects(code) for ins in dis.get_instructions(co)
            if ins.opname == "LOAD_GLOBAL"}
    return {name for name in used if name not in known}


@pytest.mark.parametrize("name", sorted(_modules()))
def test_no_function_uses_an_undefined_global(name):
    try:
        module = importlib.import_module(name)
    except ImportError as e:                       # an optional dependency (GTK, a display)
        pytest.skip(f"cannot import {name}: {e}")
    assert not _unresolved_globals(module), (
        f"{name} uses names it never defines or imports: {sorted(_unresolved_globals(module))}")


def test_the_checker_itself_catches_the_bug_it_exists_for(tmp_path, monkeypatch):
    src = tmp_path / "broken_mod.py"
    src.write_text("def f():\n    return os.getcwd()\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    module = importlib.import_module("broken_mod")
    assert _unresolved_globals(module) == {"os"}


def test_every_module_has_a_docstring():
    missing = []
    for name in _modules():
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        if not (module.__doc__ or "").strip() and not name.endswith("__init__"):
            missing.append(name)
    assert not missing, f"modules without a docstring: {missing}"


def _unused_imports(path: Path) -> list[str]:
    import ast
    src = path.read_text()
    tree = ast.parse(src)
    lines = src.splitlines()
    imported = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imported[(a.asname or a.name).split(".")[0]] = node.lineno
        elif isinstance(node, ast.ImportFrom) and node.module != "__future__":
            for a in node.names:
                imported[a.asname or a.name] = node.lineno
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    exported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets):
            exported = {e.value for e in node.value.elts if isinstance(e, ast.Constant)}
    return [name for name, line in imported.items()
            if name not in used and name not in exported and "noqa" not in lines[line - 1]]


def test_no_unused_imports():
    found = {}
    for path in sorted(ROOT.rglob("*.py")) + sorted((ROOT.parent / "tests").glob("*.py")):
        if path.name == "__init__.py":
            continue
        unused = _unused_imports(path)
        if unused:
            found[str(path.relative_to(ROOT.parent))] = unused
    assert not found, f"unused imports: {found}"
