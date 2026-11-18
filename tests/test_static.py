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
