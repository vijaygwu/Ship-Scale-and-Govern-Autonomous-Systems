"""Shared pytest fixtures and import-time stubs for Book 2 chapter tests.

The companion code modules under ``book-2/code/ch0*/*.py`` reach for a lot of
third-party libraries at import time (boto3, opentelemetry, sqlalchemy, redis,
structlog, hvac, ldclient, ...). Several of those are not listed in the runtime
``requirements.txt`` and we do not want every CI job to install them just to
run a smoke-import test. This conftest therefore stubs the missing modules
with ``unittest.mock.MagicMock`` instances in ``sys.modules`` *before* any
test tries to import a chapter module.

Gotcha: ``book-2/code/ch02-api-keys/secrets.py`` shadows the stdlib
``secrets`` module name. Adding that chapter directory to ``sys.path`` would
break ``import secrets`` in every other chapter (and in pytest itself). The
ch02 tests therefore load the file with ``importlib.util`` under the name
``book2_secrets`` instead of via ``sys.path``.
"""
from __future__ import annotations

import asyncio
import builtins
import io
import importlib
import importlib.machinery
import importlib.util
import sys
import time
import types
from collections.abc import Callable
from pathlib import Path
from unittest.mock import MagicMock

import pytest

CODE_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Stub third-party dependencies that may not be installed in CI before any
# chapter module is imported. MagicMock satisfies ``from foo import Bar`` for
# any ``Bar`` and is sufficient for import-time evaluation; tests that need
# real behavior should install the genuine package.
# ---------------------------------------------------------------------------
_STUB_MODULES = [
    "hvac",
    "ldclient",
    "ldclient.config",
    "boto3",
    "botocore",
    "botocore.exceptions",
    "botocore.config",
    "redis",
    "redis.asyncio",
    "structlog",
    "sqlalchemy",
    "sqlalchemy.ext",
    "sqlalchemy.ext.asyncio",
    "pydantic_settings",
    "starlette",
    "starlette.middleware",
    "starlette.middleware.base",
    "opentelemetry",
    "opentelemetry.trace",
    "opentelemetry.metrics",
    "opentelemetry.exporter",
    "opentelemetry.exporter.otlp",
    "opentelemetry.exporter.otlp.proto",
    "opentelemetry.exporter.otlp.proto.grpc",
    "opentelemetry.exporter.otlp.proto.grpc.metric_exporter",
    "opentelemetry.exporter.otlp.proto.grpc.trace_exporter",
    "opentelemetry.sdk",
    "opentelemetry.sdk.metrics",
    "opentelemetry.sdk.metrics.export",
    "opentelemetry.sdk.resources",
    "opentelemetry.sdk.trace",
    "opentelemetry.sdk.trace.export",
    "cachetools",
]


class _SimpleLRUCache(dict):
    def __init__(self, maxsize: int = 128, *args, **kwargs) -> None:
        super().__init__()
        self.maxsize = maxsize
        if args or kwargs:
            self.update(*args, **kwargs)

    def __getitem__(self, key):
        value = super().__getitem__(key)
        super().__delitem__(key)
        super().__setitem__(key, value)
        return value

    def __setitem__(self, key, value) -> None:
        if key in self:
            super().__delitem__(key)
        while len(self) >= self.maxsize:
            oldest = next(iter(self))
            super().__delitem__(oldest)
        super().__setitem__(key, value)


class _SimpleTTLCache(_SimpleLRUCache):
    def __init__(self, maxsize: int = 128, ttl: float = 300, *args, **kwargs) -> None:
        self.ttl = ttl
        self._expires_at = {}
        super().__init__(maxsize=maxsize)
        if args or kwargs:
            self.update(*args, **kwargs)

    def _expired(self, key) -> bool:
        expires_at = self._expires_at.get(key)
        if expires_at is None or expires_at > time.monotonic():
            return False
        self._expires_at.pop(key, None)
        if dict.__contains__(self, key):
            dict.__delitem__(self, key)
        return True

    def _prune_expiry_index(self) -> None:
        live_keys = set(dict.keys(self))
        for key in list(self._expires_at):
            if key not in live_keys:
                self._expires_at.pop(key, None)

    def __contains__(self, key) -> bool:
        return dict.__contains__(self, key) and not self._expired(key)

    def __getitem__(self, key):
        if self._expired(key):
            raise KeyError(key)
        return super().__getitem__(key)

    def __setitem__(self, key, value) -> None:
        super().__setitem__(key, value)
        self._expires_at[key] = time.monotonic() + self.ttl
        self._prune_expiry_index()

    def __delitem__(self, key) -> None:
        self._expires_at.pop(key, None)
        super().__delitem__(key)

    def clear(self) -> None:
        self._expires_at.clear()
        super().clear()


def _install_cachetools_stub_if_needed() -> None:
    module = sys.modules.get("cachetools")
    if module is not None and not isinstance(module, MagicMock):
        return

    cachetools = types.ModuleType("cachetools")
    cachetools.__spec__ = importlib.machinery.ModuleSpec("cachetools", loader=None)
    cachetools.LRUCache = _SimpleLRUCache
    cachetools.TTLCache = _SimpleTTLCache
    sys.modules["cachetools"] = cachetools


def _is_requested_module_missing(exc: ImportError, requested: str) -> bool:
    missing = getattr(exc, "name", None)
    if not missing:
        return False
    return (
        requested == missing
        or requested.startswith(f"{missing}.")
        or missing.startswith(f"{requested}.")
    )


def _install_stubs() -> None:
    for name in _STUB_MODULES:
        try:
            importlib.import_module(name)
        except (ModuleNotFoundError, ImportError) as exc:
            if not _is_requested_module_missing(exc, name):
                raise
            sys.modules[name] = MagicMock(name=name)

    _install_cachetools_stub_if_needed()

    # Make sure dotted attribute access patterns used in chapter modules
    # resolve. ``from opentelemetry import trace, metrics`` expects
    # ``opentelemetry.trace`` and ``opentelemetry.metrics`` to be available on
    # the parent module object, not just in ``sys.modules``.
    parent_to_children: dict[str, list[str]] = {}
    for dotted in _STUB_MODULES:
        if "." in dotted:
            parent, child = dotted.rsplit(".", 1)
            parent_to_children.setdefault(parent, []).append(child)
    for parent, children in parent_to_children.items():
        if parent in sys.modules:
            for child in children:
                full = f"{parent}.{child}"
                if full in sys.modules:
                    setattr(sys.modules[parent], child, sys.modules[full])

    # pydantic_settings.BaseSettings must be a real class because chapter
    # code does ``class Settings(BaseSettings)`` at module load. A bare
    # MagicMock cannot be subclassed cleanly, and once subclassed it
    # breaks ``typing.Optional[Settings]`` evaluation downstream.
    class _StubBaseSettings:
        def __init__(self, **kwargs):
            for _k, _v in kwargs.items():
                setattr(self, _k, _v)

        @classmethod
        def model_validate(cls, *_a, **_kw):
            return cls()

    def _stub_config_dict(**kwargs):
        return kwargs

    stub_ps = types.ModuleType("pydantic_settings")
    stub_ps.BaseSettings = _StubBaseSettings
    stub_ps.SettingsConfigDict = _stub_config_dict
    sys.modules["pydantic_settings"] = stub_ps


_install_stubs()


# ---------------------------------------------------------------------------
# sys.path management. Add every chapter directory *except* ch02-api-keys so
# ``import secrets`` in other chapters resolves to the stdlib module.
# ---------------------------------------------------------------------------
_CHAPTER_DIRS = {
    "identity": CODE_ROOT / "ch01-enterprise-identity",
    "rate_limits": CODE_ROOT / "ch03-rate-limits",
    "audit": CODE_ROOT / "ch04-audit-trails",
    "deployment": CODE_ROOT / "ch05-deployment",
    "monitoring": CODE_ROOT / "ch06-monitoring",
    "error_handling": CODE_ROOT / "ch07-error-handling",
    "testing": CODE_ROOT / "ch08-testing",
}
for _module_name, _path in _CHAPTER_DIRS.items():
    p = str(_path)
    if p not in sys.path:
        sys.path.insert(0, p)

_SECRETS_PATH = CODE_ROOT / "ch02-api-keys" / "secrets.py"


def _load_chapter(module_name: str, file_path: Path) -> types.ModuleType:
    """Load a chapter module from an explicit path under ``module_name``."""
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def clean_module():
    """Fresh import of a chapter module for the duration of one test.

    Use as ``mod = clean_module("identity")`` (chapter modules already on
    ``sys.path``) or ``mod = clean_module("book2_secrets", path=...)`` to
    load a file directly. The module is removed from ``sys.modules`` after
    the test so subsequent tests get a clean slate.
    """
    loaded: list[str] = []

    def _load(name: str, path: Path | None = None) -> types.ModuleType:
        if name in sys.modules:
            del sys.modules[name]
        if path is not None:
            module = _load_chapter(name, path)
        else:
            module = importlib.import_module(name)
        loaded.append(name)
        return module

    yield _load

    for name in loaded:
        sys.modules.pop(name, None)


@pytest.fixture
def secrets_module():
    """Load ch02 secrets.py as ``book2_secrets`` so it does not collide with
    stdlib ``secrets``."""
    name = "book2_secrets"
    if name in sys.modules:
        del sys.modules[name]
    module = _load_chapter(name, _SECRETS_PATH)
    yield module
    sys.modules.pop(name, None)
@pytest.fixture(scope="session")
def code_root() -> Path:
    """Root of the Book 2 companion-code tree."""
    return Path(__file__).resolve().parents[1]


@pytest.fixture
def run_async() -> Callable:
    """Run one async scenario from a synchronous pytest test."""

    def _run(coro):
        return asyncio.run(coro)

    return _run


def _identity_decorator(*args, **kwargs):
    """Decorator helper used by optional test-framework stubs."""
    del kwargs
    if len(args) == 1 and callable(args[0]):
        return args[0]

    def decorator(func):
        return func

    return decorator


def _new_module(name: str, **attrs) -> types.ModuleType:
    module = types.ModuleType(name)
    module.__spec__ = importlib.machinery.ModuleSpec(name, loader=None)
    for key, value in attrs.items():
        setattr(module, key, value)
    return module


def _install_module(monkeypatch: pytest.MonkeyPatch, name: str, module: types.ModuleType) -> None:
    monkeypatch.setitem(sys.modules, name, module)
    if "." in name:
        parent_name, child_name = name.rsplit(".", 1)
        parent = sys.modules.get(parent_name)
        if parent is not None:
            setattr(parent, child_name, module)


def _tool_stub_class(class_name: str):
    class ToolStub:
        class RateLimitError(Exception):
            pass

        class PathNotAllowedError(Exception):
            pass

        class ConfirmationRequiredError(Exception):
            pass

        def __init__(self, *args, **kwargs) -> None:
            self.args = args
            self.kwargs = kwargs

        def execute(self, *args, **kwargs):
            return {"success": True, "args": args, "kwargs": kwargs}

    ToolStub.__name__ = class_name
    return ToolStub


def _install_ch08_optional_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Let the chapter 8 examples import when optional test SDKs are absent."""
    real_open = builtins.open

    def open_with_empty_golden_data(file, *args, **kwargs):
        file_name = str(file)
        if "/ch08-testing/golden/" in file_name and file_name.endswith(".json"):
            return io.StringIO('{"tests": []}')
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", open_with_empty_golden_data)

    try:
        importlib.import_module("hypothesis")
        importlib.import_module("hypothesis.strategies")
    except ModuleNotFoundError:
        strategies = _new_module(
            "hypothesis.strategies",
            text=lambda *args, **kwargs: ("text", args, kwargs),
            lists=lambda *args, **kwargs: ("lists", args, kwargs),
            sampled_from=lambda values: ("sampled_from", tuple(values)),
        )
        health_check = types.SimpleNamespace(function_scoped_fixture=object())
        hypothesis = _new_module(
            "hypothesis",
            __version__="0.0-test-stub",
            given=_identity_decorator,
            settings=_identity_decorator,
            HealthCheck=health_check,
            strategies=strategies,
        )
        _install_module(monkeypatch, "hypothesis", hypothesis)
        _install_module(monkeypatch, "hypothesis.strategies", strategies)

    try:
        importlib.import_module("respx")
    except ModuleNotFoundError:
        class Route:
            call_count = 0
            side_effect = None

            def mock(self, *args, **kwargs):
                return self

        respx = _new_module(
            "respx",
            mock=_identity_decorator,
            get=lambda *args, **kwargs: Route(),
        )
        _install_module(monkeypatch, "respx", respx)

    try:
        importlib.import_module("vcr")
    except ModuleNotFoundError:
        vcr = _new_module("vcr", use_cassette=_identity_decorator)
        _install_module(monkeypatch, "vcr", vcr)

    if "src" not in sys.modules:
        _install_module(monkeypatch, "src", _new_module("src"))
    if "src.tools" not in sys.modules:
        _install_module(monkeypatch, "src.tools", _new_module("src.tools"))

    tool_modules = {
        "src.tools.web_search": ("WebSearchTool",),
        "src.tools.file_operations": ("FileOperationsTool",),
        "src.tools.database": ("DatabaseTool",),
        "src.tools.weather": ("WeatherTool",),
        "src.tools.stock_price": ("StockPriceTool",),
    }
    for module_name, class_names in tool_modules.items():
        try:
            importlib.import_module(module_name)
        except ModuleNotFoundError:
            module = _new_module(
                module_name,
                **{class_name: _tool_stub_class(class_name) for class_name in class_names},
            )
            _install_module(monkeypatch, module_name, module)


@pytest.fixture
def import_chapter(code_root: Path, monkeypatch: pytest.MonkeyPatch) -> Callable:
    """Import a chapter file from its hyphenated directory by path."""

    def _import(
        chapter_dir: str,
        module_basename: str,
        *,
        stub_testing_optionals: bool = False,
    ):
        if stub_testing_optionals:
            _install_ch08_optional_stubs(monkeypatch)

        monkeypatch.syspath_prepend(str(code_root))

        basename = module_basename.removesuffix(".py")
        path = code_root / chapter_dir / f"{basename}.py"
        if not path.exists():
            raise AssertionError(f"Chapter module does not exist: {path}")

        safe_name = "".join(
            char if char.isalnum() else "_"
            for char in f"book2_{chapter_dir}_{basename}"
        )
        sys.modules.pop(safe_name, None)

        spec = importlib.util.spec_from_file_location(safe_name, path)
        if spec is None or spec.loader is None:
            raise AssertionError(f"Could not load import spec for {path}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[safe_name] = module
        try:
            spec.loader.exec_module(module)
        except pytest.skip.Exception:
            sys.modules.pop(safe_name, None)
            raise
        except ModuleNotFoundError as exc:
            sys.modules.pop(safe_name, None)
            pytest.skip(f"{path.name} requires missing dependency {exc.name!r}")

        return module

    return _import


def pytest_configure(config):
    for marker in ("unit", "integration", "behavioral", "safety", "slow", "regression"):
        config.addinivalue_line("markers", f"{marker}: Book 2 companion-code tests")
