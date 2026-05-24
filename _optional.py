"""Small helpers for optional dependencies used by book listings.

The companion code is meant to import in a minimal Python environment while
still failing loudly when an example reaches a dependency the reader has not
installed or wired.  Chapter modules use these helpers instead of sprinkling
try/except ImportError blocks through every listing.
"""

from __future__ import annotations

import importlib
import types
from typing import Any, Iterable


class _RequiredDependency:
    """Fail-loud placeholder for a missing package or production collaborator."""

    def __init__(self, name: str, hint: str | None = None) -> None:
        self.name = name
        self.hint = hint or "Install or configure this dependency before use."

    def _raise(self) -> None:
        raise RuntimeError(f"{self.name} is required. {self.hint}")

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        self._raise()

    def __getattr__(self, attr: str) -> Any:
        self._raise()

    def __iter__(self) -> Any:
        self._raise()

    def __await__(self) -> Any:
        self._raise()

    def __bool__(self) -> bool:
        self._raise()

    def __repr__(self) -> str:
        return f"_RequiredDependency(name={self.name!r})"


class _OptionalModule(types.ModuleType):
    """Module-shaped placeholder that exposes configured exception classes."""

    def __init__(
        self,
        module_name: str,
        stub_exception_names: Iterable[str] = (),
        hint: str | None = None,
    ) -> None:
        super().__init__(module_name)
        self.__dict__["_missing_dependency_hint"] = (
            hint or f"Install the `{module_name.split('.')[0]}` package."
        )

        exception_namespace = types.SimpleNamespace()
        for exc_name in stub_exception_names:
            exc_type = type(exc_name, (Exception,), {})
            setattr(self, exc_name, exc_type)
            setattr(exception_namespace, exc_name, exc_type)

        # SDKs such as hvac and botocore conventionally expose exceptions
        # through a nested `.exceptions` namespace.
        self.exceptions = exception_namespace

    def __getattr__(self, attr: str) -> Any:
        return _RequiredDependency(
            f"{self.__name__}.{attr}",
            self.__dict__["_missing_dependency_hint"],
        )


def optional_import(
    module_name: str,
    *,
    stub_exception_names: Iterable[str] = (),
    hint: str | None = None,
) -> types.ModuleType:
    """Import an optional module or return a fail-loud module placeholder."""

    try:
        return importlib.import_module(module_name)
    except ImportError:
        return _OptionalModule(module_name, stub_exception_names, hint)
