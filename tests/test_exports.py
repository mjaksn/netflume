"""The export list and the documentation, held against each other.

The audit rounds before the first release ran a checker that verified every
documented name *resolves*. It never checked the other direction, that every
documented name is *exported*, and two ceilings sat in the README's table as
public tuning knobs while being absent from their modules' ``__all__`` for as
long as that took to notice. A one-directional check that looked like coverage.

So this goes both ways, and it holds the three tiers the package is arranged
in: a name in ``netflume.__all__`` is what a consumer of flows needs, a name in
a module's ``__all__`` is what a caller tuning or extending that module needs,
and anything in neither is internal and may move without notice.

What counts as documentation here is deliberately weak: any identifier
appearing in code in the README, inline or fenced. That is a floor rather than
a claim the prose is any good. It catches the failure that actually happens,
which is a name reaching ``__all__`` and being written about nowhere.
"""

import importlib
import pkgutil
import re
import unittest
from os.path import abspath, dirname, join

import netflume

README = join(dirname(dirname(abspath(__file__))), "README.md")

MODULES = sorted(m.name for m in pkgutil.iter_modules(netflume.__path__))


def _readme_code():
    """Every code span in the README, inline and fenced."""
    with open(README, encoding="utf-8") as fh:
        text = fh.read()
    return (re.findall(r"`([^`\n]+)`", text)
            + re.findall(r"```[a-z]*\n(.*?)```", text, re.S))


_CODE = _readme_code()

#: Every identifier the README writes in code, however it was qualified.
NAMES = {m.group(0) for span in _CODE
         for m in re.finditer(r"[A-Za-z_][A-Za-z0-9_]*", span)}

#: The module-qualified references, which are how the README spells a name
#: that a module exports and the package deliberately does not.
PATHS = {f"netflume.{pair[0]}.{pair[1]}" for span in _CODE
         for pair in re.findall(r"\bnetflume\.([a-z_]+)\.([A-Za-z_][A-Za-z0-9_]*)",
                                span)}


class EveryExportIsDocumented(unittest.TestCase):
    def test_the_readme_mentions_every_package_export(self):
        for name in netflume.__all__:
            with self.subTest(name=name):
                self.assertIn(name, NAMES,
                              f"netflume.{name} is exported but the README "
                              "never writes it")

    def test_the_readme_mentions_every_module_only_export(self):
        # A name a module exports and the package does not is reachable only
        # as netflume.<module>.<name>, and that is how the README has to spell
        # it, or a reader cannot tell which import works.
        for mod in MODULES:
            module = importlib.import_module("netflume." + mod)
            for name in getattr(module, "__all__", ()):
                if name in netflume.__all__:
                    continue
                with self.subTest(module=mod, name=name):
                    self.assertIn(f"netflume.{mod}.{name}", PATHS,
                                  f"netflume.{mod} exports {name}, which the "
                                  "package does not re-export, so the README "
                                  "must name it with its module path")


class EveryDocumentedNameIsExported(unittest.TestCase):
    """The direction the old checker missed."""

    def test_module_paths_resolve(self):
        for path in sorted(PATHS):
            _, mod, name = path.split(".")
            with self.subTest(path=path):
                module = importlib.import_module("netflume." + mod)
                self.assertTrue(hasattr(module, name),
                                f"{path} is documented but does not exist")

    def test_module_paths_are_exported(self):
        for path in sorted(PATHS):
            _, mod, name = path.split(".")
            with self.subTest(path=path):
                module = importlib.import_module("netflume." + mod)
                self.assertIn(name, module.__all__,
                              f"{path} is documented as public but is missing "
                              f"from netflume.{mod}.__all__")


class EveryModuleDeclaresItsSurface(unittest.TestCase):
    def test_every_module_has_an_all(self):
        # Without one there is no statement of what the module considers
        # public, and the checks above have nothing to hold it to.
        for mod in MODULES:
            with self.subTest(module=mod):
                module = importlib.import_module("netflume." + mod)
                self.assertIsInstance(getattr(module, "__all__", None), list)

    def test_every_package_export_comes_from_a_module(self):
        # __version__ is the exception: it is defined in __init__ itself.
        declared = set()
        for mod in MODULES:
            module = importlib.import_module("netflume." + mod)
            declared.update(getattr(module, "__all__", ()))
        for name in netflume.__all__:
            if name == "__version__":
                continue
            with self.subTest(name=name):
                self.assertIn(name, declared,
                              f"the package exports {name}, but no module "
                              "declares it")


if __name__ == "__main__":
    unittest.main()
