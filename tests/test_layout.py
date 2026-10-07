#!/usr/bin/env python3
"""The repo holds one pack root per architecture: `nodo pack arm64` / `nodo pack amd64`.

`nodo pack <dir>` reads `<dir>/.service/` and nothing else (the name is fixed),
takes the architecture from `.service/service.json`, copies `<dir>` to its cache
following symlinks, and resolves each local dependency as `<copy>/<path>`. So
each pack root must hold, inside itself, every dependency's own pack root for
the same architecture, and the shared sources reach them as symlinks. These
tests check that shape without a node, since a wrong one only shows up as a
failed (or wrong-architecture) pack.

Run with:  python3 tests/test_layout.py
"""
import json
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
ARCHES = ("arm64", "amd64")
SERVICE_FILES = ("Dockerfile", "service.json", "pack_config.json")


def _json(path):
    with open(path) as fh:
        return json.load(fh)


def _pack_roots(arch):
    """(label, pack root) for the demo and every dependency it packs, for `arch`."""
    root = os.path.join(ROOT, arch)
    yield "demo", root
    deps = _json(os.path.join(root, ".service", "pack_config.json"))["dependencies"]
    for env, dep in deps.items():
        yield env, os.path.join(root, dep)


class PerArchitectureLayoutTests(unittest.TestCase):
    def test_service_dirs_live_only_under_an_architecture(self):
        # A stray .service at the old places would make `nodo pack .` (or
        # `nodo pack tiny`) pack something no one maintains any more.
        for d in ("", "tiny", "heavy", "ping", "benchmark", "sharefs", "sharefs-denied"):
            self.assertFalse(os.path.exists(os.path.join(ROOT, d, ".service")), d or ".")

    def test_every_service_file_is_maintained_per_architecture(self):
        for arch in ARCHES:
            for label, root in _pack_roots(arch):
                for name in SERVICE_FILES:
                    path = os.path.join(root, ".service", name)
                    # Real files, not links to a shared one: each architecture's
                    # Dockerfile and pack_config are edited on their own.
                    self.assertTrue(os.path.isfile(path), f"{arch}/{label}: {name}")
                    self.assertFalse(os.path.islink(os.path.join(os.path.realpath(root), ".service", name)),
                                     f"{arch}/{label}: {name} is a symlink")

    def test_every_manifest_declares_its_directory_architecture(self):
        for arch in ARCHES:
            for label, root in _pack_roots(arch):
                declared = _json(os.path.join(root, ".service", "service.json"))["architecture"]
                self.assertEqual(declared, f"linux/{arch}", f"{arch}/{label}")

    def test_the_demo_is_tagged_as_the_verifier_in_both_architectures(self):
        for arch in ARCHES:
            tag = _json(os.path.join(ROOT, arch, ".service", "service.json"))["tag"]
            self.assertEqual(tag, "celaut-node-honesty-verifier", arch)

    def test_both_architectures_pack_the_same_dependencies(self):
        deps = {arch: _json(os.path.join(ROOT, arch, ".service", "pack_config.json"))["dependencies"]
                for arch in ARCHES}
        self.assertEqual(deps["arm64"], deps["amd64"])
        self.assertEqual(set(deps["arm64"]),
                         {"TINY", "HEAVY", "PING", "BENCHMARK", "SHAREFS", "SHAREFS_DENIED"})

    def test_dependencies_resolve_inside_the_pack_root(self):
        # nodo resolves a local dependency inside its cache copy of the pack
        # root, so `../x` or an absolute path would point outside it.
        for arch in ARCHES:
            deps = _json(os.path.join(ROOT, arch, ".service", "pack_config.json"))["dependencies"]
            for env, dep in deps.items():
                self.assertFalse(os.path.isabs(dep) or ".." in dep.split("/"), f"{arch}: {env}={dep}")
                self.assertTrue(os.path.isdir(os.path.join(ROOT, arch, dep, ".service")), f"{arch}: {env}")

    def test_everything_included_exists_in_each_pack_root(self):
        for arch in ARCHES:
            for label, root in _pack_roots(arch):
                for item in _json(os.path.join(root, ".service", "pack_config.json")).get("include", []):
                    self.assertTrue(os.path.exists(os.path.join(root, item)),
                                    f"{arch}/{label}: include '{item}' is missing or a broken link")

    def test_every_manifest_uses_the_current_packer_fields(self):
        # nodo maps the legacy `entrypoint` to init.entry_path and ignores a
        # pack_config `workdir`. Each child serves plain HTTP, so an api slot
        # that claims "tls" describes a protocol the service does not speak.
        for arch in ARCHES:
            for label, root in _pack_roots(arch):
                manifest = _json(os.path.join(root, ".service", "service.json"))
                where = f"{arch}/{label}"
                self.assertNotIn("entrypoint", manifest, where)
                self.assertTrue(manifest.get("init", {}).get("entry_path"), where)
                for slot in manifest.get("api", []):
                    self.assertNotIn("tls", slot.get("protocol", []), where)
                pack_config = _json(os.path.join(root, ".service", "pack_config.json"))
                self.assertNotIn("workdir", pack_config, where)

    def test_dockerfiles_copy_only_from_the_build_context(self):
        # The build context is .service/, with the project under service/. nodo
        # rewrites `./x` to `service/x`; a bare `x` is left alone and breaks.
        for arch in ARCHES:
            for label, root in _pack_roots(arch):
                with open(os.path.join(root, ".service", "Dockerfile")) as fh:
                    for line in fh:
                        parts = line.split()
                        if not parts or parts[0] != "COPY" or any(p.startswith("--from") for p in parts):
                            continue
                        for src in [p for p in parts[1:-1] if not p.startswith("--")]:
                            self.assertTrue(src == "service" or src.startswith(("service/", "./")),
                                            f"{arch}/{label}: COPY {src}")


class RustToolchainTests(unittest.TestCase):
    """`cargo build --locked` runs in the pinned `rust:<version>` image, not on the machine
    that wrote the lockfile. A lockfile resolved with a newer cargo can pick crates that
    need a newer rustc, and compiles fine locally while the pack fails. Declaring
    `rust-version` makes `cargo generate-lockfile` (with
    CARGO_RESOLVER_INCOMPATIBLE_RUST_VERSIONS=fallback) stay inside what the image has."""

    CHILDREN = ("sharefs", "sharefs-denied")

    @staticmethod
    def _version(text):
        return tuple(int(p) for p in text.split("."))

    def test_each_rust_child_declares_the_toolchain_its_image_builds_with(self):
        for child in self.CHILDREN:
            with open(os.path.join(ROOT, child, "Cargo.toml")) as fh:
                declared = re.search(r'^rust-version = "([\d.]+)"', fh.read(), re.M)
            self.assertIsNotNone(declared, f"{child}: Cargo.toml declares no rust-version")
            for arch in ARCHES:
                with open(os.path.join(ROOT, child, arch, ".service", "Dockerfile")) as fh:
                    image = re.search(r"^FROM rust:([\d.]+)", fh.read(), re.M)
                self.assertIsNotNone(image, f"{child}/{arch}: no pinned rust image")
                self.assertLessEqual(self._version(declared.group(1)), self._version(image.group(1)),
                                     f"{child}/{arch}: rust-version is newer than its image")


if __name__ == "__main__":
    unittest.main(verbosity=2)
