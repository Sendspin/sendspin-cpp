#!/usr/bin/env python3
# Copyright 2026 Sendspin Contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Deepest stack call chain of each ESP-IDF task, from GCC's -fcallgraph-info=su output.

Reads every .ci file under an ESP-IDF build directory, adds the indirect-call edges and the
precompiled-library frames from edges.json, and prints, for each task root in tasks.json, the
deepest simple call path and the sum of its frames: a static upper bound on the task's stack use
(see README.md for the recipe and what it does not model).
"""

import argparse
import collections
import glob
import json
import os
import re
import shutil
import subprocess
import sys

NODE_RE = re.compile(r'node: \{ title: "([^"]*)" label: "([^"]*)"')
EDGE_RE = re.compile(r'edge: \{ sourcename: "([^"]*)" targetname: "([^"]*)"')
FRAME_RE = re.compile(r"\\n(\d+) bytes \(([^)]*)\)")
INDIRECT = "__indirect_call"
ROM_SYMBOL_RE = re.compile(
    r"^\s*(?:PROVIDE\s*\(\s*)?([A-Za-z_][A-Za-z_0-9]*)\s*=\s*(?:0x[0-9A-Fa-f]+|[A-Za-z_])",
    re.MULTILINE,
)
FUNC_RE = re.compile(r"^[0-9a-f]+ <([^>]+)>:$")
ENTRY_RE = re.compile(r"\tentry\ta1, (\d+)")
INSN_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f]+ *\t(\S+)")
RELOC_RE = re.compile(r"R_XTENSA_(ASM_EXPAND|SLOT0_OP)\t([^+\s]+)")
CALLS = ("call0", "call4", "call8", "call12")
TOOLCHAIN_GCC = "xtensa-esp32-elf-gcc"


def symbol(title):
    """A node title is 'file:symbol' for a function defined in that file, else the symbol."""
    if title.startswith("/") and ":" in title:
        return title.rsplit(":", 1)[1]
    return title


class Graph:
    def __init__(self):
        self.frames = {}
        self.qualifier = {}
        self.labels = {}
        self.edges = collections.defaultdict(set)
        # Functions given call targets by edges.json.
        self.patched = set()

    def load(self, build_dir):
        for root, _, files in os.walk(build_dir):
            for name in files:
                if name.endswith(".ci"):
                    self._load_file(os.path.join(root, name))

    def _load_file(self, path):
        with open(path, errors="replace") as ci:
            for line in ci:
                node = NODE_RE.search(line)
                if node:
                    sym = symbol(node.group(1))
                    label = node.group(2)
                    frame = FRAME_RE.search(label)
                    if frame and int(frame.group(1)) >= self.frames.get(sym, -1):
                        self.frames[sym] = int(frame.group(1))
                        self.qualifier[sym] = frame.group(2)
                    if frame or sym not in self.labels:
                        self.labels[sym] = label.split("\\n")[0]
                    continue
                edge = EDGE_RE.search(line)
                if edge:
                    self.edges[symbol(edge.group(1))].add(symbol(edge.group(2)))

    def add_archive(self, objdump, archive):
        """Frames and direct calls of a precompiled archive (newlib, libgcc, libstdc++), which has
        no .ci file: each function's frame from its windowed-ABI `entry` instruction, its calls
        from the relocations on its call instructions (-mlongcalls expands each into an l32r and
        a callx8 marked R_XTENSA_ASM_EXPAND). Functions a .ci file already measured are kept."""
        output = subprocess.run(
            [objdump, "-dr", archive], capture_output=True, text=True, check=True
        ).stdout
        func = None
        last_insn = ""
        for line in output.splitlines():
            match = FUNC_RE.match(line)
            if match:
                func = match.group(1)
                if func in self.frames:
                    func = None
                    continue
                self.frames[func] = 0
                self.qualifier[func] = "objdump entry"
                self.labels.setdefault(func, func)
                last_insn = ""
                continue
            if func is None:
                continue
            entry = ENTRY_RE.search(line)
            if entry and self.frames[func] == 0:
                self.frames[func] = int(entry.group(1))
            insn = INSN_RE.match(line)
            if insn:
                last_insn = insn.group(1)
                continue
            reloc = RELOC_RE.search(line)
            if reloc and not reloc.group(2).startswith("."):
                if reloc.group(1) == "ASM_EXPAND" or last_insn in CALLS:
                    self.edges[func].add(reloc.group(2))

    def add_aliases(self, objdump, build_dir):
        """Resolve symbols that are aliases of a measured function (a C __attribute__((alias)), a
        constructor's or destructor's complete-object symbol emitted as an alias of its base
        one): every global symbol at the same section and offset of an object file as a measured
        function gets a zero-byte edge to it, so the alias counts the function's frame."""
        objects = []
        for root, _, files in os.walk(build_dir):
            objects.extend(os.path.join(root, f) for f in files if f.endswith(".obj"))
        for start in range(0, len(objects), 200):
            output = subprocess.run(
                [objdump, "-t", *objects[start:start + 200]], capture_output=True, text=True
            ).stdout
            groups = collections.defaultdict(list)
            current = ""
            for line in output.splitlines():
                if line.endswith(":     file format elf32-xtensa-le"):
                    current = line.split(":", 1)[0]
                    continue
                fields = line.split()
                # value, flags..., section, size, name
                if (len(fields) < 5 or not fields[0].isalnum() or fields[-1].startswith(".")
                        or fields[-3] in ("*UND*", "*ABS*", "*COM*")):
                    continue
                groups[(current, fields[-3], fields[0])].append(fields[-1])
            for names in groups.values():
                measured = [n for n in names if n in self.frames]
                for name in names:
                    if name not in self.frames and measured:
                        self.frames[name] = 0
                        self.qualifier[name] = "alias"
                        self.labels.setdefault(name, name)
                        self.edges[name].add(measured[0])

    def resolve(self, name):
        """Symbols a table entry names: 'sym:<regex>' over mangled symbols, an exact symbol, or a
        demangled-label substring of at least 13 characters."""
        if name.startswith("sym:"):
            pattern = re.compile(name[4:])
            return sorted(s for s in self.frames if pattern.search(s))
        if name in self.frames or name in self.edges:
            return [name]
        if len(name) < 13:
            return []
        return sorted(s for s, label in self.labels.items() if name in label)

    def add_tables(self, tables):
        for name, frame in tables.get("synthetic", {}).items():
            self.frames[name] = frame
            self.qualifier[name] = "objdump entry"
            self.labels[name] = name
        for source, targets in tables.get("edges", {}).items():
            sources = self.resolve(source)
            if not sources:
                print(f"warning: edge source {source!r} matches nothing", file=sys.stderr)
            resolved = [(target, self.resolve(target)) for target in targets]
            for target, dsts in resolved:
                if not dsts:
                    print(f"warning: edge target {target!r} of {source!r} matches nothing",
                          file=sys.stderr)
            # A source counts as covered for --indirect only when a target resolved: a table
            # whose every target is stale adds no frame.
            if not any(dsts for _, dsts in resolved):
                continue
            for src in sources:
                self.patched.add(src)
                for _, dsts in resolved:
                    self.edges[src].update(dsts)

    def callees(self, sym):
        return sorted(t for t in self.edges.get(sym, ()) if t != INDIRECT)

    def reachable(self, root):
        seen, pending = set(), [root]
        while pending:
            sym = pending.pop()
            if sym in seen:
                continue
            seen.add(sym)
            pending.extend(self.callees(sym))
        return seen

    def cycles(self, roots):
        """Every call cycle reachable from the roots, as its strongly connected component (Tarjan,
        iterative): the sets of functions that can recurse into each other."""
        index, low, on_stack, stack, cycles = {}, {}, set(), [], []
        counter = [0]

        def visit(start):
            work = [(start, iter(self.callees(start)))]
            index[start] = low[start] = counter[0]
            counter[0] += 1
            stack.append(start)
            on_stack.add(start)
            while work:
                node, children = work[-1]
                descended = False
                for child in children:
                    if child not in index:
                        index[child] = low[child] = counter[0]
                        counter[0] += 1
                        stack.append(child)
                        on_stack.add(child)
                        work.append((child, iter(self.callees(child))))
                        descended = True
                        break
                    if child in on_stack:
                        low[node] = min(low[node], index[child])
                if descended:
                    continue
                work.pop()
                if work:
                    parent = work[-1][0]
                    low[parent] = min(low[parent], low[node])
                if low[node] == index[node]:
                    component = []
                    while True:
                        member = stack.pop()
                        on_stack.discard(member)
                        component.append(member)
                        if member == node:
                            break
                    if len(component) > 1 or node in self.edges.get(node, ()):
                        cycles.append(sorted(component))

        for root in roots:
            if root not in index:
                visit(root)
        return cycles

    def deepest(self, root):
        """The deepest simple path from root: memoized outside cycles, exhaustive inside them.
        A path through a cycle visits each of its functions once, so recursion is charged a
        single pass (README.md, What it does not model)."""
        cyclic = {sym for cycle in self.cycles([root]) for sym in cycle}
        memo = {}
        sys.setrecursionlimit(100000)

        def walk(sym, on_path):
            if sym not in cyclic and sym in memo:
                return memo[sym]
            best = (0, [])
            on_path.add(sym)
            for child in self.callees(sym):
                if child in on_path:
                    continue
                result = walk(child, on_path)
                if result[0] > best[0]:
                    best = result
            on_path.discard(sym)
            result = (self.frames.get(sym, 0) + best[0], [sym] + best[1])
            if sym not in cyclic:
                memo[sym] = result
            return result

        return walk(root, set())


def rom_functions(patterns):
    """Functions the chip's ROM provides (symbols the ROM linker scripts place at an absolute
    address or define as another ROM symbol): they have no .ci file, and their frames on the
    caller's stack are not something any build can measure."""
    names = set()
    for pattern in patterns:
        for path in glob.glob(pattern):
            with open(path, errors="replace") as ld:
                names.update(ROM_SYMBOL_RE.findall(ld.read()))
    return names


def toolchain_archives():
    """newlib's libc and libm, libstdc++ and libgcc as the xtensa-esp32 toolchain on PATH links
    them, or nothing without the toolchain."""
    gcc = shutil.which(TOOLCHAIN_GCC)
    if gcc is None:
        return []
    archives = []
    for flag in ("-print-file-name=libc.a", "-print-file-name=libm.a",
                 "-print-file-name=libstdc++.a", "-print-libgcc-file-name"):
        path = subprocess.run([gcc, flag], capture_output=True, text=True).stdout.strip()
        if os.path.isfile(path):
            archives.append(path)
    return archives


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("build_dir", help="ESP-IDF build directory holding the .ci files")
    parser.add_argument("--edges", default=os.path.join(here, "edges.json"))
    parser.add_argument("--tasks", default=os.path.join(here, "tasks.json"))
    parser.add_argument("--task", action="append", help="only these tasks (default: all)")
    parser.add_argument("--path", action="store_true", help="print each deepest path")
    parser.add_argument(
        "--frameless",
        action="store_true",
        help="list every reachable function with no measured frame that the ROM does not "
        "provide: each counts as 0 bytes, so a missing .ci file under-reports silently",
    )
    parser.add_argument(
        "--cycles",
        action="store_true",
        help="list every call cycle a task reaches: the total charges each one a single pass, "
        "so a recursion deeper than that is not in it",
    )
    parser.add_argument(
        "--indirect",
        action="store_true",
        help="list every reachable function that calls through a pointer, marking those "
        "edges.json gives targets: where to add edges",
    )
    default_rom = os.path.join(
        os.environ.get("IDF_PATH", ""), "components", "esp_rom", "esp32", "ld", "*.ld"
    )
    parser.add_argument(
        "--rom-ld",
        action="append",
        help=f"ROM linker scripts whose PROVIDEs are not reported as frameless "
        f"(default: {default_rom})",
    )
    parser.add_argument(
        "--archive",
        action="append",
        help="precompiled archive to read frames and calls from with objdump (default: the "
        f"toolchain's libc, libm, libstdc++ and libgcc, when {TOOLCHAIN_GCC} is on PATH)",
    )
    args = parser.parse_args()
    rom = rom_functions(args.rom_ld or [default_rom])

    graph = Graph()
    graph.load(args.build_dir)
    archives = args.archive if args.archive is not None else toolchain_archives()
    if not archives:
        print("warning: no precompiled archives read; their functions count as 0 bytes",
              file=sys.stderr)
    objdump = shutil.which(TOOLCHAIN_GCC.replace("gcc", "objdump")) or "objdump"
    for archive in archives:
        graph.add_archive(objdump, archive)
    graph.add_aliases(objdump, args.build_dir)
    with open(args.edges) as edges:
        graph.add_tables(json.load(edges))
    with open(args.tasks) as tasks_file:
        tasks = {k: v for k, v in json.load(tasks_file).items() if not k.startswith("_")}

    for task, roots in tasks.items():
        if args.task and task not in args.task:
            continue
        for root_name in roots:
            for root in graph.resolve(root_name):
                total, path = graph.deepest(root)
                print(f"{task}: {total} bytes from {graph.labels.get(root, root)[:80]}")
                if args.path:
                    for sym in path:
                        frame = graph.frames.get(sym, 0)
                        kind = graph.qualifier.get(sym, "?")
                        print(f"  {frame:6d} {kind:14s} {graph.labels.get(sym, sym)[:120]}")
                cycles = graph.cycles([root])
                on_path = set(path)
                deepest_cycles = [c for c in cycles if on_path.intersection(c)]
                if cycles:
                    print(
                        f"  warning: {len(cycles)} call cycles reachable, {len(deepest_cycles)} "
                        "on the deepest path, each charged one pass (--cycles lists them)",
                        file=sys.stderr,
                    )
                if args.cycles:
                    for cycle in cycles:
                        mark = "ON PATH" if cycle in deepest_cycles else "off path"
                        names = ", ".join(graph.labels.get(c, c)[:60] for c in cycle[:4])
                        more = f", +{len(cycle) - 4} more" if len(cycle) > 4 else ""
                        print(f"  cycle {mark:8s} {len(cycle):3d} functions: {names}{more}")
                reach = graph.reachable(root) if args.frameless or args.indirect else set()
                if args.frameless or args.path:
                    frameless = sorted(
                        s for s in (reach or set(path)) if s not in graph.frames and s not in rom
                    )
                    for sym in frameless:
                        print(f"  warning: no frame for {sym}", file=sys.stderr)
                    if frameless:
                        print(
                            f"  warning: {len(frameless)} reachable functions without a frame "
                            "count as 0 bytes",
                            file=sys.stderr,
                        )
                if args.indirect:
                    for sym in sorted(reach):
                        if INDIRECT in graph.edges.get(sym, ()):
                            mark = "covered" if sym in graph.patched else "NO EDGES"
                            print(f"  indirect {mark:8s} {graph.labels.get(sym, sym)[:110]}")


if __name__ == "__main__":
    main()
