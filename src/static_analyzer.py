#!/usr/bin/env python3
"""
static_analyzer.py
Lightweight improved static analyzer for loops, calls, I/O, conditionals, recursion and hotspots.
Usage:
    python src/static_analyzer.py path/to/file.py [--no-print] [--only-in-func] [--json]
"""
import ast
import argparse
import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Any, List, Set, Optional


def add_parents(tree: ast.AST) -> None:
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            child.parent = node


@dataclass
class FuncStats:
    name: str
    lineno: Optional[int] = None
    loops: int = 0
    max_loop_depth: int = 0
    func_calls: int = 0
    io_ops: int = 0
    conditionals: int = 0
    recursion: Set[str] = field(default_factory=set)
    comprehensions: int = 0
    heavy_allocations_in_loops: List[int] = field(default_factory=list)
    loop_lines: List[int] = field(default_factory=list)
    cyclomatic: int = 1


class GreenCodeAnalyzer(ast.NodeVisitor):
    def __init__(self, count_print: bool = True, only_inside_functions: bool = False):
        self.count_print = count_print
        self.only_inside_functions = only_inside_functions

        self.functions: Dict[str, FuncStats] = {}
        self.current: FuncStats = FuncStats(name="<global>", lineno=None)
        self.functions["<global>"] = self.current
        self._loop_depth_stack: List[int] = [0]
        self.defined_funcs: Set[str] = set()

    def push_function(self, name: str, lineno: Optional[int]):
        prev = self.current
        fs = FuncStats(name=name, lineno=lineno)
        self.functions[name] = fs
        self.current = fs
        self._loop_depth_stack.append(0)
        return prev

    def pop_function(self, prev):
        self._loop_depth_stack.pop()
        self.current = prev

    def current_loop_depth(self) -> int:
        return self._loop_depth_stack[-1]

    def enter_loop(self):
        self._loop_depth_stack[-1] += 1
        self.current.loops += 1
        d = self._loop_depth_stack[-1]
        if d > self.current.max_loop_depth:
            self.current.max_loop_depth = d

    def exit_loop(self):
        self._loop_depth_stack[-1] -= 1

    def visit_Module(self, node: ast.Module):
        add_parents(node)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.defined_funcs.add(node.name)
        prev = self.push_function(node.name, getattr(node, "lineno", None))
        self.generic_visit(node)
        self.pop_function(prev)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_For(self, node: ast.For):
        if self.only_inside_functions and self.current.name == "<global>":
            # still traverse to find nested constructs but skip counting
            self.generic_visit(node)
            return
        self.enter_loop()
        if hasattr(node, "lineno"):
            self.current.loop_lines.append(node.lineno)
        self.generic_visit(node)
        self.exit_loop()

    def visit_While(self, node: ast.While):
        if self.only_inside_functions and self.current.name == "<global>":
            self.generic_visit(node)
            return
        self.enter_loop()
        if hasattr(node, "lineno"):
            self.current.loop_lines.append(node.lineno)
        self.generic_visit(node)
        self.exit_loop()

    def visit_If(self, node: ast.If):
        self.current.conditionals += 1
        self.current.cyclomatic += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp):
        self.current.cyclomatic += max(1, len(node.values) - 1)
        self.generic_visit(node)

    def visit_Try(self, node: ast.Try):
        self.current.cyclomatic += max(1, len(node.handlers))
        self.generic_visit(node)

    def _is_io_name(self, name: str) -> bool:
        if name == "open":
            return True
        if not self.count_print and name in ("print", "input"):
            return False
        return name in ("print", "input")

    def visit_Call(self, node: ast.Call):
        self.current.func_calls += 1

        # name-based checks
        if isinstance(node.func, ast.Name):
            name = node.func.id
            if self._is_io_name(name):
                self.current.io_ops += 1
            if name == self.current.name:
                self.current.recursion.add(self.current.name)

            # heavy allocations inside loops (list/dict/set constructors)
            if name in ("list", "dict", "set") and self.current_loop_depth() > 0 and hasattr(node, "lineno"):
                self.current.heavy_allocations_in_loops.append(node.lineno)

        elif isinstance(node.func, ast.Attribute):
            attr = node.func.attr.lower()
            if attr in ("read", "readline", "readlines", "write", "flush"):
                self.current.io_ops += 1
            if attr == self.current.name:
                self.current.recursion.add(self.current.name)

        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp):
        self.current.comprehensions += 1
        if self.current_loop_depth() > 0 and hasattr(node, "lineno"):
            self.current.heavy_allocations_in_loops.append(node.lineno)
        self.generic_visit(node)

    def visit_DictComp(self, node: ast.DictComp):
        self.current.comprehensions += 1
        if self.current_loop_depth() > 0 and hasattr(node, "lineno"):
            self.current.heavy_allocations_in_loops.append(node.lineno)
        self.generic_visit(node)

    def visit_SetComp(self, node: ast.SetComp):
        self.current.comprehensions += 1
        if self.current_loop_depth() > 0 and hasattr(node, "lineno"):
            self.current.heavy_allocations_in_loops.append(node.lineno)
        self.generic_visit(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp):
        self.current.comprehensions += 1
        self.generic_visit(node)


def compute_score(fs: FuncStats) -> float:
    score = 0.0
    score += fs.loops * 2.0
    score += fs.max_loop_depth * 3.0
    score += fs.func_calls * 0.4
    score += fs.io_ops * 1.5
    score += len(fs.recursion) * 4.0
    score += fs.comprehensions * 1.0
    score += len(fs.heavy_allocations_in_loops) * 3.0
    score += max(0, fs.cyclomatic - 1) * 0.5
    return score


def analyze_file(path: str, count_print: bool, only_inside_functions: bool):
    with open(path, "r", encoding="utf-8") as fh:
        src = fh.read()
    tree = ast.parse(src, filename=path)
    add_parents(tree)
    analyzer = GreenCodeAnalyzer(count_print=count_print, only_inside_functions=only_inside_functions)
    analyzer.visit(tree)

    per_scope = {}
    total = 0.0
    for name, fs in analyzer.functions.items():
        per_scope[name] = {
            "name": fs.name,
            "lineno": fs.lineno,
            "loops": fs.loops,
            "max_loop_depth": fs.max_loop_depth,
            "func_calls": fs.func_calls,
            "io_ops": fs.io_ops,
            "conditionals": fs.conditionals,
            "recursion": sorted(list(fs.recursion)),
            "comprehensions": fs.comprehensions,
            "heavy_allocations_in_loops": fs.heavy_allocations_in_loops,
            "loop_lines": fs.loop_lines,
            "cyclomatic": fs.cyclomatic,
            "score": compute_score(fs),
        }
        total += per_scope[name]["score"]
    return {"per_scope": per_scope}, total


def pretty_print(result: Dict[str, Any], total_score: float, suggestions: List[str]):
    print("\n--- Green Code Analysis ---")
    for scope, stats in result["per_scope"].items():
        print(f"\nScope: {stats['name']}" + (f" (line {stats['lineno']})" if stats['lineno'] else ""))
        print(f"  Loops: {stats['loops']} (max depth {stats['max_loop_depth']})")
        print(f"  Function calls: {stats['func_calls']}")
        print(f"  Conditionals: {stats['conditionals']}")
        print(f"  Comprehensions: {stats['comprehensions']}")
        print(f"  I/O ops: {stats['io_ops']}")
        print(f"  Cyclomatic complexity: {stats['cyclomatic']}")
        print(f"  Heavy allocations in loops: {stats['heavy_allocations_in_loops'] or 'None'}")
        print(f"  Loop lines: {stats['loop_lines'] or 'None'}")
        print(f"  Score: {stats['score']:.2f}")
    print(f"\nTotal Energy Score: {total_score:.2f}")


def suggestions_from_result(per_scope: Dict[str, Any]) -> List[str]:
    s = []
    max_depth = max((v["max_loop_depth"] for v in per_scope.values()), default=0)
    total_heavy = sum(len(v["heavy_allocations_in_loops"]) for v in per_scope.values())
    total_io = sum(v["io_ops"] for v in per_scope.values())
    if max_depth >= 3:
        s.append("Deep nested loops (>=3) found — consider major refactor or vectorization.")
    elif max_depth == 2:
        s.append("Nested loops (depth 2) — try precomputation or hash lookups to reduce inner loop work.")
    if total_heavy:
        s.append("Heavy allocations inside loops detected — move allocations outside the loop or use generators.")
    if total_io:
        s.append("I/O operations detected — batch writes or disable counting of prints with --no-print.")
    if not s:
        s.append("No major static issues detected.")
    return s


def main():
    p = argparse.ArgumentParser(description="Static analyzer for green code heuristics")
    p.add_argument("path", help="Python file to analyze")
    p.add_argument("--no-print", action="store_true", help="Do not count print()/input() as I/O")
    p.add_argument("--only-in-func", action="store_true", help="Count only loops inside functions (ignore top-level loops)")
    p.add_argument("--json", action="store_true", help="Output JSON")
    args = p.parse_args()

    count_print = not args.no_print
    only_in_func = args.only_in_func

    result, total = analyze_file(args.path, count_print=count_print, only_inside_functions=only_in_func)
    suggestions = suggestions_from_result(result["per_scope"])

    if args.json:
        out = {"result": result, "total_score": total, "suggestions": suggestions}
        print(json.dumps(out, indent=2))
    else:
        pretty_print(result, total, suggestions)
        print("\nSuggestions:")
        for s in suggestions:
            print(f"- {s}")


if __name__ == "__main__":
    main()
