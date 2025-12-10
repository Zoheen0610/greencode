#!/usr/bin/env python3
"""
hybrid_full_analyzer.py

Combines improved static analysis (per-function stats, heavy-allocation detection,
cyclomatic complexity, suggestions) with dynamic measurements:
 - exact tracing (call counts, line hit counts) via in-process tracer (--trace)
 - or safe subprocess energy estimation (--safe-subprocess)

Usage:
  python src/hybrid_full_analyzer.py target.py [--args "a b"] [--trace | --safe-subprocess]
      [--power 15.0] [--ci 400.0] [--json]

Notes:
 - Default behavior is --trace (in-process tracer) for best hybrid results.
 - If your target has destructive side-effects prefer --safe-subprocess (less dynamic detail).
 - Requires psutil for subprocess energy estimation (pip install psutil).
"""
import ast
import runpy
import sys
import os
import argparse
import time
import json
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set, Tuple

# -------------------------
# Helpers
# -------------------------
def discover_python_files(target_path: str) -> List[str]:
    """Return list of python files to analyze based on target_path."""
    if os.path.isfile(target_path) and target_path.endswith(".py"):
        return [os.path.abspath(target_path)]

    files = []
    for root, dirs, filenames in os.walk(target_path):
        for fname in filenames:
            if fname.endswith(".py"):
                files.append(os.path.join(root, fname))
    return sorted(files)

# --- Static analysis (improved) -------------------------------------------------

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

class StaticAnalyzer(ast.NodeVisitor):
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
            self.generic_visit(node); return
        self.enter_loop()
        if hasattr(node, "lineno"):
            self.current.loop_lines.append(node.lineno)
        self.generic_visit(node)
        self.exit_loop()

    def visit_While(self, node: ast.While):
        if self.only_inside_functions and self.current.name == "<global>":
            self.generic_visit(node); return
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
        if isinstance(node.func, ast.Name):
            name = node.func.id
            if self._is_io_name(name):
                self.current.io_ops += 1
            if name == self.current.name:
                self.current.recursion.add(self.current.name)
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

def static_analyze_file(path: str, count_print: bool, only_inside_functions: bool) -> Tuple[Dict[str, Any], float]:
    with open(path, "r", encoding="utf-8") as fh:
        src = fh.read()
    tree = ast.parse(src, filename=path)
    add_parents(tree)
    analyzer = StaticAnalyzer(count_print=count_print, only_inside_functions=only_inside_functions)
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

# --- Dynamic measurement: tracer (in-process) ---------------------------------

def run_with_tracer_inprocess(target_path: str, target_args: List[str]) -> Tuple[Dict[str,int], Dict[int,int], float]:
    """
    Runs target via runpy.run_path under sys.settrace and returns:
      - dynamic_calls: mapping function_name -> call count
      - dynamic_lines: mapping lineno -> hit count
      - wall_seconds: runtime wall time
    NOTE: runs in-process (side-effects occur)
    """
    call_counts = defaultdict(int)
    line_counts = defaultdict(int)
    target_abspath = os.path.abspath(target_path)

    def tracer(frame, event, arg):
        filename = frame.f_code.co_filename
        # only trace target file
        if os.path.abspath(filename) != target_abspath:
            return None
        if event == "call":
            name = frame.f_code.co_name
            call_counts[name] += 1
            return tracer
        elif event == "line":
            line_counts[frame.f_lineno] += 1
        return tracer

    old_argv = sys.argv[:]
    old_trace = sys.gettrace()
    sys.argv = [target_path] + target_args
    start = time.perf_counter()
    try:
        sys.settrace(tracer)
        runpy.run_path(target_path, run_name="__main__")
    except SystemExit:
        # allow script to exit normally
        pass
    finally:
        end = time.perf_counter()
        sys.settrace(old_trace)
        sys.argv = old_argv
    wall = end - start
    return dict(call_counts), dict(line_counts), wall

# --- Dynamic measurement: safe subprocess (energy estimate only) --------------

def run_in_subprocess_measure_energy(target_path: str, target_args: List[str], cpu_power_w: float, carbon_intensity_g_per_kwh: float) -> Dict[str, Any]:
    """
    Runs the target in a subprocess and estimates runtime, CPU-time (approx), energy, and CO2.
    Returns a small dict with numbers. Requires psutil for better CPU sampling.
    """
    import subprocess
    import psutil  # ensure available
    cmd = [sys.executable, target_path] + target_args
    # start child
    p = subprocess.Popen(cmd)
    pid = p.pid
    proc = psutil.Process(pid)
    start = time.perf_counter()
    try:
        p.wait()
    except KeyboardInterrupt:
        p.terminate()
        p.wait()
    end = time.perf_counter()
    elapsed = end - start

    # attempt to get cpu times of child process (user+system)
    try:
        times = proc.cpu_times()
        cpu_time = times.user + getattr(times, "system", 0.0)
        # cpu_time may be 0 for very fast process; fallback to wall
        if cpu_time <= 0:
            cpu_time = elapsed
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        cpu_time = elapsed

    energy_joules = cpu_time * cpu_power_w
    energy_kwh = energy_joules / 3_600_000.0
    co2_grams = energy_kwh * carbon_intensity_g_per_kwh
    return {
        "wall_seconds": elapsed,
        "cpu_time_seconds": cpu_time,
        "energy_joules": energy_joules,
        "energy_kwh": energy_kwh,
        "co2_grams": co2_grams
    }

# --- Merge static + dynamic and pretty report ---------------------------------

def merge_and_report(static_result: Dict[str, Any],
                     dynamic_calls: Optional[Dict[str,int]],
                     dynamic_lines: Optional[Dict[int,int]],
                     energy_info: Optional[Dict[str,Any]],
                     target_path: str,
                     as_json: bool = False) -> None:

    per_scope = static_result.get("per_scope", {})
    # map static call-sites (per scope func_calls is count of call sites) to observed runtime counts
    # For readable report, produce:
    callsite_report = []
    for scope_name, stats in per_scope.items():
        # for the scope, extract loop lines and heavy allocations
        callsite_report.append({
            "scope": scope_name,
            "loops": stats.get("loops", 0),
            "max_loop_depth": stats.get("max_loop_depth", 0),
            "loop_lines": stats.get("loop_lines", []),
            "heavy_allocations_in_loops": stats.get("heavy_allocations_in_loops", []),
            "func_calls_sites": stats.get("func_calls", 0),
            "io_ops_sites": stats.get("io_ops", 0),
            "cyclomatic": stats.get("cyclomatic", 0),
            "score": stats.get("score", 0.0),
            "recursion": stats.get("recursion", []),
            "comprehensions": stats.get("comprehensions", 0),
            "conditionals": stats.get("conditionals", 0),
            "filename": stats.get("filename")
        })

    # Build per-function runtime summary (if we have dynamic_calls)
    funcs_runtime = []
    if dynamic_calls is not None:
        # dynamic_calls keys are function names (including '<module>' sometimes)
        for scope_name, stats in per_scope.items():
            # try to map using function name (scope key contains filename:func or similar)
            func_base = stats.get("name", scope_name)
            runtime_count = dynamic_calls.get(func_base, 0)
            funcs_runtime.append({"name": scope_name, "runtime_calls": runtime_count})

    # Loop iteration estimation from dynamic_lines
    loop_iterations = []
    if dynamic_lines is not None:
        # gather all loop lines across scopes
        loop_lines = sorted({ln for s in per_scope.values() for ln in s.get("loop_lines", [])})
        for ln in loop_lines:
            hits = dynamic_lines.get(ln, 0)
            loop_iterations.append({"lineno": ln, "estimated_iterations": hits})

    out = {
        "target": target_path,
        "static": per_scope,
        "callsite_summary": callsite_report,
        "functions_runtime": funcs_runtime,
        "loop_iterations": loop_iterations,
        "energy": energy_info,
        "raw_dynamic_calls": dynamic_calls,
        "raw_dynamic_lines": dynamic_lines,
    }

    # compute total score
    total_score = sum(s.get("score", 0.0) for s in per_scope.values())
    out["total_score"] = total_score

    if as_json:
        print(json.dumps(out, indent=2))
        return

    print("\n--- Hybrid Static + Dynamic Analysis ---")
    print(f"Target: {target_path}\n")
    # static summary per scope
    for scope, stats in per_scope.items():
        print(f"Scope: {scope}" + (f" (line {stats.get('lineno')})" if stats.get('lineno') else ""))
        print(f"  File: {stats.get('filename')}")
        print(f"  Loops: {stats.get('loops',0)} (max depth {stats.get('max_loop_depth',0)})")
        print(f"  Loop lines: {stats.get('loop_lines') or 'None'}")
        print(f"  Heavy allocs in loops: {stats.get('heavy_allocations_in_loops') or 'None'}")
        print(f"  Function-call sites: {stats.get('func_calls',0)}  |  I/O sites: {stats.get('io_ops',0)}")
        print(f"  Comprehensions: {stats.get('comprehensions',0)}  |  Cyclomatic: {stats.get('cyclomatic',0)}")
        print(f"  Score: {stats.get('score',0.0):.2f}")
        print("")

    # dynamic summaries
    if dynamic_calls is not None:
        print("Runtime function call counts (sample):")
        for fn, cnt in sorted(dynamic_calls.items(), key=lambda x: -x[1])[:30]:
            print(f"  {fn:<30} : {cnt}")
        print("")
    if loop_iterations:
        print("Loop header line hits (est. iterations):")
        for it in loop_iterations:
            print(f"  line {it['lineno']:>3}: ~{it['estimated_iterations']}")
        print("")

    if energy_info is not None:
        print("Energy estimate:")
        print(f"  Wall time: {energy_info.get('wall_seconds',0.0):.4f} s")
        if "cpu_time_seconds" in energy_info:
            print(f"  CPU time (est): {energy_info.get('cpu_time_seconds',0.0):.4f} s")
            print(f"  Energy: {energy_info.get('energy_joules',0.0):.1f} J (~{energy_info.get('energy_kwh',0.0):.6f} kWh)")
            print(f"  CO2 est.: {energy_info.get('co2_grams',0.0):.2f} g")
        print("")

    # suggestions
    print("Suggestions:")
    for s in suggestions_from_result(per_scope):
        print(f"- {s}")
    print("\nNotes:")
    print("- Static metrics are syntactic counts (call sites, loop headers, allocations).")
    print("- Dynamic metrics reflect actual runtime behavior (executions, line hits).")
    print("- If you used --trace (default), target was executed in-process under a tracer; side-effects occurred.")
    print("- Use --safe-subprocess for energy-only measurements without in-process tracing.")


# --- CLI ----------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Hybrid full analyzer: static checks + runtime measurements + energy estimate")
    p.add_argument("target", help="Python file or directory to analyze and (optionally) run")
    p.add_argument("--args", type=str, default="", help="space-separated args for target")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--trace", dest="trace", action="store_true", help="Run target in-process under tracer (default)")
    group.add_argument("--safe-subprocess", dest="safe_subprocess", action="store_true", help="Run target as subprocess and measure energy only (safer)")
    p.add_argument("--no-print", dest="no_print", action="store_true", help="Static: don't treat print()/input() as I/O")
    p.add_argument("--only-in-func", dest="only_in_func", action="store_true", help="Static: only count loops inside functions")
    p.add_argument("--power", type=float, default=15.0, help="CPU power in watts for energy estimate")
    p.add_argument("--ci", type=float, default=400.0, help="Carbon intensity (g CO2 per kWh)")
    p.add_argument("--json", action="store_true", help="Emit JSON output")
    args = p.parse_args()

    target = args.target
    if not os.path.exists(target):
        print("Target not found:", target)
        sys.exit(1)

    python_files = discover_python_files(target)
    if not python_files:
        print("No Python files found in target:", target)
        sys.exit(0)

    extra_args = args.args.split() if args.args else []
    count_print = not args.no_print
    only_in_func = args.only_in_func

    # static analysis: aggregate across files
    combined_static = {"per_scope": {}}
    total_score = 0.0

    for file in python_files:
        res, total = static_analyze_file(file, count_print=count_print, only_inside_functions=only_in_func)

        # include filename in every scope and namespace the key by file+scope
        for scope, data in res["per_scope"].items():
            key = f"{os.path.relpath(file)}:{scope}"
            # copy to avoid mutating original
            entry = dict(data)
            entry["filename"] = os.path.relpath(file)
            combined_static["per_scope"][key] = entry

        total_score += total

    static_result = combined_static
    static_total = total_score

    # dynamic part (only sensible when a single file is provided)
    dynamic_calls = None
    dynamic_lines = None
    energy_info = None

    # choose mode
    trace_mode = True if (args.trace or not args.safe_subprocess) else False

    # If exactly one python file, we can run dynamic tracer or subprocess energy estimate against it.
    if len(python_files) == 1:
        single = python_files[0]
        if trace_mode:
            # warn
            print("=== Running target in-process under tracer (side-effects WILL run). Use --safe-subprocess for safer energy-only mode. ===")
            dynamic_calls, dynamic_lines, wall = run_with_tracer_inprocess(single, extra_args)
            # estimate energy from wall time (conservative) using given power
            cpu_time_est = wall
            energy_joules = cpu_time_est * args.power
            energy_kwh = energy_joules / 3_600_000.0
            co2 = energy_kwh * args.ci
            energy_info = {
                "wall_seconds": wall,
                "cpu_time_seconds": cpu_time_est,
                "energy_joules": energy_joules,
                "energy_kwh": energy_kwh,
                "co2_grams": co2
            }
        else:
            # safe subprocess mode: measure energy & cpu approx using psutil
            try:
                energy_info = run_in_subprocess_measure_energy(single, extra_args, cpu_power_w=args.power, carbon_intensity_g_per_kwh=args.ci)
            except Exception as e:
                print("Subprocess energy measurement failed (psutil required). Error:", e)
                energy_info = None
    else:
        # many files: skip dynamic tracing for safety / practicality
        dynamic_calls = None
        dynamic_lines = None
        energy_info = None

    # produce merged report
    merge_and_report(static_result, dynamic_calls, dynamic_lines, energy_info, target, as_json=args.json)


if __name__ == "__main__":
    main()
