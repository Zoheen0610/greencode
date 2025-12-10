#!/usr/bin/env python3
"""
dynamic_profiler.py
Run a Python script and estimate CPU-time / energy / CO2 for that run.

Usage:
  python src/dynamic_profiler.py target_script.py [--power W] [--ci GperkWh] [--args 'arg1 arg2']
"""
import sys
import time
import subprocess
import psutil
import argparse


def run_and_profile(cmd_args, cpu_power_w=15.0, carbon_intensity_g_per_kwh=400.0):
    # Launch subprocess
    p = subprocess.Popen([sys.executable] + cmd_args)
    proc = psutil.Process(p.pid)

    # sample CPU times at start
    start = time.perf_counter()
    cpu_start = proc.cpu_times()
    # wait for completion (blocking)
    p.wait()
    end = time.perf_counter()
    try:
        cpu_end = proc.cpu_times()
        # proc.cpu_times() may raise if process gone; in that case we approximate with wall time
    except psutil.NoSuchProcess:
        cpu_end = cpu_start

    elapsed_wall = end - start
    # compute CPU time delta (user + system)
    cpu_time_seconds = (cpu_end.user + getattr(cpu_end, "system", 0.0)) - (cpu_start.user + getattr(cpu_start, "system", 0.0))
    if cpu_time_seconds <= 0:
        # fallback conservative estimate: use wall time
        cpu_time_seconds = elapsed_wall

    # energy: Joules = seconds * watts; convert to kWh: 1 kWh = 3.6e6 J
    energy_joules = cpu_time_seconds * cpu_power_w
    energy_kwh = energy_joules / 3_600_000.0
    co2_grams = energy_kwh * carbon_intensity_g_per_kwh

    return {
        "wall_seconds": elapsed_wall,
        "cpu_time_seconds": cpu_time_seconds,
        "energy_joules": energy_joules,
        "energy_kwh": energy_kwh,
        "co2_grams": co2_grams,
    }


def main():
    parser = argparse.ArgumentParser(description="Profile a Python run and estimate energy/CO2.")
    parser.add_argument("target", help="Python script to run")
    parser.add_argument("--power", type=float, default=15.0, help="Average CPU power (W)")
    parser.add_argument("--ci", type=float, default=400.0, help="Carbon intensity (g CO2 per kWh)")
    parser.add_argument("--args", type=str, default="", help="Space-separated args for target script")
    args = parser.parse_args()

    target = args.target
    extra = args.args.split() if args.args else []
    cmd = [target] + extra

    res = run_and_profile(cmd, cpu_power_w=args.power, carbon_intensity_g_per_kwh=args.ci)
    print("--- Dynamic Energy Estimate ---")
    print(f"Wall time: {res['wall_seconds']:.3f} s")
    print(f"Estimated CPU-time: {res['cpu_time_seconds']:.3f} s")
    print(f"Estimated Energy: {res['energy_joules']:.1f} J (~{res['energy_kwh']:.6f} kWh)")
    print(f"Estimated CO2: {res['co2_grams']:.2f} g")


if __name__ == "__main__":
    main()
