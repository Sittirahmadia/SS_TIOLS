#!/usr/bin/env python3
"""
SS-Tools Ultimate v3.0 - Anti-Cheat Screenshare Tool
Main entry point for the application.

Usage:
    python main.py          # Launch GUI
    python main.py --cli    # CLI mode (headless scan)
    python main.py --help   # Show help
"""
import sys
import os
import argparse
import json
import time

# Ensure the project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def run_gui():
    """Launch the PyQt6 GUI application."""
    from gui.main_window import main
    main()


def run_cli(args):
    """Run CLI-mode scan (headless) using parallel ScanEngine."""
    from core.config import AppSettings
    from core.utils import format_duration, severity_label, logger
    from core.database import CheatDatabase
    from core.scan_engine import ScanEngine
    from core.evidence_collector import ReportGenerator

    settings = AppSettings.load()
    if args.deep:
        settings.deep_scan_mode = True
    db = CheatDatabase()

    print("=" * 60)
    print("  SS-Tools Ultimate v3.0 - CLI Mode (Parallel Engine)")
    print(f"  Database: v{db.version}")
    print("=" * 60)

    scan_types = [s.strip() for s in (args.scan or "full").split(",")]

    all_results = []
    all_mod_results = []
    total_duration = 0.0

    for scan_type in scan_types:
        print(f"\n[*] Running {scan_type} scan (all scanners in parallel)...")

        engine = ScanEngine(settings)

        # Live progress callback
        engine.on_scanner_start = lambda name: print(f"  ⚡ Starting {name}...")
        engine.on_scanner_done = lambda name, results, dur: print(
            f"  ✓ {name}: {len(results)} findings in {format_duration(dur)}"
        )
        engine.on_scanner_error = lambda name, err: print(f"  ✗ {name}: ERROR — {err}")

        results, mod_results, duration = engine.run_scan(
            scan_type=scan_type,
            deep_scan=args.deep,
        )
        all_results.extend(results)
        all_mod_results.extend(mod_results)
        total_duration += duration

        # Print summary for this scan type
        summary = engine.get_summary()
        print(f"\n  Scanners: {summary['scanners_completed']}/{summary['scanners_total']} "
              f"(failed: {summary['scanners_failed']})")

    # Final summary
    critical = [r for r in all_results if r.severity >= 90]
    high = [r for r in all_results if 70 <= r.severity < 90]
    medium = [r for r in all_results if 50 <= r.severity < 70]
    low = [r for r in all_results if r.severity < 50]

    print("\n" + "=" * 60)
    print(f"  SCAN COMPLETE in {format_duration(total_duration)}")
    print(f"  Total: {len(all_results)} findings")
    print(f"  Critical: {len(critical)} | High: {len(high)} | Medium: {len(medium)} | Low: {len(low)}")

    if critical or len(high) > 2:
        print("\n  ██████  CHEATER DETECTED  ██████")
    else:
        print("\n  ✓ PLAYER CLEAN")
    print("=" * 60)

    # Print detailed findings
    if all_results and args.verbose:
        print("\nDetailed Findings:")
        for r in sorted(all_results, key=lambda x: -x.severity):
            print(f"  [{severity_label(r.severity):8}] [{r.scanner}] {r.name}: {r.description}")
            if r.filepath:
                print(f"           Path: {r.filepath}")
            if r.evidence:
                print(f"           Evidence: {r.evidence[:200]}")

    # Export
    if args.output:
        data = [r.to_dict() for r in all_results]
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"\nResults exported to: {args.output}")

    # Generate report
    if args.report:
        rg = ReportGenerator()
        path = rg.generate_html_report(
            all_results, scan_duration=total_duration,
            player_name=args.player or "Unknown",
            staff_name=args.staff or "Staff",
            server_name=args.server or "Server",
            mod_results=all_mod_results if all_mod_results else None,
        )
        print(f"Report generated: {path}")

    return 0 if not critical else 1


def main():
    parser = argparse.ArgumentParser(
        description="SS-Tools Ultimate v3.0 - Anti-Cheat Screenshare Tool"
    )
    parser.add_argument("--cli", action="store_true", help="Run in CLI mode (no GUI)")
    parser.add_argument("--scan", type=str, default="full",
                        help="Scan types: full,minecraft,mods,kernel,process,browser,deleted,memory,network")
    parser.add_argument("--deep", action="store_true", help="Enable deep scan mode")
    parser.add_argument("--output", "-o", type=str, help="Export results to JSON file")
    parser.add_argument("--report", action="store_true", help="Generate HTML report")
    parser.add_argument("--player", type=str, help="Player name for report")
    parser.add_argument("--staff", type=str, help="Staff name for report")
    parser.add_argument("--server", type=str, help="Server name for report")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    parser.add_argument("--update-db", action="store_true", help="Update cheat database")

    args = parser.parse_args()

    if args.update_db:
        from core.database import CheatDatabase
        db = CheatDatabase()
        db.auto_update()
        return

    if args.cli:
        sys.exit(run_cli(args))
    else:
        run_gui()


if __name__ == "__main__":
    main()
