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
    """Run CLI-mode scan (headless)."""
    from core.config import AppSettings
    from core.utils import ScanResult, ScanProgress, format_duration, severity_label, logger
    from core.database import CheatDatabase
    from core.minecraft_scanner import MinecraftScanner
    from core.mods_scanner import ModsScanner
    from core.kernel_check import KernelCheck
    from core.process_scanner import ProcessScanner
    from core.string_deleted_scanner import StringDeletedScanner
    from core.browser_scanner import BrowserScanner
    from core.deleted_file_detector import DeletedFileDetector
    from core.memory_scanner import MemoryScanner
    from core.network_scanner import NetworkScanner
    from core.evidence_collector import EvidenceCollector, ReportGenerator

    settings = AppSettings.load()
    db = CheatDatabase()
    progress = ScanProgress()
    all_results = []

    print("=" * 60)
    print("  SS-Tools Ultimate v3.0 - CLI Mode")
    print(f"  Database: v{db.version}")
    print("=" * 60)

    start_time = time.time()

    scan_types = args.scan.split(",") if args.scan else ["full"]

    for scan_type in scan_types:
        scan_type = scan_type.strip()
        print(f"\n[*] Running {scan_type} scanner...")

        try:
            if scan_type in ("full", "minecraft"):
                results = MinecraftScanner(progress).scan_all()
                all_results.extend(results)
                print(f"    Minecraft Scanner: {len(results)} findings")

            if scan_type in ("full", "mods"):
                scanner = ModsScanner(progress, settings)
                mod_files = scanner.find_all_mods()
                print(f"    Found {len(mod_files)} mod files")
                mod_results = scanner.scan_mods(mod_files, args.deep)
                for mr in mod_results:
                    if mr.status != "CLEAN":
                        all_results.append(ScanResult(
                            scanner="ModsScanner",
                            category=f"mod_{mr.status.lower()}",
                            name=mr.filename,
                            description=f"{mr.status}: {mr.filename}",
                            severity=mr.severity,
                            filepath=mr.filepath,
                        ))
                cheats = [m for m in mod_results if m.status == "CHEAT_DETECTED"]
                suspicious = [m for m in mod_results if m.status == "SUSPICIOUS"]
                print(f"    Mods Scanner: {len(cheats)} cheats, {len(suspicious)} suspicious")

            if scan_type in ("full", "kernel"):
                results = KernelCheck(progress).scan()
                all_results.extend(results)
                print(f"    Kernel Check: {len(results)} findings")

            if scan_type in ("full", "process"):
                results = ProcessScanner(progress).scan()
                all_results.extend(results)
                print(f"    Process Scanner: {len(results)} findings")

            if scan_type in ("full", "browser"):
                results = BrowserScanner(progress).scan()
                all_results.extend(results)
                print(f"    Browser Scanner: {len(results)} findings")

            if scan_type in ("full", "deleted"):
                results = StringDeletedScanner(progress).scan()
                all_results.extend(results)
                results2 = DeletedFileDetector(progress).scan()
                all_results.extend(results2)
                print(f"    Deleted Scanner: {len(results) + len(results2)} findings")

            if scan_type in ("full", "memory"):
                results = MemoryScanner(progress).scan()
                all_results.extend(results)
                print(f"    Memory Scanner: {len(results)} findings")

            if scan_type in ("full", "network"):
                results = NetworkScanner(progress).scan()
                all_results.extend(results)
                print(f"    Network Scanner: {len(results)} findings")

        except Exception as e:
            print(f"    Error in {scan_type}: {e}")

    duration = time.time() - start_time

    # Summary
    critical = [r for r in all_results if r.severity >= 90]
    high = [r for r in all_results if 70 <= r.severity < 90]
    medium = [r for r in all_results if 50 <= r.severity < 70]
    low = [r for r in all_results if r.severity < 50]

    print("\n" + "=" * 60)
    print(f"  SCAN COMPLETE in {format_duration(duration)}")
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
            all_results, scan_duration=duration,
            player_name=args.player or "Unknown",
            staff_name=args.staff or "Staff",
            server_name=args.server or "Server",
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
