#!/usr/bin/env python3
import argparse
import sys
import os
from core.scanner import SASTScanner

def main():
    parser = argparse.ArgumentParser(description="RexSAST: High-Velocity Static Analysis")
    parser.add_argument("path", help="Directory or file to scan", default=".", nargs="?")
    parser.add_argument("--git", action="store_true", help="Scan only uncommitted git changes")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"[-] Error: Path '{args.path}' does not exist.")
        sys.exit(1)

    # Move to path for proper relative rule loading if running outside
    engine_dir = os.path.dirname(os.path.abspath(__file__))
    rules_path = os.path.join(engine_dir, "rules", "custom_rules.yaml")

    scanner = SASTScanner(target_path=args.path, rules_path=rules_path, scan_git=args.git)
    scanner.run()

if __name__ == "__main__":
    main()
