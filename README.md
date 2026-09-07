# RexSAST Engine

A hyper-optimized, lightweight Static Application Security Testing (SAST) engine designed for high-velocity execution in resource-constrained environments (like Android/Termux).

## Features
- **Regex-based Secret Detection:** Instantly flags high-entropy hardcoded secrets, API keys, and tokens.
- **AST Logic Analysis:** Parses Python Abstract Syntax Trees (AST) natively to identify dangerous execution sinks (e.g., `eval()`, `exec()`).
- **Termux Native:** Zero heavy binary dependencies. Pure Python implementation for maximum portability.

## Usage
```bash
python3 cli.py /path/to/target/directory
```
