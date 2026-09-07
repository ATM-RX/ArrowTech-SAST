import os
import ast
import re
import yaml
import subprocess
from rich.console import Console
from rich.table import Table

console = Console()

class SASTScanner:
    def __init__(self, target_path, rules_path="rules/custom_rules.yaml", scan_git=False):
        self.target_path = target_path
        self.scan_git = scan_git
        self.vulnerabilities = []
        self.custom_rules = self._load_rules(rules_path)

        # Baseline secrets pattern fallback
        self.fallback_pattern = re.compile(r'(?i)(api_key|secret|token|password)[\s:=]+[\'"]([a-zA-Z0-9_\-]{16,})[\'"]')

    def _load_rules(self, rules_path):
        try:
            if os.path.exists(rules_path):
                with open(rules_path, 'r') as f:
                    data = yaml.safe_load(f)
                    return data.get('rules', [])
        except Exception as e:
            console.print(f"[bold red][!] Error loading rules: {e}[/bold red]")
        return []

    def scan_content(self, filepath, content):
        # 1. Custom YAML Regex Rules
        lines = content.splitlines()
        for i, line in enumerate(lines):
            # Check Custom Rules
            for rule in self.custom_rules:
                if rule.get('type') == 'regex':
                    # Check extension filter
                    exts = rule.get('extensions', [])
                    if exts and not any(filepath.endswith(ext) for ext in exts):
                        continue
                        
                    if re.search(rule['pattern'], line):
                        self.vulnerabilities.append({
                            "file": filepath,
                            "line": i + 1,
                            "type": rule['description'],
                            "severity": rule['severity'],
                            "id": rule['id']
                        })
            
            # Check Fallback
            if self.fallback_pattern.search(line):
                self.vulnerabilities.append({
                    "file": filepath,
                    "line": i + 1,
                    "type": "Generic Hardcoded Secret/Token",
                    "severity": "CRITICAL",
                    "id": "GENERIC_SECRET"
                })

        # 2. AST Parsing (Python only)
        if filepath.endswith('.py'):
            self._scan_ast(filepath, content)

    def _scan_ast(self, filepath, content):
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in ['eval', 'exec']:
                        self.vulnerabilities.append({
                            "file": filepath,
                            "line": node.lineno,
                            "type": f"Dangerous function call: {node.func.id}()",
                            "severity": "HIGH",
                            "id": "AST_DANGEROUS_SINK"
                        })
        except SyntaxError:
            pass 

    def run(self):
        if self.scan_git:
            console.print("[bold cyan][*] Git integration activated. Scanning uncommitted changes...[/bold cyan]")
            self._scan_git_diff()
        else:
            if os.path.isfile(self.target_path):
                with open(self.target_path, 'r', encoding='utf-8', errors='ignore') as f:
                    self.scan_content(self.target_path, f.read())
            else:
                for root, dirs, files in os.walk(self.target_path):
                    if '.git' in dirs:
                        dirs.remove('.git') # Ignore .git directory
                    for file in files:
                        if file.endswith(('.py', '.js', '.json', '.env', '.txt', '.pem', '.key')):
                            filepath = os.path.join(root, file)
                            try:
                                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                                    self.scan_content(filepath, f.read())
                            except Exception:
                                pass
        
        self._report()

    def _scan_git_diff(self):
        try:
            # Get modified and untracked files
            result = subprocess.run(['git', '-C', self.target_path, 'ls-files', '--modified', '--others', '--exclude-standard'], 
                                  capture_output=True, text=True)
            files = result.stdout.splitlines()
            if not files:
                console.print("[green][+] No uncommitted changes found.[/green]")
                return

            for file in files:
                filepath = os.path.join(self.target_path, file)
                if os.path.isfile(filepath):
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            self.scan_content(filepath, f.read())
                    except Exception:
                        pass
        except Exception as e:
            console.print(f"[bold red][!] Git integration error: {e}[/bold red]")

    def _report(self):
        console.print("\n[bold]---- Scan Complete ----[/bold]")
        if not self.vulnerabilities:
            console.print("[bold green][+] Zero vulnerabilities detected. Architecture is clean.[/bold green]")
            return

        table = Table(title="Vulnerability Report", show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="dim", width=12)
        table.add_column("Rule ID")
        table.add_column("File:Line", justify="left", style="cyan")
        table.add_column("Description")

        for vuln in self.vulnerabilities:
            sev_color = "red" if vuln['severity'] == 'CRITICAL' else ("yellow" if vuln['severity'] == 'HIGH' else "white")
            table.add_row(
                f"[{sev_color}]{vuln['severity']}[/{sev_color}]",
                vuln['id'],
                f"{vuln['file']}:{vuln['line']}",
                vuln['type']
            )

        console.print(table)
