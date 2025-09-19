import socket
import ssl
from datetime import datetime
from pentoolkit.utils import report
from rich.console import Console
from rich.table import Table

console = Console()

def print_ssl_table(results: dict):
    """Print SSL info in a Rich table."""
    table = Table(title=f"SSL Certificate - {results.get('target')}:{results.get('port', 443)}")
    table.add_column("Field", style="bold cyan")
    table.add_column("Value", style="white")

    table.add_row("SSL Version", results.get("ssl_version", "-"))
    table.add_row("Subject", ", ".join([f"{k}={v}" for k, v in results.get("subject", {}).items()]))
    table.add_row("Issuer", ", ".join([f"{k}={v}" for k, v in results.get("issuer", {}).items()]))

    valid_until = results.get("valid_until")
    if valid_until:
        try:
            expiry_dt = datetime.strptime(valid_until, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry_dt - datetime.utcnow()).days
            expiry_str = f"{valid_until} ({days_left} days left)"
            if days_left < 15:
                expiry_str = f"[red]{expiry_str}[/red]"
            elif days_left < 30:
                expiry_str = f"[yellow]{expiry_str}[/yellow]"
        except Exception:
            expiry_str = valid_until
    else:
        expiry_str = "-"
    table.add_row("Valid Until", expiry_str)

    console.print(table)


def scan(target: str, port: int = 443):
    console.print(f"[SSL] Checking {target}:{port}")
    results = {}

    # Resolve host
    try:
        socket.gethostbyname(target)
    except socket.gaierror:
        console.print(f"[red][!] Could not resolve {target}[/red]")
        return None

    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()

                # Extract details
                ssl_version = ssock.version()
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")

                results = {
                    "target": target,
                    "port": port,
                    "ssl_version": ssl_version,
                    "subject": subject,
                    "issuer": issuer,
                    "valid_from": not_before,
                    "valid_until": not_after,
                }

    except Exception as e:
        console.print(f"[red][!] SSL scan failed: {e}[/red]")
        return None

    if results:
        report.save_report(results, target, "ssl")
        report.save_report_html(results, target, "ssl")
        print_ssl_table(results)  # ← Rich table output

    return results
