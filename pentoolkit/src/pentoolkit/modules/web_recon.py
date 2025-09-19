# pentoolkit/modules/web_recon.py
import subprocess
import shlex
import os
from datetime import datetime
from pentoolkit.utils import report
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# Default wordlist path (adjust for your environment)
DEFAULT_WORDLIST = "/home/admin-1/Desktop/common.txt"


def sanitize_target(target: str) -> str:
    """
    Make a filesystem-safe version of a URL/hostname:
    - strip scheme, replace slashes/colon with underscores
    - Example: https://rivedix.com -> rivedix.com
    """
    t = target.strip()
    if t.startswith("https://"):
        t = t[len("https://") :]
    elif t.startswith("http://"):
        t = t[len("http://") :]
    # replace path separators and colons with underscore
    t = t.replace("/", "_").replace(":", "_")
    return t


def run_ffuf(
    target: str,
    wordlist: str = DEFAULT_WORDLIST,
    extensions: str = "",
    threads: int = 40,
    timeout: int = 10,
):
    """
    Run ffuf against a target and save JSON + HTML reports.

    Returns: parsed JSON output (dict) or None on failure.
    """
    console.print(f"[bold blue][WebRecon][/bold blue] Running ffuf on {target}")

    # Ensure report dir exists
    safe_target = sanitize_target(target)
    os.makedirs(report.REPORT_DIR, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    json_output = os.path.join(
        report.REPORT_DIR, f"{safe_target}_web_recon_{timestamp}.json"
    )

    # Build ffuf command
    # -u <target>/FUZZ
    # -w <wordlist>
    # -t <threads>
    # -timeout <timeout>
    # -o <json_output> -of json
    cmd_parts = [
        "ffuf",
        "-u",
        f"{target.rstrip('/')}/FUZZ",
        "-w",
        wordlist,
        "-t",
        str(threads),
        "-timeout",
        str(timeout),
        "-o",
        json_output,
        "-of",
        "json",
    ]
    if extensions:
        # ffuf expects -e ext1,ext2
        cmd_parts += ["-e", extensions]

    cmd = " ".join(shlex.quote(p) for p in cmd_parts)
    console.print(f"[cyan]Command:[/cyan] {cmd}")

    # Run ffuf with a progress spinner
    try:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
            task = progress.add_task("Fuzzing...", start=False)
            progress.start_task(task)
            subprocess.run(shlex.split(cmd), check=True)
            progress.update(task, description="[green]Fuzzing completed[/green]")
    except FileNotFoundError:
        console.print("[red]ffuf not found. Please install ffuf and ensure it is in PATH.[/red]")
        return None
    except subprocess.CalledProcessError as e:
        console.print(f"[red]ffuf failed: {e}[/red]")
        return None

    # Attempt to load ffuf JSON output
    data = {}
    try:
        import json

        with open(json_output, "r") as fh:
            data = json.load(fh)
    except Exception as e:
        console.print(f"[yellow]Could not read ffuf output JSON (file may be empty): {e}[/yellow]")

    # Save using Pentoolkit reporting functions (use safe_target to keep naming consistent)
    report.save_report(data, safe_target, "web_recon")
    report.save_report_html(data, safe_target, "web_recon")

    # Print CLI summary
    print_ffuf_table(data, safe_target)

    return data


def print_ffuf_table(data: dict, target: str):
    """Pretty-print top results of ffuf scan in a Rich table."""
    if not data or "results" not in data or not data.get("results"):
        console.print("[yellow]No results found.[/yellow]")
        return

    table = Table(title=f"Web Recon - {target}")
    table.add_column("URL", style="cyan", overflow="fold")
    table.add_column("Status", style="green")
    table.add_column("Length", justify="right")
    table.add_column("Words", justify="right")
    table.add_column("Lines", justify="right")

    # Show the first N results (ffuf already sorts by match)
    for item in data.get("results", []):
        table.add_row(
            item.get("url", "-"),
            str(item.get("status", "-")),
            str(item.get("length", "-")),
            str(item.get("words", "-")),
            str(item.get("lines", "-")),
        )

    console.print(table)


if __name__ == "__main__":
    target_host = input("Enter target URL (e.g., https://example.com): ").strip()
    run_ffuf(target_host)
