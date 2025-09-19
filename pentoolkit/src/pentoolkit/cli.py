# pentoolkit/cli.py
import typer
from pentoolkit import main
from pentoolkit.utils import report

import http.server
import socketserver
import webbrowser
import os

app = typer.Typer(help="Pentoolkit CLI")

scan_app = typer.Typer(help="Run scans")
report_app = typer.Typer(help="View reports")

app.add_typer(scan_app, name="scan")
app.add_typer(report_app, name="report")


@scan_app.command("run")
def run_scan(
    target: str = typer.Argument(..., help="Target hostname or URL (e.g., example.com or https://example.com)"),
    modules: str = typer.Option(
        "all",
        help="Modules to run (comma-separated or 'all'). Options: nmap, ssl, whois, waf, web_recon"
    ),
    scan_type: str = typer.Option("default", help="nmap scan type: default,syn,udp,aggressive"),
    nmap_args: str = typer.Option("", help="Custom Nmap arguments (advanced)")
):
    """
    Run scans on a target.

    Example:
      pentoolkit scan run scanme.nmap.org --modules nmap,ssl
      pentoolkit scan run https://rivedix.com --modules nmap,web_recon --nmap-args "-sC -O"
    """
    typer.echo(f"[+] Running scans on: {target} (modules={modules})")
    results = main.run_scan(target, modules, scan_type=scan_type, extra_args=nmap_args)
    typer.echo("[+] Scan finished.")

    # Show short summary (not full JSON)
    if results:
        for module, result in results.items():
            if result:
                typer.echo(f"[+] {module.upper()} module: results saved to reports/")
            else:
                typer.echo(f"[!] {module.upper()} module: no results")


# Optional dedicated subcommand for web-recon with more control
@scan_app.command("web-recon")
def run_web_recon(
    target: str = typer.Argument(..., help="Target URL (e.g., https://example.com)"),
    wordlist: str = typer.Option("/usr/share/wordlists/dirb/common.txt", help="Wordlist path for ffuf"),
    extensions: str = typer.Option("", help="File extensions to fuzz (comma-separated, e.g., php,html)"),
    threads: int = typer.Option(40, help="Number of threads"),
    timeout: int = typer.Option(10, help="Request timeout in seconds")
):
    """Run Web Recon (ffuf) on a target."""
    from pentoolkit.modules import web_recon
    web_recon.run_ffuf(target, wordlist=wordlist, extensions=extensions, threads=threads, timeout=timeout)


@report_app.command("list")
def list_reports():
    """List all saved reports"""
    reports = report.list_reports()
    if not reports:
        typer.echo("[!] No reports found.")
    else:
        typer.echo("Available reports:")
        for r in reports:
            typer.echo(f"  - {r}")


@report_app.command("show")
def show_report(filename: str):
    """Show a saved report by filename"""
    data = report.load_report(filename)
    if not data:
        typer.echo(f"[!] Could not read {filename}")
        return
    typer.echo(f"[+] Loaded {filename}. Use 'pentoolkit report serve' to view HTML reports in browser.")


@report_app.command("summary")
def report_summary(target: str = typer.Argument(..., help="Target hostname or IP")):
    """
    Generate a single aggregated HTML report for a target by combining per-module reports.
    Example: pentoolkit report summary 172.16.1.47
    """
    typer.echo(f"[+] Building aggregated report for: {target}")
    summary_obj, html_path = report.aggregate_target_reports(target)
    if html_path:
        typer.echo(f"[+] Aggregated report created: {html_path}")
    else:
        typer.echo("[!] Aggregation failed or no reports found.")


@report_app.command("serve")
def serve_reports(port: int = typer.Option(8080, help="Port to serve reports on (default: 8080)"),
                  open_browser: bool = typer.Option(True, help="Open the reports page in default browser")):
    """
    Serve the reports/ directory over HTTP so you can browse HTML reports.
    Example: pentoolkit report serve --port 8080
    """
    report_dir = report.REPORT_DIR if hasattr(report, "REPORT_DIR") else os.path.join(os.path.abspath(os.path.dirname(__file__)), "..", "reports")
    report_dir = os.path.abspath(report_dir)

    if not os.path.isdir(report_dir):
        typer.echo(f"[!] Reports directory does not exist: {report_dir}")
        raise typer.Exit(code=1)

    typer.echo(f"[+] Serving reports from: {report_dir} at http://localhost:{port}/")
    os.chdir(report_dir)

    Handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", port), Handler) as httpd:
        if open_browser:
            try:
                webbrowser.open(f"http://localhost:{port}/")
            except Exception:
                pass
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            typer.echo("[+] Stopped serving reports.")


if __name__ == "__main__":
    app()
