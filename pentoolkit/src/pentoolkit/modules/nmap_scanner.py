import subprocess
import shlex
import nmap
from pentoolkit.utils import report
from rich.console import Console
from rich.table import Table
from collections import Counter

console = Console()


def _run_nmap_raw_xml(target: str, args: str) -> str | None:
    """
    Run system 'nmap' to produce XML to stdout and return it as text.
    Falls back to None on failure.
    """
    # Build command: nmap <args> -oX -
    # Keep target near front for readability
    cmd = f"nmap {target} {args} -oX -"
    try:
        completed = subprocess.run(
            shlex.split(cmd),
            capture_output=True,
            text=True,
            timeout=300
        )
        if completed.returncode == 0 or completed.stdout:
            return completed.stdout
        else:
            return None
    except Exception as e:
        # Do not crash the whole scan if subprocess fails
        print(f"[!] Could not get raw nmap XML via subprocess: {e}")
        return None


def scan(target: str, scan_type: str = "default", nse: str = None, extra_args: str = ""):
    print(f"[Nmap] Scanning {target}...")

    nm = nmap.PortScanner()
    nmap_args = ""

    # Map scan_type to Nmap arguments
    if scan_type == "syn":
        nmap_args = "-sS -sV"
    elif scan_type == "udp":
        nmap_args = "-sU -sV"
    elif scan_type == "aggressive":
        nmap_args = "-A -sV"
    else:  # default
        nmap_args = "-sV"

    # Include NSE scripts if provided
    if nse:
        nmap_args += f" --script {nse}"

    # Include any extra arguments
    if extra_args:
        nmap_args += f" {extra_args}"

    # Trim and normalize args
    nmap_args = nmap_args.strip()

    # Try running python-nmap first (so your existing parsing works)
    try:
        nm.scan(target, arguments=nmap_args)
    except Exception as e:
        print(f"[!] Nmap scan (python-nmap) failed: {e}")
        # Don't return yet — we may try to capture raw XML with subprocess below

    open_ports = []

    try:
        # Loop through all hosts and their protocols - guard against missing hosts
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port].get('state', 'unknown')
                    service = nm[host][proto][port].get('name', 'unknown')
                    product = nm[host][proto][port].get('product', '')
                    version = nm[host][proto][port].get('version', '')

                    if state == "open":  # only log open ports
                        open_ports.append({
                            "port": port,
                            "protocol": proto,
                            "service": service,
                            "product": product,
                            "version": version,
                            "state": state
                        })
    except Exception as e:
        # If python-nmap structure differs, don't break everything
        print(f"[!] Error parsing python-nmap results: {e}")

    # --- Additional: capture raw XML using system nmap (best effort) ---
    raw_xml = _run_nmap_raw_xml(target, nmap_args)
    if raw_xml:
        # Save raw xml alongside other reports
        report.save_raw(target, "nmap", raw_xml)

    # Build a service summary (counts by service name)
    service_counts = Counter([p["service"] for p in open_ports])

    # Print results nicely (rich table)
    if open_ports:
        table = Table(title=f"Nmap Scan Results for {target}")
        table.add_column("Port", justify="center")
        table.add_column("Protocol")
        table.add_column("Service")
        table.add_column("Product")
        table.add_column("Version")
        table.add_column("State", justify="center")

        for p in open_ports:
            state_color = "green" if p["state"] == "open" else "red"
            table.add_row(
                str(p["port"]),
                p["protocol"],
                p["service"],
                p["product"],
                p["version"],
                f"[{state_color}]{p['state']}[/{state_color}]"
            )

        console.print(table)
    else:
        console.print(f"[Nmap] No open ports found on {target}", style="yellow")

    # Persist JSON and HTML; include service_summary in the saved data
    data = {
        "open_ports": open_ports,
        "service_summary": dict(service_counts),
        "nmap_args": nmap_args
    }

    if open_ports or raw_xml:
        report.save_report(data, target, "nmap")
        report.save_report_html(data, target, "nmap")
        if raw_xml:
            # already saved via report.save_raw above
            pass

    return open_ports
