from rich.console import Console
from rich.table import Table
from rich.text import Text


def print_section(console: Console, title: str, data):
    console.print(f"\n[bold green]▸ {title}[/bold green]")

    if isinstance(data, dict):
        for key, val in data.items():
            if not val and val != 0:
                continue
            if isinstance(val, list):
                if not val:
                    continue
                console.print(f"  [dim]{key}:[/dim]")
                for item in val:
                    console.print(f"    [white]• {item}[/white]")
            elif isinstance(val, dict):
                console.print(f"  [dim]{key}:[/dim]")
                for k, v in val.items():
                    console.print(f"    [white]{k}: {v}[/white]")
            else:
                console.print(f"  [dim]{key}:[/dim] [white]{val}[/white]")

    elif isinstance(data, list):
        if not data:
            console.print("  [dim]none[/dim]")
            return
        for item in data:
            if isinstance(item, dict):
                parts = "  ".join(f"[dim]{k}:[/dim] [white]{v}[/white]" for k, v in item.items() if v)
                console.print(f"  • {parts}")
            else:
                console.print(f"  • [white]{item}[/white]")


def print_finding(console: Console, label: str, value: str, severity: str = "info"):
    colors = {"info": "cyan", "warn": "yellow", "high": "red"}
    color = colors.get(severity, "white")
    console.print(f"  [{color}]■[/{color}] {label}: {value}")
