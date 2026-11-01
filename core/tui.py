"""
VulnForge TUI Dashboard
A live-refreshing terminal dashboard (Textual) over the local scan history:
a table of recent scans across all targets, and a risk-trend summary for
whichever row is selected. Read-only — it never starts or modifies a scan,
it just reads reports/history.db on a timer.

Optional dependency: pip install textual
"""
import logging

logger = logging.getLogger("vulnforge.tui")

try:
    from textual.app import App, ComposeResult
    from textual.widgets import DataTable, Footer, Header, Static

    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False


if TEXTUAL_AVAILABLE:

    class VulnForgeDashboard(App):
        """Live dashboard over reports/history.db."""

        CSS = """
        #trend { height: auto; border: round $accent; padding: 1; }
        #scans { height: 1fr; }
        """
        BINDINGS = [("r", "refresh_now", "Refresh"), ("q", "quit", "Quit")]
        TITLE = "VulnForge Dashboard"

        def __init__(self, config: dict, refresh_seconds: float = 10.0):
            super().__init__()
            self.config = config
            self.refresh_seconds = refresh_seconds
            self._selected_target: str | None = None

        def compose(self) -> ComposeResult:
            yield Header()
            yield Static("Select a row to see its risk trend.", id="trend")
            yield DataTable(id="scans")
            yield Footer()

        def on_mount(self) -> None:
            table = self.query_one("#scans", DataTable)
            table.add_columns("Scan ID", "Target", "Started", "Duration", "Risk", "Findings")
            table.cursor_type = "row"
            self.refresh_data()
            self.set_interval(self.refresh_seconds, self.refresh_data)

        def refresh_data(self) -> None:
            from core.history import ScanHistory

            rows = ScanHistory(self.config).list_scans(limit=50)
            table = self.query_one("#scans", DataTable)
            table.clear()
            for r in rows:
                table.add_row(
                    r["scan_id"], r["target"], r["start_time"],
                    f"{r['duration']}s", str(r["risk_score"]), str(r["total_findings"]),
                    key=r["scan_id"],
                )
            if rows and self._selected_target is None:
                self._selected_target = rows[0]["target"]
            if self._selected_target:
                self.update_trend(self._selected_target)

        def update_trend(self, target: str) -> None:
            from core.history import ScanHistory
            from core.trends import build_trend

            results = ScanHistory(self.config).list_results(target, 10)
            panel = self.query_one("#trend", Static)
            if not results:
                panel.update(f"[b]{target}[/b]  no scan history")
                return
            t = build_trend(results)
            panel.update(
                f"[b]{target}[/b]  risk {t['sparkline']}  {t['direction']}  "
                f"new since previous: {len(t['new_since_previous'])}  "
                f"resolved since previous: {len(t['resolved_since_previous'])}"
            )

        def on_data_table_row_selected(self, event) -> None:
            table = self.query_one("#scans", DataTable)
            try:
                row = table.get_row(event.row_key)
                self._selected_target = row[1]
                self.update_trend(self._selected_target)
            except Exception as exc:
                logger.debug(f"Row selection lookup failed: {exc}")

        def action_refresh_now(self) -> None:
            self.refresh_data()

else:
    VulnForgeDashboard = None  # type: ignore


def run_dashboard(config: dict, refresh_seconds: float = 10.0) -> None:
    if not TEXTUAL_AVAILABLE:
        raise RuntimeError(
            "The TUI dashboard needs the 'textual' package, which isn't installed. "
            "Install it with: pip install textual"
        )
    VulnForgeDashboard(config, refresh_seconds).run()
