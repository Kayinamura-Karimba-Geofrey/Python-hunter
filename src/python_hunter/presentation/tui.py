"""Interactive Terminal User Interface (TUI) Dashboard for Python Hunter.

Provides rich curses-based terminal navigation across multi-domain findings,
attack paths, and remediation advisories with keyboard navigation and non-tty fallback.
"""

import curses
import os
import sys
from typing import Any

from python_hunter import __version__
from python_hunter.application.orchestrator.scan_context import ScanResult
from python_hunter.application.orchestrator.scan_orchestrator import ScanOrchestrator
from python_hunter.domain.common.enums import Severity
from python_hunter.domain.findings.finding import Finding


class SecurityTUI:
    """Curses-driven interactive terminal dashboard."""

    TAB_NAMES = ["ALL", "MALWARE", "SECRETS", "SUPPLY_CHAIN", "SAST"]

    def __init__(self, target_path: str = ".", scan_result: ScanResult | None = None) -> None:
        self.target_path = target_path
        self.scan_result = scan_result or ScanOrchestrator().run_scan(target_path)
        self.active_tab_idx = 0
        self.selected_finding_idx = 0
        self.scroll_offset = 0

    def get_tab_findings(self, tab_idx: int) -> list[Finding]:
        """Filter findings according to active category tab."""
        all_f = self.scan_result.findings
        if tab_idx == 0:
            return all_f
        elif tab_idx == 1:
            return [f for f in all_f if getattr(f, "category", None) and f.category.value == "MALWARE_RISK"]
        elif tab_idx == 2:
            return [f for f in all_f if getattr(f, "category", None) and f.category.value == "SECRET_LEAK"]
        elif tab_idx == 3:
            return [
                f for f in all_f
                if getattr(f, "category", None)
                and f.category.value in ("SUPPLY_CHAIN", "VULNERABLE_DEPENDENCY", "DEPENDENCY")
            ]
        elif tab_idx == 4:
            malware = self.get_tab_findings(1)
            secrets = self.get_tab_findings(2)
            supply = self.get_tab_findings(3)
            return [f for f in all_f if f not in malware and f not in secrets and f not in supply]
        return all_f

    def run(self) -> int:
        """Run interactive curses loop or fallback to ANSI snapshot in non-tty mode."""
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            sys.stdout.write(self.render_snapshot() + "\n")
            return 0

        try:
            return curses.wrapper(self._curses_main)
        except Exception:
            sys.stdout.write(self.render_snapshot() + "\n")
            return 0

    def _init_colors(self) -> None:
        """Initialize curses color pairs."""
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED, -1)     # Critical / Failed
        curses.init_pair(2, curses.COLOR_YELLOW, -1)  # High / Medium
        curses.init_pair(3, curses.COLOR_GREEN, -1)   # Low / Passed
        curses.init_pair(4, curses.COLOR_CYAN, -1)    # Highlights
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLUE)  # Selected header
        curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_WHITE) # Inverted selection

    def _curses_main(self, stdscr: curses.window) -> int:
        curses.curs_set(0)
        stdscr.nodelay(False)
        self._init_colors()

        while True:
            stdscr.clear()
            max_y, max_x = stdscr.getmaxyx()

            if max_y < 12 or max_x < 50:
                stdscr.addstr(0, 0, "Terminal too small for Python Hunter TUI.")
                stdscr.refresh()
                key = stdscr.getch()
                if key in (ord('q'), ord('Q')):
                    break
                continue

            findings = self.get_tab_findings(self.active_tab_idx)
            if self.selected_finding_idx >= len(findings):
                self.selected_finding_idx = max(0, len(findings) - 1)

            # 1. Header
            risk_score = self.scan_result.project_risk.overall_score if self.scan_result.project_risk else 0.0
            gate_str = "PASSED" if self.scan_result.exit_code == 0 else "FAILED"
            gate_pair = curses.color_pair(3) if self.scan_result.exit_code == 0 else curses.color_pair(1)

            header_title = f" PYTHON HUNTER TUI v{__version__} "
            stdscr.addstr(0, 0, header_title.ljust(max_x), curses.color_pair(5) | curses.A_BOLD)

            sub_header = f" Target: {self.target_path} | Risk: {risk_score:.1f}/100 | Policy: "
            stdscr.addstr(1, 0, sub_header)
            stdscr.addstr(1, len(sub_header), gate_str, gate_pair | curses.A_BOLD)
            stdscr.addstr(1, len(sub_header) + len(gate_str), f" | Findings: {len(self.scan_result.findings)}")

            # 2. Tabs Bar
            tab_x = 2
            for i, name in enumerate(self.TAB_NAMES):
                count = len(self.get_tab_findings(i))
                tab_text = f" [{i+1}] {name} ({count}) "
                if i == self.active_tab_idx:
                    stdscr.addstr(2, tab_x, tab_text, curses.color_pair(6) | curses.A_BOLD)
                else:
                    stdscr.addstr(2, tab_x, tab_text, curses.color_pair(4))
                tab_x += len(tab_text) + 1

            stdscr.addstr(3, 0, "─" * (max_x - 1))

            # 3. Split Windows
            split_x = max(25, int(max_x * 0.45))
            list_height = max_y - 6

            # Left Pane: Finding List
            for row in range(list_height):
                f_idx = self.scroll_offset + row
                curr_y = 4 + row
                if f_idx < len(findings):
                    f = findings[f_idx]
                    sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                    sev_pair = curses.color_pair(1) if sev == "CRITICAL" else (curses.color_pair(2) if sev in ("HIGH", "MEDIUM") else curses.color_pair(3))

                    badge = f"[{sev[:4]}]"
                    title = f.title[:split_x - 14]

                    line_str = f" {badge} {title} "
                    if f_idx == self.selected_finding_idx:
                        stdscr.addstr(curr_y, 1, line_str.ljust(split_x - 2), curses.color_pair(6) | curses.A_BOLD)
                    else:
                        stdscr.addstr(curr_y, 1, badge, sev_pair | curses.A_BOLD)
                        stdscr.addstr(curr_y, 1 + len(badge), f" {title}")
                else:
                    if not findings and row == 0:
                        stdscr.addstr(curr_y, 2, "No findings in this category.", curses.color_pair(3))

            # Vertical separator
            for row in range(list_height):
                stdscr.addstr(4 + row, split_x, "│")

            # Right Pane: Inspector Details
            if findings and self.selected_finding_idx < len(findings):
                sf = findings[self.selected_finding_idx]
                detail_x = split_x + 2
                detail_w = max_x - detail_x - 2

                stdscr.addstr(4, detail_x, f"RULE: {sf.rule_id}", curses.color_pair(4) | curses.A_BOLD)
                sev_str = sf.severity.value if hasattr(sf.severity, "value") else str(sf.severity)
                stdscr.addstr(5, detail_x, f"SEVERITY: {sev_str} | CONFIDENCE: {sf.confidence.value}")
                stdscr.addstr(6, detail_x, f"FILE: {sf.file_path}:{sf.location.line_start if sf.location else 1}")

                stdscr.addstr(7, detail_x, "─" * (detail_w))
                stdscr.addstr(8, detail_x, "TITLE: " + sf.title[:detail_w], curses.A_BOLD)

                # Description
                stdscr.addstr(9, detail_x, "DESCRIPTION:")
                desc_lines = sf.description[:detail_w * 3].splitlines()
                for d_i, d_line in enumerate(desc_lines[:3]):
                    stdscr.addstr(10 + d_i, detail_x + 2, d_line[:detail_w - 4])

                # Evidence
                ev_y = 10 + min(3, len(desc_lines)) + 1
                if ev_y < max_y - 8:
                    stdscr.addstr(ev_y, detail_x, "EVIDENCE:")
                    stdscr.addstr(ev_y + 1, detail_x + 2, (sf.evidence or "-")[:detail_w - 4], curses.color_pair(2))

                # Remediation
                rem_y = ev_y + 3
                if rem_y < max_y - 4:
                    stdscr.addstr(rem_y, detail_x, "REMEDIATION:", curses.A_BOLD)
                    rem_lines = sf.remediation[:detail_w * 2].splitlines()
                    for r_i, r_line in enumerate(rem_lines[:2]):
                        stdscr.addstr(rem_y + 1 + r_i, detail_x + 2, r_line[:detail_w - 4], curses.color_pair(3))

            # Bottom Status Bar
            stdscr.addstr(max_y - 2, 0, "─" * (max_x - 1))
            status_bar = " [↑/↓/j/k] Navigate  [1-5] Switch Tab  [r] Rescan  [q] Quit"
            stdscr.addstr(max_y - 1, 0, status_bar[:max_x - 1], curses.A_DIM)

            stdscr.refresh()

            # Handle user keyboard input
            key = stdscr.getch()
            if key in (ord('q'), ord('Q')):
                break
            elif key in (curses.KEY_UP, ord('k')):
                if self.selected_finding_idx > 0:
                    self.selected_finding_idx -= 1
                    if self.selected_finding_idx < self.scroll_offset:
                        self.scroll_offset = self.selected_finding_idx
            elif key in (curses.KEY_DOWN, ord('j')):
                if self.selected_finding_idx < len(findings) - 1:
                    self.selected_finding_idx += 1
                    if self.selected_finding_idx >= self.scroll_offset + list_height:
                        self.scroll_offset += 1
            elif key in (ord('1'), ord('2'), ord('3'), ord('4'), ord('5')):
                self.active_tab_idx = key - ord('1')
                self.selected_finding_idx = 0
                self.scroll_offset = 0
            elif key == 9:  # TAB
                self.active_tab_idx = (self.active_tab_idx + 1) % len(self.TAB_NAMES)
                self.selected_finding_idx = 0
                self.scroll_offset = 0
            elif key in (ord('r'), ord('R')):
                self.scan_result = ScanOrchestrator().run_scan(self.target_path)
                self.selected_finding_idx = 0
                self.scroll_offset = 0

        return 0

    def render_snapshot(self) -> str:
        """Render readable ANSI snapshot for non-interactive / headless terminals."""
        risk_score = self.scan_result.project_risk.overall_score if self.scan_result.project_risk else 0.0
        gate_status = "PASSED" if self.scan_result.exit_code == 0 else "FAILED"
        lines = [
            "╔════════════════════════════════════════════════════════════════╗",
            f"║           PYTHON HUNTER TUI DASHBOARD v{__version__:<23}║",
            "╠════════════════════════════════════════════════════════════════╣",
            f"║ Target: {self.target_path:<54}║",
            f"║ Risk: {risk_score:.1f}/100 | Policy Gate: {gate_status:<33}║",
            f"║ Total Security Findings: {len(self.scan_result.findings):<37}║",
            "╠════════════════════════════════════════════════════════════════╣",
            "║ [1] ALL   [2] MALWARE   [3] SECRETS   [4] SUPPLY_CHAIN   [5] SAST║",
            "╚════════════════════════════════════════════════════════════════╝",
            "",
            "FINDINGS SUMMARY:",
        ]
        for idx, f in enumerate(self.scan_result.findings[:15], 1):
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            loc = f"{f.file_path}:{f.location.line_start}" if f.location else f.file_path
            lines.append(f"  {idx:2d}. [{sev:<8}] {f.rule_id}: {f.title}")
            lines.append(f"      Location: {loc}")
            lines.append(f"      Remedy:   {f.remediation.splitlines()[0] if f.remediation else '-'}")

        if len(self.scan_result.findings) > 15:
            lines.append(f"\n  ... and {len(self.scan_result.findings) - 15} additional finding(s).")

        return "\n".join(lines)
