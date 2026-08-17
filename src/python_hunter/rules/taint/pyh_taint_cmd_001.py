"""PYH-TAINT-CMD-001: Command Injection Dataflow Detector."""

from python_hunter.domain.common.enums import Category
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.taint.models import TaintFlow


class PYHTaintCMD001:
    """Detector for untrusted data flowing into operating system command execution sinks."""

    id = "PYH-TAINT-CMD-001"
    name = "Command Injection Risk"
    category = Category.CODE_INJECTION

    def evaluate_flow(self, flow: TaintFlow) -> Finding:
        sink_loc = flow.sink_node.location
        loc = Location(
            line_start=sink_loc.line_start if sink_loc else 1,
            line_end=sink_loc.line_end if sink_loc else 1,
            column_start=sink_loc.column_start if sink_loc else 0,
            column_end=sink_loc.column_end if sink_loc else 10,
        )
        file_path = sink_loc.file_path if sink_loc else "unknown"

        path_steps = " → ".join(node.label for node in flow.flow_path)

        description = (
            f"Untrusted input originating from source '{flow.source_node.label}' ({flow.source_category.value}) "
            f"flows into system command execution sink '{flow.sink_node.label}'. "
            f"Flow Path: {path_steps}."
        )

        remediation = (
            "1. Avoid passing unverified user strings to shell execution APIs like os.system() or subprocess.run(shell=True).\n"
            "2. Use subprocess.run(['cmd', arg1, arg2], shell=False) with explicit command lists or sanitize with shlex.quote()."
        )

        return Finding(
            rule_id=self.id,
            severity=flow.severity,
            confidence=flow.confidence,
            category=self.category,
            title=f"Command Injection: {flow.sink_node.label}",
            description=description,
            file_path=file_path,
            location=loc,
            evidence=f"Source: {flow.source_node.label} → Sink: {flow.sink_node.label}",
            remediation=remediation,
        )
