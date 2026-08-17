"""PYH-TAINT-CODE-001: Arbitrary Code Execution Dataflow Detector."""

from python_hunter.domain.common.enums import Category
from python_hunter.domain.common.value_objects import Location
from python_hunter.domain.findings.finding import Finding
from python_hunter.domain.taint.models import TaintFlow


class PYHTaintCode001:
    """Detector for untrusted data flowing into eval/exec code evaluation sinks."""

    id = "PYH-TAINT-CODE-001"
    name = "Arbitrary Code Execution Risk"
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
            f"flows into dynamic code evaluation sink '{flow.sink_node.label}'. "
            f"Flow Path: {path_steps}."
        )

        remediation = (
            "1. Remove eval(), exec(), or compile() calls accepting untrusted input.\n"
            "2. Use ast.literal_eval() for safely parsing Python literals, or implement safer data representation structures."
        )

        return Finding(
            rule_id=self.id,
            severity=flow.severity,
            confidence=flow.confidence,
            category=self.category,
            title=f"Code Execution Risk: {flow.sink_node.label}",
            description=description,
            file_path=file_path,
            location=loc,
            evidence=f"Source: {flow.source_node.label} → Sink: {flow.sink_node.label}",
            remediation=remediation,
        )
