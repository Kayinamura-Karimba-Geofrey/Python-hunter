"""Distributed Tracing and Correlation Context Propagation."""

import uuid
from dataclasses import dataclass, field


@dataclass
class TraceContext:
    """Trace propagation context across API, Queue, Worker, and Event Bus."""

    trace_id: str
    span_id: str
    parent_span_id: str | None = None

    @staticmethod
    def new_trace() -> "TraceContext":
        return TraceContext(trace_id=uuid.uuid4().hex, span_id=uuid.uuid4().hex[:16])

    def create_child_span(self) -> "TraceContext":
        return TraceContext(trace_id=self.trace_id, span_id=uuid.uuid4().hex[:16], parent_span_id=self.span_id)
