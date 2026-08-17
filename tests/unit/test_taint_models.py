"""Unit tests for Taint Domain Models."""

import unittest

from python_hunter.domain.ast.models import ASTLocation
from python_hunter.domain.taint.config import TaintConfig
from python_hunter.domain.taint.models import (
    FunctionSummary,
    SanitizationContext,
    TaintFlow,
    TaintNode,
    TaintSinkCategory,
    TaintSourceCategory,
    TaintStateEnum,
)


class TestTaintModels(unittest.TestCase):
    """Test suite for Taint domain models and configurations."""

    def test_taint_node_formatting(self) -> None:
        loc = ASTLocation(file_path="app.py", line_start=10, column_start=4)
        node = TaintNode(label="request.args['name']", location=loc, node_type="source")
        self.assertEqual(node.to_summary(), "[SOURCE] request.args['name'] (app.py:10:4)")

    def test_sink_category_required_sanitization(self) -> None:
        self.assertEqual(
            TaintSinkCategory.SQL_INJECTION.required_sanitization_context,
            SanitizationContext.SQL_SAFE,
        )
        self.assertEqual(
            TaintSinkCategory.COMMAND_INJECTION.required_sanitization_context,
            SanitizationContext.SHELL_SAFE,
        )
        self.assertEqual(
            TaintSinkCategory.PATH_TRAVERSAL.required_sanitization_context,
            SanitizationContext.PATH_SAFE,
        )

    def test_taint_flow_sanitization_check(self) -> None:
        src = TaintNode(label="src", node_type="source")
        snk = TaintNode(label="snk", node_type="sink")

        # Un-sanitized flow
        flow1 = TaintFlow(
            source_node=src,
            sink_node=snk,
            sink_category=TaintSinkCategory.SQL_INJECTION,
            source_category=TaintSourceCategory.HTTP_REQUEST,
            applied_sanitizers=[],
        )
        self.assertFalse(flow1.is_sanitized)

        # Wrong context sanitizer (HTML_SAFE applied to SQL sink)
        flow2 = TaintFlow(
            source_node=src,
            sink_node=snk,
            sink_category=TaintSinkCategory.SQL_INJECTION,
            source_category=TaintSourceCategory.HTTP_REQUEST,
            applied_sanitizers=[("html.escape", SanitizationContext.HTML_SAFE)],
        )
        self.assertFalse(flow2.is_sanitized)

        # Right context sanitizer (SQL_SAFE applied to SQL sink)
        flow3 = TaintFlow(
            source_node=src,
            sink_node=snk,
            sink_category=TaintSinkCategory.SQL_INJECTION,
            source_category=TaintSourceCategory.HTTP_REQUEST,
            applied_sanitizers=[("parameterized", SanitizationContext.SQL_SAFE)],
        )
        self.assertTrue(flow3.is_sanitized)

    def test_taint_config_defaults(self) -> None:
        cfg = TaintConfig()
        self.assertIn("request.args", cfg.sources)
        self.assertIn("cursor.execute", cfg.sinks)
        self.assertIn("shlex.quote", cfg.sanitizers)


if __name__ == "__main__":
    unittest.main()
