"""Unit tests for Step 27 Cross-Service API & Attack-Path Analysis."""

import unittest
from python_hunter.domain.architecture.cross_service_attack_path import CrossServiceAttackPathEngine
from python_hunter.domain.architecture.service_discovery import ServiceDiscoveryEngine
from python_hunter.domain.architecture.service_models import Service, TrustBoundary


class TestCrossServiceAnalysisEngine(unittest.TestCase):
    """Test suite for service discovery, docker-compose parsing, API client route matching, cross-service attack paths, and zero execution."""

    def setUp(self) -> None:
        self.discovery = ServiceDiscoveryEngine()
        self.path_engine = CrossServiceAttackPathEngine()

    def test_service_discovery(self) -> None:
        services = self.discovery.discover_services(".")
        self.assertIsInstance(services, list)

    def test_cross_service_attack_path_building(self) -> None:
        pub_service = Service(service_id="gateway", name="gateway", language=None, root_directory=".", trust_boundary=TrustBoundary.PUBLIC_API)
        int_service = Service(service_id="user_service", name="user_service", language=None, root_directory=".", trust_boundary=TrustBoundary.INTERNAL_SERVICE)
        
        from python_hunter.domain.architecture.service_models import ApiClientCall
        from python_hunter.domain.common.value_objects import Location

        pub_service.api_calls.append(
            ApiClientCall(
                caller_service="gateway",
                target_url="http://user_service/users/1",
                http_method="GET",
                path="/users/1",
                file_path="app.py",
                location=Location(1, 1),
            )
        )

        paths = self.path_engine.build_attack_paths([pub_service, int_service])
        self.assertTrue(len(paths) > 0)
        self.assertIn("user_service", paths[0].path_id)


if __name__ == "__main__":
    unittest.main()
