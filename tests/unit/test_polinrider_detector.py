"""Unit tests for PolinRider / TasksJacker Malware Detector and Cleaner."""

import json
import os
import shutil
import tempfile
import unittest

from python_hunter.domain.malware.analyzers.polinrider_detector import PolinRiderDetector
from python_hunter.domain.malware.cleaners.polinrider_cleaner import PolinRiderCleaner
from python_hunter.application.orchestrator.scan_orchestrator import ScanOrchestrator


class TestPolinRiderDetectorAndCleaner(unittest.TestCase):
    """Comprehensive test suite for PolinRider multi-vector detection and automated disinfection."""

    def setUp(self) -> None:
        self.test_dir = tempfile.mkdtemp(prefix="pyh_polinrider_test_")
        self.detector = PolinRiderDetector()
        self.cleaner = PolinRiderCleaner()

    def tearDown(self) -> None:
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_clean_repo_has_zero_findings(self) -> None:
        """Verify that a normal clean repository produces no PolinRider findings."""
        with open(os.path.join(self.test_dir, "app.py"), "w", encoding="utf-8") as f:
            f.write("print('Hello secure world!')\n")

        findings = self.detector.detect(self.test_dir)
        self.assertEqual(len(findings), 0)

    def test_vector1_vscode_task_hijacking_detected(self) -> None:
        """Verify detection of .vscode/tasks.json folderOpen auto-execution."""
        vscode_dir = os.path.join(self.test_dir, ".vscode")
        os.makedirs(vscode_dir, exist_ok=True)

        tasks_payload = {
            "version": "2.0.0",
            "tasks": [
                {
                    "label": "Build Client Fonts",
                    "type": "shell",
                    "command": "node ./public/fonts/fa-solid-500.woff2",
                    "runOptions": {
                        "runOn": "folderOpen"
                    }
                }
            ]
        }
        with open(os.path.join(vscode_dir, "tasks.json"), "w", encoding="utf-8") as f:
            json.dump(tasks_payload, f)

        findings = self.detector.detect(self.test_dir)
        task_findings = [f for f in findings if f.rule_id == "PYH-MAL-001"]
        self.assertGreaterEqual(len(task_findings), 1)
        self.assertEqual(task_findings[0].severity.value, "CRITICAL")
        self.assertIn("tasks.json", task_findings[0].file_path)

    def test_vector1_vscode_settings_automatic_tasks_flagged(self) -> None:
        """Verify detection of task.allowAutomaticTasks in settings.json."""
        vscode_dir = os.path.join(self.test_dir, ".vscode")
        os.makedirs(vscode_dir, exist_ok=True)

        settings_payload = {
            "task.allowAutomaticTasks": "on"
        }
        with open(os.path.join(vscode_dir, "settings.json"), "w", encoding="utf-8") as f:
            json.dump(settings_payload, f)

        findings = self.detector.detect(self.test_dir)
        settings_findings = [f for f in findings if f.rule_id == "PYH-MAL-001" and "settings.json" in f.file_path]
        self.assertEqual(len(settings_findings), 1)

    def test_vector2_trojan_disguised_font_detected(self) -> None:
        """Verify detection of disguised font files containing JavaScript payloads."""
        fonts_dir = os.path.join(self.test_dir, "public", "fonts")
        os.makedirs(fonts_dir, exist_ok=True)

        trojan_font = os.path.join(fonts_dir, "fa-solid-900.woff2")
        with open(trojan_font, "wb") as f:
            # Script payload disguised as woff2
            f.write(b"const http = require('http'); eval(Buffer.from('...').toString());")

        # Also write a legitimate font with magic bytes
        real_font = os.path.join(fonts_dir, "real-font.woff2")
        with open(real_font, "wb") as f:
            f.write(b"wOF2" + b"\x00" * 64)

        findings = self.detector.detect(self.test_dir)
        font_findings = [f for f in findings if f.rule_id == "PYH-MAL-002"]
        self.assertEqual(len(font_findings), 1)
        self.assertIn("fa-solid-900.woff2", font_findings[0].file_path)

    def test_vector3_dropper_scripts_detected(self) -> None:
        """Verify detection of PolinRider batch wiping and dropper scripts."""
        with open(os.path.join(self.test_dir, "temp_auto_push.bat"), "w", encoding="utf-8") as f:
            f.write("@echo off\ngit push origin --force main\n")

        with open(os.path.join(self.test_dir, "branch_structure.json"), "w", encoding="utf-8") as f:
            f.write("{\"branches\": [\"master\", \"main\"]}")

        findings = self.detector.detect(self.test_dir)
        dropper_findings = [f for f in findings if f.rule_id == "PYH-MAL-003"]
        self.assertEqual(len(dropper_findings), 2)

    def test_vector4_ioc_signatures_detected(self) -> None:
        """Verify signature match on obfuscated string markers."""
        src_file = os.path.join(self.test_dir, "bundle.js")
        with open(src_file, "w", encoding="utf-8") as f:
            f.write("var " + "_$_1" + "e42 = ['\\x68\\x65\\x6c\\x6c\\x6f'];\nglobal['" + "!" + "'](payload);\n")

        findings = self.detector.detect(self.test_dir)
        ioc_findings = [f for f in findings if f.rule_id == "PYH-MAL-004"]
        self.assertGreaterEqual(len(ioc_findings), 1)

    def test_vector5_build_config_injection_detected(self) -> None:
        """Verify detection of Trojan payload invocation inside build scripts."""
        webpack_config = os.path.join(self.test_dir, "webpack.config.js")
        with open(webpack_config, "w", encoding="utf-8") as f:
            f.write("require('./public/fonts/fa-solid-500.woff2');\nmodule.exports = {};\n")

        findings = self.detector.detect(self.test_dir)
        build_findings = [f for f in findings if f.rule_id == "PYH-MAL-005"]
        self.assertEqual(len(build_findings), 1)

    def test_automated_cleaner_disinfects_all_vectors(self) -> None:
        """Verify that PolinRiderCleaner neutralizes all malware vectors and restores repo hygiene."""
        # 1. Setup infected tasks.json with both a benign task and a malicious task
        vscode_dir = os.path.join(self.test_dir, ".vscode")
        os.makedirs(vscode_dir, exist_ok=True)
        tasks_path = os.path.join(vscode_dir, "tasks.json")
        tasks_data = {
            "version": "2.0.0",
            "tasks": [
                {
                    "label": "Legitimate Test Runner",
                    "type": "shell",
                    "command": "pytest"
                },
                {
                    "label": "Malicious Hook",
                    "type": "shell",
                    "command": "node ./public/fonts/fa-solid-500.woff2",
                    "runOptions": {"runOn": "folderOpen"}
                }
            ]
        }
        with open(tasks_path, "w", encoding="utf-8") as f:
            json.dump(tasks_data, f)

        # 2. Setup settings.json with automatic tasks allowed
        settings_path = os.path.join(vscode_dir, "settings.json")
        with open(settings_path, "w", encoding="utf-8") as f:
            json.dump({"task.allowAutomaticTasks": True}, f)

        # 3. Create dropper batch files
        dropper_bat = os.path.join(self.test_dir, "temp_auto_push.bat")
        with open(dropper_bat, "w", encoding="utf-8") as f:
            f.write("@echo off\ngit push origin --force\n")

        dropper_json = os.path.join(self.test_dir, "branch_structure.json")
        with open(dropper_json, "w", encoding="utf-8") as f:
            f.write("{}\n")

        # 4. Create disguised Trojan font
        fonts_dir = os.path.join(self.test_dir, "public", "fonts")
        os.makedirs(fonts_dir, exist_ok=True)
        trojan_font = os.path.join(fonts_dir, "fa-solid-500.woff2")
        with open(trojan_font, "wb") as f:
            f.write(b"#!/usr/bin/env node\neval('malicious code');")

        # 5. Create build script with IoC
        build_script = os.path.join(self.test_dir, "build.js")
        with open(build_script, "w", encoding="utf-8") as f:
            f.write("console.log('Building...');\nvar " + "rmce" + "j%otb% = 'payload';\nconsole.log('Done');\n")

        # 6. Create .gitignore with concealment rules
        gitignore_path = os.path.join(self.test_dir, ".gitignore")
        with open(gitignore_path, "w", encoding="utf-8") as f:
            f.write("node_modules/\n*.log\ntemp_auto_push.bat\nbranch_structure.json\n")

        # Verify infection is detected before cleaning
        pre_findings = self.detector.detect(self.test_dir)
        self.assertGreaterEqual(len(pre_findings), 4)

        # Execute disinfection
        clean_res = self.cleaner.clean(self.test_dir)

        self.assertTrue(clean_res.success)
        self.assertEqual(clean_res.tasks_sanitized, 1)
        self.assertEqual(clean_res.settings_sanitized, 1)
        self.assertIn("temp_auto_push.bat", clean_res.droppers_deleted)
        self.assertIn("branch_structure.json", clean_res.droppers_deleted)
        self.assertTrue(any("fa-solid-500.woff2" in p for p in clean_res.trojan_fonts_deleted))
        self.assertTrue(clean_res.gitignore_cleaned)

        # Verify malicious files are deleted from disk
        self.assertFalse(os.path.exists(dropper_bat))
        self.assertFalse(os.path.exists(dropper_json))
        self.assertFalse(os.path.exists(trojan_font))

        # Verify legitimate task is retained in tasks.json
        with open(tasks_path, "r", encoding="utf-8") as f:
            disinfected_tasks = json.load(f)
        self.assertEqual(len(disinfected_tasks["tasks"]), 1)
        self.assertEqual(disinfected_tasks["tasks"][0]["label"], "Legitimate Test Runner")

        # Verify settings.json was sanitized
        with open(settings_path, "r", encoding="utf-8") as f:
            disinfected_settings = json.load(f)
        self.assertFalse(disinfected_settings.get("task.allowAutomaticTasks"))

        # Verify .gitignore had dropper rules stripped
        with open(gitignore_path, "r", encoding="utf-8") as f:
            gitignore_content = f.read()
        self.assertNotIn("temp_auto_push.bat", gitignore_content)
        self.assertIn("node_modules/", gitignore_content)

        # Verify detector reports 0 findings after disinfection!
        post_findings = self.detector.detect(self.test_dir)
        self.assertEqual(len(post_findings), 0)

    def test_orchestrator_integration_with_clean_flag(self) -> None:
        """Verify ScanOrchestrator executes detector and automated disinfection with --clean."""
        # Setup infected repo
        vscode_dir = os.path.join(self.test_dir, ".vscode")
        os.makedirs(vscode_dir, exist_ok=True)
        with open(os.path.join(vscode_dir, "tasks.json"), "w", encoding="utf-8") as f:
            json.dump({
                "version": "2.0.0",
                "tasks": [{"label": "Malware", "command": "node payload.woff2", "runOn": "folderOpen"}]
            }, f)

        orchestrator = ScanOrchestrator()
        result = orchestrator.run_scan(self.test_dir, options={"clean": True})

        self.assertIsNotNone(result)
        self.assertGreaterEqual(len(result.findings), 1)
        self.assertEqual(result.exit_code, 1)
        self.assertIsNotNone(result.project_risk)
        self.assertGreaterEqual(result.project_risk.overall_score, 90.0)

        cleanup = result.context.options.get("cleanup_result")
        self.assertIsNotNone(cleanup)
        self.assertEqual(cleanup.tasks_sanitized, 1)


if __name__ == "__main__":
    unittest.main()
