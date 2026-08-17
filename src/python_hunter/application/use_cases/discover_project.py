"""Discover Project Use Case Application Service."""

import os
from python_hunter.domain.discovery.enums import (
    DirectoryCategory,
    FileCategory,
    ProjectType,
)
from python_hunter.domain.discovery.interfaces import FileSystem, ProjectDiscoveryEngine
from python_hunter.domain.discovery.manifest import (
    DirectoryMetadata,
    FileMetadata,
    ManifestStatistics,
    ProjectManifest,
)
from python_hunter.domain.exceptions.base import ProjectError, ValidationError
from python_hunter.infrastructure.discovery.framework_detector import FrameworkDetector
from python_hunter.infrastructure.discovery.ignore_rules import IgnoreRuleEngine
from python_hunter.infrastructure.discovery.local_filesystem import LocalFileSystem
from python_hunter.infrastructure.discovery.metadata_parser import SafeMetadataParser


class DiscoverProjectUseCase(ProjectDiscoveryEngine):
    """Orchestrates Project Discovery workflow: Validation -> Scanning -> Classification -> Manifest Generation."""

    KNOWN_ENTRY_POINTS = {"main.py", "__main__.py", "manage.py", "app.py", "cli.py", "run.py"}

    def __init__(
        self,
        fs: FileSystem | None = None,
        config_ignores: list[str] | None = None,
        cli_overrides: list[str] | None = None,
    ) -> None:
        self.fs = fs or LocalFileSystem()
        self.config_ignores = config_ignores or []
        self.cli_overrides = cli_overrides or []

    def discover(self, target_path: str) -> ProjectManifest:
        """Execute project discovery on target_path (directory or single python file)."""
        if not target_path or not target_path.strip():
            raise ValidationError("Target path cannot be empty")

        norm_target = self.fs.normalize_path(target_path)
        if not self.fs.exists(norm_target):
            raise ProjectError(f"Target path '{target_path}' does not exist", {"path": target_path})

        # Single file discovery mode
        if self.fs.is_file(norm_target):
            return self._discover_single_file(norm_target)

        if not self.fs.is_dir(norm_target):
            raise ProjectError(f"Target path '{target_path}' is neither a file nor a directory", {"path": target_path})

        return self._discover_directory(norm_target)

    def _discover_single_file(self, file_path: str) -> ProjectManifest:
        """Handle single file discovery mode."""
        root_dir = os.path.dirname(file_path)
        rel_path = os.path.basename(file_path)

        meta = self.fs.get_file_metadata(root_dir, rel_path)
        stats = ManifestStatistics(
            total_files=1,
            python_files=1 if meta.is_python else 0,
            total_bytes=meta.size_bytes,
        )

        proj_name = os.path.splitext(rel_path)[0]
        return ProjectManifest(
            root_path=root_dir,
            project_name=proj_name,
            project_type=ProjectType.SINGLE_MODULE if meta.is_python else ProjectType.UNKNOWN,
            type_confidence=0.9 if meta.is_python else 0.2,
            files=[meta],
            statistics=stats,
        )

    def _discover_directory(self, root_path: str) -> ProjectManifest:
        """Handle directory project discovery."""
        project_name = os.path.basename(root_path.rstrip(os.sep)) or "unnamed_project"

        # Check for .gitignore content
        gitignore_path = os.path.join(root_path, ".gitignore")
        gitignore_content = ""
        if self.fs.exists(gitignore_path) and self.fs.is_file(gitignore_path):
            try:
                gitignore_content = self.fs.read_text_safe(gitignore_path)
            except Exception:
                pass

        ignore_engine = IgnoreRuleEngine(
            gitignore_content=gitignore_content,
            config_ignores=self.config_ignores,
            cli_overrides=self.cli_overrides,
        )

        discovered_files: list[FileMetadata] = []
        discovered_dirs: list[DirectoryMetadata] = []

        dependencies: list[str] = []
        file_samples: list[str] = []

        entry_points: set[str] = set()
        dependency_files: list[str] = []
        configuration_files: list[str] = []
        ci_files: list[str] = []
        container_files: list[str] = []

        is_git = False
        has_docker = False
        has_ci = False
        has_venv = False

        pyproject_data: dict = {}
        py_files_count = 0
        ignored_files_count = 0
        total_bytes = 0

        rel_dir_paths: list[str] = []
        rel_py_paths: list[str] = []

        for current_root, dirs, files in self.fs.walk(root_path):
            rel_dir = os.path.relpath(current_root, root_path)
            if rel_dir != ".":
                rel_dir_paths.append(rel_dir)
                is_ign_dir = ignore_engine.is_ignored(rel_dir)

                # Classify directory
                dir_name = os.path.basename(rel_dir).lower()
                if dir_name in (".git",):
                    is_git = True
                    dir_cat = DirectoryCategory.GIT_METADATA
                elif dir_name in (".venv", "venv", "env"):
                    has_venv = True
                    dir_cat = DirectoryCategory.VIRTUAL_ENV
                elif dir_name in ("tests", "test"):
                    dir_cat = DirectoryCategory.TESTS
                elif dir_name in ("src",):
                    dir_cat = DirectoryCategory.SOURCE
                elif dir_name in ("docs", "documentation"):
                    dir_cat = DirectoryCategory.DOCUMENTATION
                elif dir_name in (".github", ".gitlab", ".circleci"):
                    has_ci = True
                    dir_cat = DirectoryCategory.CI_CD
                else:
                    dir_cat = DirectoryCategory.UNKNOWN

                discovered_dirs.append(
                    DirectoryMetadata(
                        relative_path=rel_dir,
                        category=dir_cat,
                        is_hidden=os.path.basename(rel_dir).startswith("."),
                        is_ignored=is_ign_dir,
                    )
                )

            for file_name in files:
                rel_file = os.path.normpath(os.path.join(rel_dir, file_name)) if rel_dir != "." else file_name
                is_ign_file = ignore_engine.is_ignored(rel_file)

                if is_ign_file:
                    ignored_files_count += 1
                    continue

                file_meta = self.fs.get_file_metadata(root_path, rel_file)
                total_bytes += file_meta.size_bytes

                # Specific file recognitions
                base_name = os.path.basename(rel_file)
                base_lower = base_name.lower()

                if file_meta.is_python:
                    py_files_count += 1
                    rel_py_paths.append(rel_file)
                    if base_name in self.KNOWN_ENTRY_POINTS:
                        entry_points.add(rel_file)

                    # Read small sample for framework detection
                    if len(file_samples) < 5:
                        try:
                            sample = self.fs.read_text_safe(os.path.join(root_path, rel_file), max_bytes=2000)
                            file_samples.append(sample)
                        except Exception:
                            pass

                if base_lower in ("pyproject.toml", "requirements.txt", "setup.py", "setup.cfg", "pipfile", "poetry.lock"):
                    dependency_files.append(rel_file)
                    if base_lower == "pyproject.toml":
                        content = self.fs.read_text_safe(os.path.join(root_path, rel_file))
                        pyproject_data = SafeMetadataParser.parse_pyproject_toml(content)
                    elif base_lower == "requirements.txt":
                        content = self.fs.read_text_safe(os.path.join(root_path, rel_file))
                        dependencies.extend(SafeMetadataParser.parse_requirements_txt(content))

                if file_meta.category == FileCategory.CONFIGURATION or base_lower.endswith((".ini", ".cfg", ".toml", ".yaml", ".yml")):
                    configuration_files.append(rel_file)

                if base_lower in ("dockerfile", "docker-compose.yml", "compose.yml", "containerfile"):
                    has_docker = True
                    container_files.append(rel_file)

                if rel_file.startswith((".github", ".gitlab", ".circleci")) or base_lower in ("jenkinsfile",):
                    has_ci = True
                    ci_files.append(rel_file)

                discovered_files.append(file_meta)

        # Detect frameworks and package structure
        combined_samples = "\n".join(file_samples)
        frameworks, test_frameworks = FrameworkDetector.detect_frameworks(dependencies, combined_samples)
        package_layout = FrameworkDetector.detect_package_layout(rel_dir_paths, rel_py_paths)

        has_setup = any(f.endswith("setup.py") or f.endswith("setup.cfg") for f in dependency_files)
        proj_type, confidence = FrameworkDetector.detect_project_type(
            frameworks=frameworks,
            has_pyproject=bool(pyproject_data),
            has_setup=has_setup,
            package_layout=package_layout,
            entry_points=list(entry_points),
        )

        proj_name_override = pyproject_data.get("name")
        if not proj_name_override and isinstance(pyproject_data.get("project"), dict):
            proj_name_override = pyproject_data["project"].get("name")
        override_name = proj_name_override or project_name

        stats = ManifestStatistics(
            total_files=len(discovered_files),
            python_files=py_files_count,
            configuration_files=len(configuration_files),
            dependency_files=len(dependency_files),
            test_files=len([f for f in discovered_files if "test" in f.relative_path.lower()]),
            total_bytes=total_bytes,
            ignored_files=ignored_files_count,
            total_directories=len(discovered_dirs),
        )

        return ProjectManifest(
            root_path=root_path,
            project_name=override_name,
            project_type=proj_type,
            type_confidence=confidence,
            package_layout=package_layout,
            is_git_repository=is_git,
            has_docker=has_docker,
            has_ci_cd=has_ci,
            has_virtual_env=has_venv,
            files=discovered_files,
            directories=discovered_dirs,
            entry_points=sorted(list(entry_points)),
            frameworks=frameworks,
            test_frameworks=test_frameworks,
            dependency_files=dependency_files,
            configuration_files=configuration_files,
            ci_files=ci_files,
            container_files=container_files,
            metadata_info=pyproject_data,
            statistics=stats,
        )
