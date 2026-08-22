"""Terraform HCL static parser adapter."""

import os
import re
from typing import Any, Dict, List, Optional
from python_hunter.domain.infrastructure.models import (
    IAMPermission,
    IAMPolicy,
    InfrastructureIR,
    InfrastructureResource,
    InfrastructureResourceType,
)
from python_hunter.infrastructure.iac.registry import InfrastructureAdapter


class TerraformAdapter(InfrastructureAdapter):
    """Parses Terraform (.tf, .tfvars) files statically into Cloud Infrastructure IR."""

    @property
    def adapter_name(self) -> str:
        return "TerraformAdapter"

    def detect(self, file_path: str, content: str) -> bool:
        fname = os.path.basename(file_path).lower()
        return fname.endswith(".tf") or fname.endswith(".tfvars")

    def parse_and_build_ir(self, file_path: str, content: str, ir: InfrastructureIR) -> None:
        lines = content.splitlines()
        current_block_type = None
        current_res_type = None
        current_res_name = None
        block_lines = []
        start_line = 1

        resource_pattern = re.compile(r'^\s*(resource|module|provider|variable)\s+"([^"]+)"\s+"?([^"\s]+)"?\s*\{')

        for idx, line in enumerate(lines, start=1):
            m = resource_pattern.match(line)
            if m:
                if current_res_name and block_lines:
                    self._create_terraform_resource(
                        file_path, start_line, current_block_type, current_res_type, current_res_name, "\n".join(block_lines), ir
                    )
                current_block_type = m.group(1)
                current_res_type = m.group(2)
                current_res_name = m.group(3)
                block_lines = [line]
                start_line = idx
            elif current_res_name:
                block_lines.append(line)

        if current_res_name and block_lines:
            self._create_terraform_resource(
                file_path, start_line, current_block_type, current_res_type, current_res_name, "\n".join(block_lines), ir
            )

    def _create_terraform_resource(
        self,
        file_path: str,
        start_line: int,
        block_type: str,
        tf_type: str,
        name: str,
        block_content: str,
        ir: InfrastructureIR,
    ) -> None:
        res_type = InfrastructureResourceType.TERRAFORM_RESOURCE
        provider = "Cloud"
        if tf_type.startswith("aws_"):
            provider = "AWS"
        elif tf_type.startswith("azurerm_"):
            provider = "Azure"
        elif tf_type.startswith("google_"):
            provider = "GCP"

        # Categorize cloud resource
        if "s3" in tf_type or "storage" in tf_type or "bucket" in tf_type:
            res_type = InfrastructureResourceType.CLOUD_STORAGE
        elif "db" in tf_type or "database" in tf_type or "rds" in tf_type or "postgres" in tf_type:
            res_type = InfrastructureResourceType.CLOUD_DATABASE
        elif "instance" in tf_type or "container" in tf_type or "ecs" in tf_type or "eks" in tf_type:
            res_type = InfrastructureResourceType.CLOUD_COMPUTE
        elif "iam" in tf_type or "role" in tf_type or "policy" in tf_type:
            res_type = InfrastructureResourceType.CLOUD_IAM
        elif "security_group" in tf_type or "vpc" in tf_type or "subnet" in tf_type or "firewall" in tf_type:
            res_type = InfrastructureResourceType.CLOUD_NETWORK

        is_public = False
        if "0.0.0.0/0" in block_content or "public-read" in block_content or "publicly_accessible = true" in block_content or "publicly_accessible=true" in block_content:
            is_public = True

        has_encryption = True
        if 'encrypted = false' in block_content or 'encryption = false' in block_content:
            has_encryption = False

        iam_policies = []
        if res_type == InfrastructureResourceType.CLOUD_IAM:
            has_wildcard = "*" in block_content
            iam_policies.append(
                IAMPolicy(
                    name=name,
                    principal_or_role=tf_type,
                    permissions=[
                        IAMPermission(
                            effect="Allow",
                            actions=["*"] if has_wildcard else ["read"],
                            resources=["*"] if has_wildcard else ["specified"],
                            has_wildcard_action=has_wildcard,
                            has_wildcard_resource=has_wildcard,
                        )
                    ],
                    is_admin=has_wildcard,
                )
            )

        res = InfrastructureResource(
            id=f"tf::{provider}::{tf_type}::{name}",
            name=f"{tf_type}.{name}",
            type=res_type,
            provider=provider,
            file_path=file_path,
            line=start_line,
            properties={
                "tf_type": tf_type,
                "block_type": block_type,
                "raw_block": block_content,
            },
            iam_policies=iam_policies,
            is_publicly_exposed=is_public,
            has_encryption_enabled=has_encryption,
        )

        ir.resources.append(res)
        ir.graph.add_resource(res)
        ir.terraform_files.append({"file_path": file_path, "resource": res})
