"""Dockerfile and Docker Compose static parser adapter."""

import os
import re
from typing import Any, Dict, List, Optional
from python_hunter.domain.infrastructure.models import (
    ContainerImage,
    InfrastructureEnvironment,
    InfrastructureIR,
    InfrastructureResource,
    InfrastructureResourceType,
)
from python_hunter.domain.infrastructure.yaml_parser import safe_yaml_load
from python_hunter.infrastructure.iac.registry import InfrastructureAdapter


class DockerAdapter(InfrastructureAdapter):
    """Parses Dockerfiles and Docker Compose files into Infrastructure IR."""

    @property
    def adapter_name(self) -> str:
        return "DockerAdapter"

    def detect(self, file_path: str, content: str) -> bool:
        fname = os.path.basename(file_path).lower()
        if "dockerfile" in fname or fname.endswith(".dockerfile"):
            return True
        if fname in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            return True
        return False

    def parse_and_build_ir(self, file_path: str, content: str, ir: InfrastructureIR) -> None:
        fname = os.path.basename(file_path).lower()
        if "dockerfile" in fname or fname.endswith(".dockerfile"):
            self._parse_dockerfile(file_path, content, ir)
        else:
            self._parse_docker_compose(file_path, content, ir)

    def _parse_dockerfile(self, file_path: str, content: str, ir: InfrastructureIR) -> None:
        lines = content.splitlines()
        instructions = []
        base_images = []
        user = "root"
        exposed_ports = []
        envs = {}
        args = {}

        for idx, line in enumerate(lines, start=1):
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue
            
            parts = clean.split(maxsplit=1)
            cmd = parts[0].upper()
            val = parts[1] if len(parts) > 1 else ""

            instructions.append({"cmd": cmd, "val": val, "line": idx})

            if cmd == "FROM":
                raw_img = val.split()[0]
                is_latest = raw_img.endswith(":latest") or ":" not in raw_img
                is_pinned = "@sha256:" in raw_img
                tag = raw_img.split(":")[1] if ":" in raw_img and "@" not in raw_img else None
                digest = raw_img.split("@")[1] if "@" in raw_img else None
                
                base_images.append(
                    ContainerImage(
                        raw_reference=raw_img,
                        tag=tag,
                        digest=digest,
                        is_pinned_by_digest=is_pinned,
                        is_latest_or_unpinned=is_latest,
                    )
                )
            elif cmd == "USER":
                user = val
            elif cmd == "EXPOSE":
                for p in val.split():
                    try:
                        exposed_ports.append(int(p.split("/")[0]))
                    except ValueError:
                        pass
            elif cmd == "ENV":
                if "=" in val:
                    k, v = val.split("=", 1)
                    envs[k.strip()] = v.strip()
                else:
                    eparts = val.split()
                    if len(eparts) >= 2:
                        envs[eparts[0]] = eparts[1]
            elif cmd == "ARG":
                if "=" in val:
                    k, v = val.split("=", 1)
                    args[k.strip()] = v.strip()
                else:
                    args[val.strip()] = ""

        runs_as_root = (user == "root" or user == "0")

        res = InfrastructureResource(
            id=f"dockerfile::{file_path}",
            name=os.path.basename(file_path),
            type=InfrastructureResourceType.DOCKERFILE,
            provider="Docker",
            file_path=file_path,
            line=1,
            properties={
                "instructions": instructions,
                "user": user,
                "envs": envs,
                "args": args,
            },
            container_images=base_images,
            exposed_ports=exposed_ports,
            runs_as_root=runs_as_root,
        )

        ir.resources.append(res)
        ir.graph.add_resource(res)
        ir.dockerfiles.append({"file_path": file_path, "resource": res})

    def _parse_docker_compose(self, file_path: str, content: str, ir: InfrastructureIR) -> None:
        try:
            data = safe_yaml_load(content)
        except Exception:
            return

        if not isinstance(data, dict) or "services" not in data:
            return

        services = data.get("services", {})
        for svc_name, svc_conf in services.items():
            if not isinstance(svc_conf, dict):
                continue

            raw_img = svc_conf.get("image", "")
            images = []
            if raw_img:
                is_latest = raw_img.endswith(":latest") or ":" not in raw_img
                is_pinned = "@sha256:" in raw_img
                images.append(
                    ContainerImage(
                        raw_reference=raw_img,
                        is_pinned_by_digest=is_pinned,
                        is_latest_or_unpinned=is_latest,
                    )
                )

            ports_raw = svc_conf.get("ports", [])
            exposed_ports = []
            is_public = False
            if isinstance(ports_raw, dict):
                ports_raw = list(ports_raw.values())
            for p in ports_raw:
                p_str = ""
                if isinstance(p, dict):
                    # PyYAML parses "0.0.0.0:2375:2375" as { "0.0.0.0:2375": 2375 } or key-value
                    for k_port, v_port in p.items():
                        p_str = f"{k_port}:{v_port}"
                else:
                    p_str = str(p)
                if ":" in p_str:
                    parts = p_str.split(":")
                    if len(parts) == 3:
                        host_ip, host_p, container_p = parts[0], parts[1], parts[2]
                    elif len(parts) == 2:
                        host_ip, host_p = "", parts[0]
                        container_p = parts[1]
                    else:
                        host_ip, host_p = "", p_str
                    if host_ip in ("0.0.0.0", "", "*"):
                        is_public = True
                    try:
                        port_num = int(container_p.split("/")[0])
                        exposed_ports.append(port_num)
                    except ValueError:
                        pass

            is_privileged = bool(svc_conf.get("privileged", False))
            user = str(svc_conf.get("user", "root"))
            runs_as_root = (user == "root" or user == "0" or not user)
            caps = svc_conf.get("cap_add", [])
            network_mode = str(svc_conf.get("network_mode", ""))
            pid_mode = str(svc_conf.get("pid", ""))

            res = InfrastructureResource(
                id=f"compose::{file_path}::{svc_name}",
                name=svc_name,
                type=InfrastructureResourceType.DOCKER_COMPOSE,
                provider="Docker",
                file_path=file_path,
                properties={
                    "service_name": svc_name,
                    "capabilities": caps,
                    "network_mode": network_mode,
                    "pid_mode": pid_mode,
                    "volumes": svc_conf.get("volumes", []),
                    "environment": svc_conf.get("environment", {}),
                },
                container_images=images,
                exposed_ports=exposed_ports,
                is_publicly_exposed=is_public,
                is_privileged=is_privileged,
                runs_as_root=runs_as_root,
            )

            ir.resources.append(res)
            ir.graph.add_resource(res)
            ir.compose_files.append({"file_path": file_path, "service": svc_name, "resource": res})
