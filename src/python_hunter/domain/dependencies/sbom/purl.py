"""Package URL (purl) Specification Helper.

Conforms to https://github.com/package-url/purl-spec for generating canonical
package identifiers across PyPI, NPM, Cargo, Go, Maven, Composer, and Rubygems.
"""

import urllib.parse
from python_hunter.domain.dependencies.models import Ecosystem


class PURLHelper:
    """Generates canonical Package URL (purl) strings."""

    ECOSYSTEM_TYPE_MAP: dict[Ecosystem, str] = {
        Ecosystem.PYTHON: "pypi",
        Ecosystem.JAVASCRIPT: "npm",
        Ecosystem.CRATES_IO: "cargo",
        Ecosystem.GO_MODULES: "golang",
        Ecosystem.MAVEN: "maven",
        Ecosystem.GRADLE: "maven",
        Ecosystem.COMPOSER: "composer",
        Ecosystem.RUBYGEMS: "gem",
        Ecosystem.GENERIC: "generic",
    }

    @classmethod
    def generate_purl(
        cls,
        ecosystem: Ecosystem | str,
        name: str,
        version: str = "",
        namespace: str = "",
    ) -> str:
        """Generate canonical purl string: pkg:<type>/[<namespace>/]<name>[@<version>]."""
        if isinstance(ecosystem, str):
            try:
                eco_enum = Ecosystem(ecosystem.lower())
                purl_type = cls.ECOSYSTEM_TYPE_MAP.get(eco_enum, ecosystem.lower())
            except ValueError:
                purl_type = ecosystem.lower()
        else:
            purl_type = cls.ECOSYSTEM_TYPE_MAP.get(ecosystem, "generic")

        clean_name = name.strip()
        clean_version = version.strip()
        clean_namespace = namespace.strip()

        # Handle NPM scoped packages e.g. @angular/core
        if purl_type == "npm" and clean_name.startswith("@") and "/" in clean_name:
            scope, pkg = clean_name.split("/", 1)
            clean_namespace = scope.lstrip("@")
            clean_name = pkg

        # Handle Maven/Gradle groupId:artifactId
        if purl_type == "maven" and ":" in clean_name:
            group, artifact = clean_name.split(":", 1)
            clean_namespace = group
            clean_name = artifact

        # Handle PyPI canonical naming (lowercase)
        if purl_type == "pypi":
            clean_name = clean_name.lower().replace("_", "-")

        # Encode namespace and name components safely
        encoded_name = urllib.parse.quote(clean_name, safe="")
        if clean_namespace:
            encoded_ns = urllib.parse.quote(clean_namespace, safe="")
            base = f"pkg:{purl_type}/{encoded_ns}/{encoded_name}"
        else:
            base = f"pkg:{purl_type}/{encoded_name}"

        if clean_version and clean_version.upper() not in ("UNKNOWN", "ANY", "*", "LATEST"):
            encoded_ver = urllib.parse.quote(clean_version, safe=".")
            return f"{base}@{encoded_ver}"

        return base
