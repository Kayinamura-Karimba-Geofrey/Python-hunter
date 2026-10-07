# Software Bill of Materials (`sbom`)

The `sbom` command generates enterprise-grade, machine-readable **Software Bill of Materials (SBOM)** documents compliant with modern software supply-chain standards, including **CycloneDX 1.5** and **SPDX 2.3**.

---

## 1. Supported Standards & Specifications

| Standard | Specification Versions | Ecosystem Identifiers | Primary Use Cases |
| :--- | :--- | :--- | :--- |
| **CycloneDX** | `1.5` (default), `1.4` | Package URL (`purl`), SHA-256, license IDs | Application security, automated vulnerability management, CI/CD ingestion, container compliance. |
| **SPDX** | `2.3` (default), `2.2` | Package Name, SPDXID, PackageDownloadLocation | Open-source licensing compliance, enterprise software procurement, regulatory filings (Executive Order 14028). |

---

## 2. Command: `python-hunter sbom`

### Syntax
```bash
python-hunter sbom [TARGET] [OPTIONS]
```

### Options Reference

| Option | Choices | Default | Description |
| :--- | :--- | :--- | :--- |
| `target` | Positional | `.` | Target project directory or dependency manifest (`requirements.txt`, `pyproject.toml`, `package.json`). |
| `-f`, `--format` | `cyclonedx`, `cdx`, `spdx`, `spdx-json` | `cyclonedx` | SBOM standard serialization format. |
| `--spec-version` | String (e.g. `1.5`, `2.3`) | *(latest standard)* | Explicit specification standard version. |
| `-o`, `--output` | File path | `stdout` | Destination file path for generated JSON document. |
| `--include-vulns`| Flag | `False` | Embed matched vulnerability advisories (CVE, GHSA, CVSS) directly into CycloneDX document. |

---

## 3. Usage Examples

### Example 1: Generate Standard CycloneDX 1.5 JSON SBOM
Generate a canonical CycloneDX SBOM for your repository:
```bash
python-hunter sbom . --format cyclonedx -o cyclonedx-sbom.json
```

Sample output snippet:
```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:6b68b420-569b-4e69-bc91-31405b0d8794",
  "version": 1,
  "metadata": {
    "timestamp": "2026-09-30T19:40:00Z",
    "tools": [
      {
        "vendor": "Python Hunter Security",
        "name": "python-hunter",
        "version": "1.0.0"
      }
    ],
    "component": {
      "type": "application",
      "name": "my-service",
      "version": "0.1.0"
    }
  },
  "components": [
    {
      "type": "library",
      "name": "fastapi",
      "version": "0.115.0",
      "purl": "pkg:pypi/fastapi@0.115.0",
      "licenses": [
        {"license": {"id": "MIT"}}
      ],
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        }
      ]
    }
  ],
  "dependencies": [
    {
      "ref": "pkg:pypi/fastapi@0.115.0",
      "dependsOn": [
        "pkg:pypi/pydantic@2.9.2",
        "pkg:pypi/starlette@0.38.6"
      ]
    }
  ]
}
```

---

### Example 2: Embed Vulnerability Intelligence (`--include-vulns`)
CycloneDX supports embedding active vulnerability telemetry inside the SBOM document. This creates an audit package pairing exact software inventory with known risks:

```bash
python-hunter sbom . --format cyclonedx --include-vulns -o sbom-with-vulns.json
```

Appended vulnerability telemetry structure:
```json
{
  "vulnerabilities": [
    {
      "id": "GHSA-xxxx-xxxx-xxxx",
      "source": {
        "name": "GitHub Security Advisory",
        "url": "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx"
      },
      "ratings": [
        {
          "severity": "high",
          "score": 7.5,
          "method": "CVSSv31"
        }
      ],
      "affects": [
        {
          "ref": "pkg:pypi/urllib3@1.26.4"
        }
      ],
      "description": "Proxy-Authorization header leakage in cross-origin redirects."
    }
  ]
}
```

---

### Example 3: Generate SPDX 2.3 JSON SBOM
Generate an SPDX 2.3 compliant document for enterprise software delivery:

```bash
python-hunter sbom . --format spdx -o spdx-sbom.json
```

Sample SPDX output structure:
```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "my-service",
  "documentNamespace": "http://spdx.org/spdxdocs/my-service-9591d4a7",
  "creationInfo": {
    "creators": ["Tool: python-hunter-1.0.0"],
    "created": "2026-09-30T19:40:00Z"
  },
  "packages": [
    {
      "name": "cryptography",
      "SPDXID": "SPDXRef-Package-cryptography",
      "versionInfo": "43.0.1",
      "downloadLocation": "https://pypi.org/project/cryptography/43.0.1/",
      "filesAnalyzed": false,
      "licenseConcluded": "Apache-2.0 OR BSD-3-Clause",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:pypi/cryptography@43.0.1"
        }
      ]
    }
  ]
}
```

---

## 4. CI/CD Integration Best Practices

In modern compliance pipelines, generate and archive SBOM documents on every tagged release:

```yaml
- name: Generate CycloneDX SBOM
  run: |
    python-hunter sbom . --format cyclonedx --include-vulns -o cyclonedx-sbom.json

- name: Archive SBOM Artifact
  uses: actions/upload-artifact@v4
  with:
    name: release-sbom
    path: cyclonedx-sbom.json
```
