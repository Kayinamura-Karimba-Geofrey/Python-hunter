# CI/CD Pipeline Integration Guide

This guide provides drop-in CI/CD configuration templates to integrate **Python Hunter** into major continuous integration and delivery platforms.

---

## 1. GitHub Actions

Save to `.github/workflows/python-hunter.yml`:

```yaml
name: Python Hunter Security Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 4 * * 1'  # Weekly Monday 4 AM UTC audit

jobs:
  security-audit:
    name: Security Scan & SBOM
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write  # Required for uploading SARIF to GitHub Code Scanning
      pull-requests: write    # Required for PR comments

    steps:
      - name: Checkout Source Code
        uses: actions/checkout@v4

      - name: Set up Python 3.12
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'
          cache: 'pip'

      - name: Install Python Hunter
        run: |
          pip install --upgrade pip
          pip install -e .

      - name: Run Unified Security Scan (SARIF)
        run: |
          python-hunter scan . --ci --format sarif -o results.sarif --fail-on high

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif

      - name: Generate CycloneDX SBOM
        run: |
          python-hunter sbom . --format cyclonedx --include-vulns -o cyclonedx-sbom.json

      - name: Generate Markdown Summary
        if: always()
        run: |
          python-hunter report . --format markdown -o $GITHUB_STEP_SUMMARY

      - name: Archive SBOM & Scan Artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-audit-artifacts
          path: |
            results.sarif
            cyclonedx-sbom.json
```

---

## 2. GitLab CI/CD

Save to `.gitlab-ci.yml`:

```yaml
stages:
  - test
  - security

python-hunter-sast:
  stage: security
  image: python:3.12-slim
  before_script:
    - apt-get update && apt-get install -y git
    - pip install --upgrade pip
    - pip install -e .
  script:
    # 1. Generate GitLab Code Climate report
    - python-hunter diagnostics . --format codeclimate -o gl-code-quality-report.json
    # 2. Run CI scan and export SARIF
    - python-hunter scan . --ci --format sarif -o gl-sast-report.sarif --fail-on high
  artifacts:
    reports:
      codequality: gl-code-quality-report.json
      sast: gl-sast-report.sarif
    paths:
      - gl-code-quality-report.json
      - gl-sast-report.sarif
    when: always
```

---

## 3. Jenkins Pipeline

Save to `Jenkinsfile`:

```groovy
pipeline {
    agent {
        docker {
            image 'python:3.12-slim'
        }
    }
    stages {
        stage('Install Python Hunter') {
            steps {
                sh 'pip install --upgrade pip'
                sh 'pip install -e .'
            }
        }
        stage('Security Analysis') {
            steps {
                sh 'python-hunter scan . --ci --format sarif -o results.sarif --fail-on high'
                sh 'python-hunter report . --format html -o security-report.html'
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'results.sarif, security-report.html', fingerprint: true
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: '.',
                reportFiles: 'security-report.html',
                reportName: 'Python Hunter Security Dashboard'
            ])
        }
    }
}
```

---

## 4. Azure DevOps Pipelines

Save to `azure-pipelines.yml`:

```yaml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.12'

  - script: |
      python -m pip install --upgrade pip
      pip install -e .
    displayName: 'Install Python Hunter'

  - script: |
      python-hunter scan . --ci --format sarif -o $(Build.ArtifactStagingDirectory)/results.sarif --fail-on high
    displayName: 'Execute Security Scan'

  - task: PublishBuildArtifacts@1
    inputs:
      PathtoPublish: '$(Build.ArtifactStagingDirectory)/results.sarif'
      ArtifactName: 'CodeAnalysisLogs'
      publishLocation: 'Container'
    condition: always()
```
