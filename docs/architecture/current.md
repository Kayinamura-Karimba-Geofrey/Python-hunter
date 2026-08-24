# Current Architecture Document - Python Hunter Platform

## Overview
Python Hunter is an enterprise-grade polyglot application security platform supporting SAST, SCA, Secret Detection, Infrastructure Security (Docker, K8s, Terraform, Actions), Security Knowledge Graphs, Attack Path Analysis, Safe Verification, Risk Scoring, Alerts, Incidents, Multi-tenancy (RBAC, Tenant Isolation), Governance, and Integrations (GitHub, Jira, Slack, Teams, Webhooks, SIEM).

```
                      ┌───────────────────────────┐
                      │    FastAPI API / CLI      │
                      └─────────────┬─────────────┘
                                    │
                      ┌─────────────▼─────────────┐
                      │ SecurityApplicationService│
                      └─────────────┬─────────────┘
                                    │
    ┌───────────────────────────────┼───────────────────────────────┐
    │                               │                               │
┌───▼───────────────────┐ ┌─────────▼─────────────┐ ┌───────────────▼───────────┐
│ SecurityJobQueue      │ │ SecurityEventBus      │ │ RBAC & Tenant Context     │
│ (In-memory worker)    │ │ (In-memory Pub/Sub)   │ │ (In-memory Organization)  │
└───────────────────────┘ └───────────────────────┘ └───────────────────────────┘
```

## System Components & Analysis

### 1. API Layer
- **Framework**: FastAPI + Uvicorn / Rich CLI interface.
- **State**: Handled via `SecurityApplicationService` singleton.
- **Bottlenecks**: In-memory state dictionaries (`self.organizations`, `self.users`, `self.projects`) constrain horizontal scaling across multiple load-balanced API nodes.

### 2. Job Queue & Background Processing
- **Queue System**: `SecurityJobQueue` and `SecurityWorker`.
- **Bottlenecks**: In-memory queue storage locks worker execution to a single process. High-volume parallel scans require a distributed message queue abstraction.

### 3. Event Bus
- **Event Bus System**: `SecurityEventBus`.
- **Bottlenecks**: Synchronous in-memory pub/sub handlers. Needs partitioning and correlation propagation to handle high throughput.

### 4. Storage & State Persistence
- **Storage Subsystems**: Local SQLite, JSON baseline files, history stores.
- **Bottlenecks**: Direct file disk writes without distributed object storage abstraction for large artifacts (SARIF, scan logs).

### 5. Multi-Tenancy & Governance
- **Isolation**: Domain-level `TenantContext` validation.
- **Bottlenecks**: Lacks centralized distributed resource quota manager (`ResourceQuota`) for rate limiting and backpressure under heavy tenant load.
