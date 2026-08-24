# Target Architecture Document - Python Hunter Distributed System

## Target High-Availability Architecture

```
                  ┌──────────────────────┐
                  │    Users / CLI / UI  │
                  └──────────┬───────────┘
                             │
                  ┌──────────▼───────────┐
                  │  Load Balancer / Nginx│
                  └──────────┬───────────┘
                             │
       ┌─────────────────────┼─────────────────────┐
       │                     │                     │
 ┌─────▼─────┐         ┌─────▼─────┐         ┌─────▼─────┐
 │ API Node 1│         │ API Node 2│         │ API Node 3│ (Stateless FastAPI)
 └─────┬─────┘         └─────┬─────┘         └─────┬─────┘
       │                     │                     │
       └─────────────────────┼─────────────────────┘
                             │
                  ┌──────────▼───────────┐
                  │ Distributed Job Queue│ (Priority Queue + DLQ + Jitter Retries)
                  └──────────┬───────────┘
                             │
       ┌─────────────────────┼─────────────────────┐
       │                     │                     │
 ┌─────▼─────┐         ┌─────▼─────┐         ┌─────▼─────┐
 │SAST Pool  │         │SCA Pool   │         │Secrets Pool│ (Specialized Workers)
 └─────┬─────┘         └─────┬─────┘         └─────┬─────┘
       │                     │                     │
       └─────────────────────┼─────────────────────┘
                             │
                  ┌──────────▼───────────┐
                  │ Scalable Event Bus   │ (Partitioned Event Stream)
                  └──────────┬───────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
 ┌──────▼──────┐      ┌──────▼──────┐      ┌──────▼──────┐
 │ Alerts      │      │ Risk Engine │      │ Integrations│
 └─────────────┘      └─────────────┘      └─────────────┘

 ┌────────────────────────────────────────────────────────┐
 │ Distributed Storage Layer                              │
 │  - Relational DB (PostgreSQL / SQLite Connection Pool) │
 │  - Redis (Cache, Distributed Locks, Quotas)            │
 │  - Object Storage (Local FS / S3 SARIF & Artifacts)    │
 │  - Observability (Structured Logs, Metrics, Traces)    │
 └────────────────────────────────────────────────────────┘
```

## Key Architectural Principles

1. **Stateless API Gateway & Nodes**: API instances do not store critical in-process state. Session verification and rate-limiting draw from a distributed cache abstraction.
2. **Specialized Worker Pools & Bulkhead Isolation**: SAST, SCA, Secrets, IaC, and Integrations run in dedicated pools so that a spike in one scanner type does not starve another.
3. **Sandbox Workload Isolation**: Repository scanner execution runs in isolated temporary filesystems with explicit CPU, Memory, network policy, and execution timeouts.
4. **Fair Scheduling & Resource Quotas**: Enforces strict `ResourceQuota` limits per tenant (concurrent scans, daily scans, API requests) to ensure fair multi-tenant utilization.
5. **Observability & Distributed Tracing**: Unified correlation IDs propagate across `API -> Queue -> Worker -> Finding -> Event -> Notification`.
