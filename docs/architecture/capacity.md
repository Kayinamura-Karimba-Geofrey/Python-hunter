# Capacity Model Document - Python Hunter Platform

## Capacity Estimation Matrix

| Scale Tier | Organizations | Repositories | Scans / Day | Active Workers | Storage / Month | Database Pool |
|---|---|---|---|---|---|---|
| **Tier 1 (Small)** | 1 - 10 | 50 - 500 | 500 | 4 - 8 | 50 GB | 20 connections |
| **Tier 2 (Enterprise)** | 10 - 100 | 500 - 2,500 | 5,000 | 16 - 32 | 500 GB | 50 connections |
| **Tier 3 (Large Scale)** | 1,000+ | 10,000+ | 50,000+ | 64 - 128+ | 5 TB+ | 150+ connections |

## Compute & RAM Sizing

- **API Nodes**: 2 - 4 CPU cores, 4 GB RAM per node (scalable N instances).
- **SAST Workers**: 4 CPU cores, 8 GB RAM per worker (AST & Taint CFG memory requirements).
- **SCA / Secret Workers**: 2 CPU cores, 4 GB RAM per worker.
- **Sandbox Limits**: Max 2 CPU cores, 4 GB RAM, 10 min timeout per repository scan.
