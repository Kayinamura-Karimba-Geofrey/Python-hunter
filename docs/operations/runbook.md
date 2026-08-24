# Production Operations Runbook - Python Hunter Platform

## Operational Procedures

### 1. Zero-Downtime Deployment
1. Deploy new API and Worker container images to staging cluster.
2. Execute forward-compatible database migrations (`python-hunter db migrate`).
3. Rolling update API Gateway nodes behind Load Balancer.
4. Scale up new worker pools while draining old worker queues.

### 2. Failure Recovery & Disaster Response
- **Dead-Letter Queue (DLQ) Recovery**: Inspect failed jobs using `python-hunter jobs dlq list`, resolve root cause (e.g. credential fix), then execute `python-hunter jobs dlq replay <job_id>`.
- **Database Failover**: RPO target: < 5 minutes, RTO target: < 15 minutes.
- **Cache / Lock Clearing**: If worker node crashes with active distributed locks, lock TTL automatically releases ownership after 30 seconds.

### 3. Backup & Restoration Strategy
- **Backup Frequency**: Daily automated full database snapshots + continuous WAL archiving.
- **Encryption**: AES-256 encrypted backups at rest.
- **Restoration Validation**: Automated weekly sandbox restore test.
