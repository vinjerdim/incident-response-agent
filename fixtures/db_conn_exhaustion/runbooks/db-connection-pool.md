# orders-service DB connection pool exhaustion

Symptoms: "Connection is not available", "pool exhausted", 503s with ~30s latency.

1. Check db_pool_active_connections and db_pool_pending_requests.
2. Look for long-running batch jobs holding connections (reconcile-ledger, export-orders).
   These share the service's pool of 50 connections.
3. Check recent deploys for pool-size or query changes.
4. Suggested remediation (requires approval): pause the offending batch job; consider
   giving batch jobs a dedicated pool.
