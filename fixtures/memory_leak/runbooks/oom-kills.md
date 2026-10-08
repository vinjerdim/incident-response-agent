# Pods OOMKilled

1. Confirm OOMKilled in logs and a sawtooth in container_memory_mb.
2. Steady growth between restarts implies a leak (unbounded cache, growing list, etc.);
   check deploys in the last week for new caches/buffers.
3. GC warnings are usually a symptom of memory pressure, not the cause.
4. Suggested remediation (requires approval): roll back the leaking change or raise the
   memory limit as a stopgap.
