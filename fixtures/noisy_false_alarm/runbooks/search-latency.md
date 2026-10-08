# search-api latency alerts

Known issue: SearchP99High evaluates a 1-minute window, so a single slow request (e.g. cold
shard warmup after a node restart) can trip it. Before escalating, confirm sustained
elevation across multiple minutes and in p50, and check error_rate.

If isolated: no remediation needed. Suggested follow-up: widen the alert window to 5m.
