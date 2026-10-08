# Checkout API elevated 5xx

1. Check recent deploys to checkout-api (`list_deploys`). Errors starting within minutes of a
   rollout strongly implicate that rollout.
2. Inspect error logs for exception type and file/line.
3. Check orders-db health (CPU, slow queries). DB CPU < 70% is normal under load.
4. Suggested remediation (requires approval): roll back to the previous version.
