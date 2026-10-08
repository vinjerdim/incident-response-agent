# auth-service login failures

1. Distinguish 401 (bad credentials / key issue) from 429 (rate limited) from 5xx.
2. 429 spikes: check rate_limiter config history (config pushes appear in list_deploys
   with kind=config).
3. Suggested remediation (requires approval): revert the config revision.
