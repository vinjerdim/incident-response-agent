# Upstream carrier API problems

shipping-quotes calls fastcarrier and parcelco. If only one carrier's host shows timeouts or
errors, the issue is almost certainly upstream; check the carrier's status page and open a
ticket with them. Our own deploys rarely affect a single carrier.

Suggested mitigation (requires approval): disable the failing carrier in the quote fan-out
feature flag so customers still get quotes from the healthy carrier.
