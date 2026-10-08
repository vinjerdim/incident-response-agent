# catalog-api scaling

Marketing campaigns (utm_campaign=...) can multiply traffic 3-5x. HPA maxReplicas is 20.
If replicas are pinned at max with high CPU and no new errors in code paths, this is a
capacity problem, not a bug.

Suggested remediation (requires approval): raise HPA maxReplicas to 40 and confirm DB
read-replica headroom.
