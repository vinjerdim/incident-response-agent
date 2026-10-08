# mTLS client certificate rotation (partner bank)

The payments-gateway presents client cert CN=payments-gateway.mtls to partnerbank.
cert-checker warns 14, 7, 1 and 0 days before notAfter.

Suggested remediation (requires approval): issue a new cert from the internal CA, upload to
the secret store, and restart the gateway pods. Partner bank must have the CA in its trust
store (already true for our internal CA).
