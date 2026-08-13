# EC2 private DoH upgrade

This package turns the existing CloudFront VPC origin into a non-recursive DoH
service. `/dns-query` is public, but it answers only the exact names pushed by
`cloudflare_dns`; every other name receives DNS `REFUSED` (status 5). The admin
sync endpoint remains protected with timestamp + nonce + HMAC-SHA256.

The old secret query path can stay enabled during client migration and should be
removed after all clients use `/dns-query`.

See `../AWS_DOH_UPGRADE_ZH.md` for the copy/paste deployment and verification
steps.
