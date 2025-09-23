## Checklist

- [ ] No calls to /v2/api/.../internet/vpn/*, /stat/teleport*, /openapi.json, /api-docs
- [ ] `_join_api` used for all UniFi URLs
- [ ] No duplicate entities; stable `unique_id` scheme
- [ ] No secrets in logs; timeouts set; SSL verify respected
- [ ] Coordinator never raises on VPN 4xx/400
- [ ] Tests (rg checks) pass
