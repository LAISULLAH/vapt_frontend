# Vulnerability Scan Report
- Target: nokia.com (34.107.106.80)
- Time: 2025-09-22T23:42:59.550274

## Open Ports
- Port 80: http nginx 1.22.1
- Port 443: http nginx 

## Findings
### Port 443 — http nginx
- Severity: MEDIUM (score 5/10)
- Issue: HTTPS service exposed.
- Details: Server header: AkamaiGHost; Missing X-Frame-Options header.; Missing X-Content-Type-Options header.; TLS: No SAN entries in certificate.
- Remediation: Ensure TLS config and patching. Correct certificate SAN or reissue certificate.

### Port 80 — http nginx 1.22.1
- Severity: MEDIUM (score 4/10)
- Issue: HTTP service exposed.
- Details: Server header: AkamaiGHost; Missing X-Frame-Options header.; Missing X-Content-Type-Options header.
- Remediation: Harden web server, validate inputs, use WAF.
