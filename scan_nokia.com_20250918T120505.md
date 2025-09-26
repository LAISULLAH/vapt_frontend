# Vulnerability Scan Report
- Target: nokia.com (34.107.106.80)
- Time: 2025-09-18T12:05:05.191060

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
- Related advisories:
  - BIT-nginx-2023-44487 — 
    - http://www.openwall.com/lists/oss-security/2023/10/13/4
    - http://www.openwall.com/lists/oss-security/2023/10/13/9
  - ECHO-56a6-a351-03e9 — 
    - https://advisory.echohq.com/cve/CVE-2023-44487
  - ECHO-8390-88ac-b8ec — 
    - https://advisory.echohq.com/cve/CVE-2024-7347
  - ECHO-56f7-b9e3-0470 — 
    - https://advisory.echohq.com/cve/CVE-2013-0337
  - ECHO-839e-058f-bf10 — 
    - https://advisory.echohq.com/cve/CVE-2009-4487
  - BIT-nginx-2024-7347 — NGINX MP4 module vulnerability
    - https://my.f5.com/manage/s/article/K000140529
    - http://www.openwall.com/lists/oss-security/2024/08/14/4
