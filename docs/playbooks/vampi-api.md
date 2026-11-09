# Playbook — VAmPI (REST API)

**Target:** `http://vampi:5000` (host: `http://127.0.0.1:5000`, OpenAPI at `/openapi.json`)
**Authorization:** bundled lab only. See docs/METHODOLOGY.md § Scope.

VAmPI is deliberately broken for **OWASP API Security Top 10 (2023)** practice. The
2023 edition dropped standalone Injection — focus on object-level auth, auth, and
data-exposure logic flaws that scanners miss.

| # | Step | Do | Tool / skill | API Top 10 |
|---|------|----|--------------|------------|
| 1 | Conformance fuzz | Run schemathesis off the OpenAPI spec (`--checks all`) — finds 500s, schema breaks, auth gaps | `api-vampi` (schemathesis) | — |
| 2 | BOLA | Register 2 users; read user A's record as user B by swapping the id/username | manual | **API1:2023** |
| 3 | Broken auth | Call authenticated endpoints with no/forged JWT; test user + password **enumeration** on `/login` and `/register` | manual | **API2:2023** |
| 4 | Mass assignment | Set an `admin`/privileged field at register; become admin | manual | **API3 / API6** |
| 5 | Excessive data | List endpoints returning all users' data (incl. passwords) | manual | **API3:2023** |

**ATT&CK tags:** T1190 (exploit public-facing app), T1078 (valid accounts).
**Report** per docs/METHODOLOGY.md § Reporting.
