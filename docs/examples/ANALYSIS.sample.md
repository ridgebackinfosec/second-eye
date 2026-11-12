<!--
  GENERATED FILE - do not edit by hand.
  Produced from tests/fixtures/demo_capture/raw.har by:
      python scripts/generate_doc_examples.py
  Edit the fixture or the renderer, then regenerate.
-->

# Second-Eye Capture Analysis

**Capture:** auth-flow-test
**Target(s):** app.example-corp.com
**Capture window:** 2026-03-14T09:15:00Z → 2026-03-14T09:16:30Z
**Total requests:** 13 (3 navigation, 8 xhr-api, 2 static-asset)
**Full fidelity data:** raw.har (this document is a derived summary)

---

## Summary

*Counts below exclude static-asset requests.*

**Endpoints touched:**
- **GET** /login
- **POST** *(state-changing)* /login
- **GET** /dashboard
- **GET** /api/v2/users/4815/profile
- **GET** /api/v2/reports
- **POST** *(state-changing)* /api/v2/reports
- **GET** /api/v2/admin/audit-log
- **GET** /api/v2/notifications
- **GET** /api/v2/reports/9001/export

**Auth mechanisms observed:**
- Bearer token: 8 request(s)
- session cookie: 9 request(s)

**Status codes:** 8x 200, 1x 201, 1x 302, 1x 403

**Parameter names observed:** `user_id` (query, 1x), `org_id` (query, 2x), `limit` (query, 1x), `since` (query, 3x), `format` (query, 1x), `title` (body, 1x), `owner_id` (body, 1x)

## Capture Signals

**Security headers observed:**
- Strict-Transport-Security: present on 0/11 responses
- Content-Security-Policy: present on 0/11 responses
- X-Frame-Options: present on 1/11 responses
- X-Content-Type-Options: present on 2/11 responses
- X-XSS-Protection: present on 0/11 responses
- Referrer-Policy: present on 0/11 responses
- Permissions-Policy: present on 0/11 responses

**Stack fingerprint hints:**
- `nginx` (Server header)

**Cookie flag issues:**
- `session`: missing Secure, SameSite (entry #3)

## Sequence Diagram

```mermaid
sequenceDiagram
    participant Operator
    participant Target
    Operator->>Target: GET /login
    Target-->>Operator: 200
    Operator->>Target: POST /login
    Target-->>Operator: 200 (final, 2 hops)
    Operator->>Target: GET /api/v2/users/4815/profile
    Target-->>Operator: 200
    Operator->>Target: GET /api/v2/reports?user_id=4815&org_id=162342&limit=25
    Target-->>Operator: 200
    Operator->>Target: POST /api/v2/reports
    Target-->>Operator: 201
    Operator->>Target: GET /api/v2/admin/audit-log?org_id=162342
    Target-->>Operator: 403
    Operator->>Target: GET /api/v2/notifications?since=1773480000
    Target-->>Operator: 200
    Operator->>Target: GET /api/v2/reports/9001/export?format=csv
    Target-->>Operator: 200
```

## Contents

- [Flow 1 — 09:15:00 (navigation)](#flow-1--091500-navigation)
- [Flow 2 — 09:15:06 (navigation, redirect chain)](#flow-2--091506-navigation-redirect-chain)
- [Flow 3 — 09:15:07 (xhr-api)](#flow-3--091507-xhr-api)
- [Flow 4 — 09:15:07 (xhr-api)](#flow-4--091507-xhr-api)
- [Flow 5 — 09:15:19 (xhr-api)](#flow-5--091519-xhr-api)
- [Flow 6 — 09:15:24 (xhr-api)](#flow-6--091524-xhr-api)
- [Flow 7 — 09:15:30 (xhr-api)](#flow-7--091530-xhr-api)
- [Flow 10 — 09:16:12 (xhr-api)](#flow-10--091612-xhr-api)

## Flow 1 — 09:15:00 (navigation)

**GET** https://app.example-corp.com/login → `200` `text/html`

```html
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Sign in — Example Corp</title>
<link rel="stylesheet" href="/static/app.css"></head>
<body>
  <main class="login">
    <h1>Sign in</h1>
    <form method="post" action="/login">
      <input name="username" autocomplete="username">
      <input name="password" type="password" autocomplete="current-password">
      <button type="submit">Sign in</button>
    </form>
  </main>
  <script src="/static/app.js"></script>
</body>
</html>

```

**Assets loaded (2):** collapsed — 1x JS, 1x CSS, 1KB total

*(har_entry_index: 0)*

---

## Flow 2 — 09:15:06 (navigation, redirect chain)

**POST** *(state-changing)* https://app.example-corp.com/login → `302` → /dashboard → `200`

<details>
<summary>Redirect chain detail</summary>

| Hop | URL | Status | Location |
|---|---|---|---|
| 1 | /login | 302 | https://app.example-corp.com/dashboard |
| 2 | /dashboard | 200 | — |

</details>

```html
<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Dashboard</title></head><body><h1>Welcome back, demo</h1><div id="app" data-user-id="4815"></div><script src="/static/app.js"></script></body></html>

```

*(har_entry_index: 3)*

---

## Flow 3 — 09:15:07 (xhr-api)

**GET** https://app.example-corp.com/api/v2/users/4815/profile → `200` `application/json`

Request headers:
```
Host: app.example-corp.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0 Safari/537.36
Accept: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJFWEFNUExFLU5PVC1BLVJFQUwtVE9LRU4iLCJuYW1lIjoiZGVtbyJ9.ZmFrZS1zaWduYXR1cmUtZm9yLWRvY3Mtb25seQ
Cookie: session=sess_EXAMPLE0000NOTAREAL0000
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: same-origin
Sec-Fetch-Dest: empty
X-Requested-With: XMLHttpRequest
```

Response body:
```json
{
  "user_id": 4815,
  "username": "demo.operator",
  "email": "demo.operator@example-corp.com",
  "roles": [
    "analyst"
  ],
  "org_id": 162342
}
```

*(har_entry_index: 5)*

---

## Flow 4 — 09:15:07 (xhr-api)

**GET** https://app.example-corp.com/api/v2/reports?user_id=4815&org_id=162342&limit=25 → `200` `application/json`

Request headers:
```
Host: app.example-corp.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0 Safari/537.36
Accept: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJFWEFNUExFLU5PVC1BLVJFQUwtVE9LRU4iLCJuYW1lIjoiZGVtbyJ9.ZmFrZS1zaWduYXR1cmUtZm9yLWRvY3Mtb25seQ
Cookie: session=sess_EXAMPLE0000NOTAREAL0000
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: same-origin
Sec-Fetch-Dest: empty
X-Requested-With: XMLHttpRequest
```

Response body:
```json
{
  "total": 3,
  "items": [
    {
      "report_id": 9001,
      "title": "Q1 posture review",
      "owner_id": 4815
    },
    {
      "report_id": 9002,
      "title": "Vendor assessment",
      "owner_id": 4815
    },
    {
      "report_id": 9003,
      "title": "Access recertification",
      "owner_id": 7782
    }
  ]
}
```

*(har_entry_index: 6)*

---

## Flow 5 — 09:15:19 (xhr-api)

**POST** *(state-changing)* https://app.example-corp.com/api/v2/reports → `201` `application/json`

Request headers:
```
Host: app.example-corp.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0 Safari/537.36
Accept: application/json
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJFWEFNUExFLU5PVC1BLVJFQUwtVE9LRU4iLCJuYW1lIjoiZGVtbyJ9.ZmFrZS1zaWduYXR1cmUtZm9yLWRvY3Mtb25seQ
Cookie: session=sess_EXAMPLE0000NOTAREAL0000
Origin: https://app.example-corp.com
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: same-origin
Sec-Fetch-Dest: empty
X-Requested-With: XMLHttpRequest
```

Request body:
```json
{
  "title": "Scoped capture test",
  "owner_id": 4815
}
```

Response body:
```json
{
  "report_id": 9004,
  "title": "Scoped capture test"
}
```

*(har_entry_index: 7)*

---

## Flow 6 — 09:15:24 (xhr-api)

**GET** https://app.example-corp.com/api/v2/admin/audit-log?org_id=162342 → `403` `application/json`

Request headers:
```
Host: app.example-corp.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0 Safari/537.36
Accept: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJFWEFNUExFLU5PVC1BLVJFQUwtVE9LRU4iLCJuYW1lIjoiZGVtbyJ9.ZmFrZS1zaWduYXR1cmUtZm9yLWRvY3Mtb25seQ
Cookie: session=sess_EXAMPLE0000NOTAREAL0000
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: same-origin
Sec-Fetch-Dest: empty
X-Requested-With: XMLHttpRequest
```

Response body:
```json
{
  "error": "forbidden",
  "detail": "role 'analyst' may not read audit log"
}
```

**Note:** parameter `org_id` value `162342` was first observed in raw.har entry #6, reused here.

*(har_entry_index: 8)*

---

## Flow 7 — 09:15:30 (xhr-api)

**GET** https://app.example-corp.com/api/v2/notifications?since=1773480000 → `200` `application/json`

Request headers:
```
Host: app.example-corp.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0 Safari/537.36
Accept: application/json
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJFWEFNUExFLU5PVC1BLVJFQUwtVE9LRU4iLCJuYW1lIjoiZGVtbyJ9.ZmFrZS1zaWduYXR1cmUtZm9yLWRvY3Mtb25seQ
Cookie: session=sess_EXAMPLE0000NOTAREAL0000
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: same-origin
Sec-Fetch-Dest: empty
X-Requested-With: XMLHttpRequest
```

Response body:
```json
{
  "unread": 0,
  "items": []
}
```

**Note:** identical request observed again at 09:15:45 and 09:16:00 — appears to be a 15-second polling interval. Subsequent occurrences omitted from this narrative; see raw.har entries #10, #11.

*(har_entry_index: 9)*

---

## Flow 10 — 09:16:12 (xhr-api)

**GET** https://app.example-corp.com/api/v2/reports/9001/export?format=csv → `200` `text/csv`

Request headers:
```
Host: app.example-corp.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0 Safari/537.36
Accept: text/csv
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJFWEFNUExFLU5PVC1BLVJFQUwtVE9LRU4iLCJuYW1lIjoiZGVtbyJ9.ZmFrZS1zaWduYXR1cmUtZm9yLWRvY3Mtb25seQ
Cookie: session=sess_EXAMPLE0000NOTAREAL0000
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: same-origin
Sec-Fetch-Dest: empty
X-Requested-With: XMLHttpRequest
```

Response body:
```
report_id,title,owner_id,created_at
9001,Q1 posture review,4815,2026-01-08T11:02:00Z
9002,Vendor assessment,4815,2026-02-19T15:41:00Z

```

**Note:** response time 4821ms — ~54.7x the capture's median (88ms).

*(har_entry_index: 12)*

---

*End of capture. 13 total requests across 8 narrative flows (static-asset noise and repeated polling collapsed per flow-rendering rules).*