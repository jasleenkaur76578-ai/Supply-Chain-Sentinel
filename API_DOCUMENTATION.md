# Supply Chain Sentinel — REST API Documentation & OpenAPI Specification
**Base URL:** `http://localhost:8000/api/v1`  
**Authentication Scheme:** Bearer JWT (`Authorization: Bearer <token>`)  
**Standard Response Envelope:**  
```json
{
  "success": true,
  "data": { ... },
  "message": "Operation completed successfully",
  "meta": { "timestamp": "2026-11-23T01:00:00Z" }
}
```
**Standard Error Envelope:**
```json
{
  "success": false,
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "The requested asset was not found.",
    "details": []
  },
  "meta": { "timestamp": "2026-11-23T01:00:00Z" }
}
```

---

## 1. Authentication & Tenant Management

### `POST /auth/login`
- **Description:** Authenticate user credentials and return JWT bearer token.
- **Request Body:**
  ```json
  {
    "email": "analyst@sentinel.defense.org",
    "password": "SecurePassword123!"
  }
  ```
- **Response `200 OK`:**
  ```json
  {
    "access_token": "eyJhbGciOi...",
    "token_type": "bearer",
    "expires_in": 28800,
    "user": {
      "id": "u-4a8f9b2c",
      "email": "analyst@sentinel.defense.org",
      "full_name": "Dr. Sarah Mitchell",
      "role": "security_analyst",
      "organization": {
        "id": "org-99e1a",
        "name": "Global Financial Logistics Corp",
        "slug": "gflc"
      }
    }
  }
  ```

### `GET /auth/me`
- **Description:** Returns currently authenticated user and organization context.
- **Headers:** `Authorization: Bearer <token>`

---

## 2. Security Operations Overview (Dashboard Metrics)

### `GET /dashboard/overview`
- **Description:** Returns live calculated operational metrics and charts.
- **Query Params:** `time_range=30d` (optional: `7d`, `30d`, `90d`)
- **Response `200 OK`:**
  ```json
  {
    "metrics": {
      "total_assets": 14,
      "total_unique_dependencies": 482,
      "total_vulnerabilities": 67,
      "critical_vulnerabilities": 8,
      "high_vulnerabilities": 23,
      "known_exploited_vulnerabilities": 5,
      "affected_applications": 6,
      "vulnerable_suppliers": 4,
      "org_risk_exposure_score": 78.4,
      "remediation_completion_rate": 62.5,
      "last_intelligence_sync": "2026-11-23T00:45:00Z"
    },
    "severity_distribution": {
      "CRITICAL": 8,
      "HIGH": 23,
      "MEDIUM": 26,
      "LOW": 10
    },
    "risk_trends": [
      { "date": "2026-11-16", "risk_score": 84.2, "critical_count": 11 },
      { "date": "2026-11-23", "risk_score": 78.4, "critical_count": 8 }
    ],
    "urgent_attention_findings": [
      {
        "id": "finding-1",
        "cve_id": "CVE-2021-44228",
        "package": "org.apache.logging.log4j:log4j-core",
        "installed_version": "2.14.1",
        "severity": "CRITICAL",
        "cvss": 10.0,
        "is_kev": true,
        "affected_apps": ["Payment Gateway", "Order Processing API"],
        "critical_services": ["Core Transaction Engine"]
      }
    ]
  }
  ```

---

## 3. Application & Software Asset Management

### `GET /applications`
- **Description:** List registered applications with active SBOM status and risk scores.
- **Query Params:** `environment=PRODUCTION`, `criticality=CRITICAL`

### `POST /applications`
- **Description:** Register a new application.
- **Request Body:**
  ```json
  {
    "name": "Payment Gateway Service",
    "repository_url": "https://github.com/org/payment-gateway",
    "environment": "PRODUCTION",
    "business_criticality": "CRITICAL",
    "internet_exposed": true,
    "business_service_ids": ["service-uuid-1"]
  }
  ```

---

## 4. SBOM Ingestion & Analysis

### `POST /sbom/upload`
- **Description:** Securely ingest and parse an SBOM file (CycloneDX JSON/XML or SPDX JSON).
- **Consumes:** `multipart/form-data`
- **Form Fields:**
  - `file`: SBOM file binary (max 25MB)
  - `application_id`: UUID
- **Processing Steps:**
  1. File type and content validation (MIME, XML safe defusing, JSON schema check).
  2. Component extraction, version extraction, PURL normalization.
  3. Direct vs. transitive dependency linkage derivation.
  4. Real-time vulnerability intelligence lookup against OSV.dev and CISA KEV.
  5. Dependency graph updates in database.
- **Response `200 OK`:**
  ```json
  {
    "sbom_id": "sbom-99f2e",
    "format": "CYCLONEDX_JSON",
    "spec_version": "1.4",
    "components_parsed": 84,
    "dependencies_parsed": 142,
    "vulnerabilities_detected": 6,
    "critical_count": 1,
    "parsing_warnings": []
  }
  ```

### `GET /sbom/{sbom_id}/report`
- **Description:** Detailed SBOM analysis report including license distribution, component tree, and vulnerabilities.

---

## 5. Vulnerability & Threat Intelligence

### `GET /vulnerabilities`
- **Description:** List detected vulnerabilities across the organization.
- **Query Params:** `severity=CRITICAL`, `is_kev=true`, `search=log4j`

### `GET /vulnerabilities/{cve_id}`
- **Description:** Detailed threat intelligence card for a specific CVE.
- **Includes:** CVSS v3.1 vector, EPSS score & percentile, CISA KEV date, patch advice, affected internal packages.

---

## 6. Dependency Graph & Traversal

### `GET /graph/application/{application_id}`
- **Description:** Returns complete node and edge topology for React Flow / Cytoscape rendering.
- **Query Params:** `max_depth=3`, `include_vulnerabilities=true`
- **Response Format:**
  ```json
  {
    "nodes": [
      { "id": "app-1", "type": "application", "label": "Payment Gateway", "data": { "criticality": "CRITICAL", "risk": 82 } },
      { "id": "pkg-1", "type": "package", "label": "spring-boot-starter-web@2.5.4", "data": { "is_direct": true } },
      { "id": "pkg-2", "type": "package", "label": "log4j-core@2.14.1", "data": { "is_direct": false, "depth": 2, "severity": "CRITICAL" } }
    ],
    "edges": [
      { "id": "e1-2", "source": "app-1", "target": "pkg-1", "label": "depends_on" },
      { "id": "e2-3", "source": "pkg-1", "target": "pkg-2", "label": "transitive_child" }
    ]
  }
  ```

---

## 7. Attack Propagation & Blast Radius Engine

### `POST /propagation/analyze`
- **Description:** Execute graph traversal from a specified package or CVE to discover full downstream organizational exposure.
- **Request Body:**
  ```json
  {
    "package_name": "org.apache.logging.log4j:log4j-core",
    "version": "2.14.1",
    "vulnerability_id": "CVE-2021-44228"
  }
  ```
- **Response `200 OK`:**
  ```json
  {
    "originating_component": "log4j-core@2.14.1",
    "vulnerability": "CVE-2021-44228",
    "severity": "CRITICAL",
    "blast_radius_score": 92.5,
    "affected_applications_count": 3,
    "affected_applications": [
      {
        "id": "app-1",
        "name": "Payment Gateway",
        "environment": "PRODUCTION",
        "internet_exposed": true,
        "dependency_depth": 2,
        "path_trace": ["Payment Gateway", "spring-boot-starter-logging", "log4j-core"]
      }
    ],
    "associated_business_services": [
      { "name": "Core Transaction Processing", "criticality": "MISSION_CRITICAL", "hourly_downtime_cost": 75000 }
    ],
    "risk_factors": [
      "Known exploited in the wild (CISA KEV active)",
      "Reachable in Internet-Exposed Production Service",
      "Affects core transaction path"
    ],
    "recommended_actions": [
      "Upgrade log4j-core to 2.17.1 or higher immediately",
      "Apply JVM parameter `-Dlog4j2.formatMsgNoLookups=true` as emergency compensating control"
    ]
  }
  ```

---

## 8. AI Security Intelligence Assistant

### `POST /ai/chat`
- **Description:** Grounded RAG-based AI analysis interface.
- **Request Body:**
  ```json
  {
    "query": "Which of our production services are vulnerable to Log4Shell, and what is our immediate remediation plan?",
    "conversation_id": "conv-102"
  }
  ```
- **Response `200 OK`:**
  ```json
  {
    "response": "Based on our current database records, 2 applications are exposed to CVE-2021-44228: Payment Gateway and Logistics Order Engine. Both transitively depend on log4j-core@2.14.1...",
    "grounding_references": [
      { "entity_type": "VULNERABILITY", "entity_id": "CVE-2021-44228" },
      { "entity_type": "APPLICATION", "entity_id": "Payment Gateway" }
    ],
    "confidence": "HIGH"
  }
  ```

---

## 9. Remediation Management & Verification

### `GET /remediation/tasks`
- **Description:** List active and completed remediation tasks with SLA deadlines.

### `POST /remediation/verify`
- **Description:** Compare original SBOM with newly uploaded SBOM to mathematically prove remediation of target CVE.
- **Request Body:**
  ```json
  {
    "application_id": "app-uuid",
    "new_sbom_id": "sbom-new-uuid",
    "target_vulnerability_id": "CVE-2021-44228"
  }
  ```
- **Response `200 OK`:**
  ```json
  {
    "verified": true,
    "status": "RESOLVED",
    "previous_version": "2.14.1",
    "current_version": "2.17.1",
    "residual_risk": "NONE",
    "message": "CVE-2021-44228 is successfully eliminated from the dependency tree."
  }
  ```
