# Supply Chain Sentinel — Testing Strategy & Verification Guide
**Testing Frameworks:** pytest (Backend), Vitest / React Testing Library (Frontend)  
**Target Coverage:** Unit, Integration, Blast Radius Graph Correctness, and Security Ingestion  

---

## 1. Automated Test Suites

### 1.1 Backend Test Scope (`pytest`)
- **Authentication & RBAC:**
  - Valid user login & JWT generation.
  - Role enforcement (e.g. `read_only_exec` denied on `POST /sbom/upload`).
  - Tenant isolation (preventing User in Org A querying Assets of Org B).
- **SBOM Ingestion:**
  - CycloneDX 1.4 JSON parsing & PURL normalization.
  - CycloneDX 1.4 XML parsing with XXE attack payloads (ensuring safe rejection).
  - SPDX 2.3 JSON parsing & relationship mapping.
- **Vulnerability Matching:**
  - Direct and transitive component version comparison against OSV ranges.
  - CISA KEV presence detection.
  - EPSS probability ingestion.
- **Dependency Graph Engine:**
  - Graph node & edge generation from parsed SBOM.
  - Cycle detection & deep transitive tree traversal.
- **Attack Propagation Engine:**
  - Correct identification of all downstream applications for a vulnerable package.
  - Correct business service linkage and financial exposure estimation.
- **Remediation Verification:**
  - Comparison of old vs. updated SBOM to verify vulnerability eradication.

### 1.2 Execution Commands
```bash
# Run backend test suite
cd backend
pytest -v --cov=app tests/

# Run frontend tests
cd frontend
npm test
```
